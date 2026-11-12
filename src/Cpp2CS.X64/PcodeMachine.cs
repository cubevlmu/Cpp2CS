using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Model;

namespace Cpp2CS.X64;

/// <summary>Win64 机器后端；SLEIGH 解码失败和未建模语义保留诊断。</summary>
public sealed class PcodeMachine(ImageDocument image, SleighDecoder decoder) : IMachine
{
    public Architecture Architecture => Cpp2CS.Model.Architecture.X64;
    public ImageDocument Image { get; } = image;

    // 寄存器顺序：RAX RCX RDX RBX RSP RBP RSI RDI R8...R15。
    public CallingConvention Convention { get; } = new()
    {
        StackPointer = Storage.Gpr(4),
        IntegerArguments = [Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8), Storage.Gpr(9)],
        FloatArguments = [Storage.Vec(0), Storage.Vec(1), Storage.Vec(2), Storage.Vec(3)],
        IndirectResult = null,
        IntegerResults = [Storage.Gpr(0)],
        FloatResults = [Storage.Vec(0)],
        Clobbered = [Storage.Gpr(0), Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8),
            Storage.Gpr(9), Storage.Gpr(10), Storage.Gpr(11),
            .. Enumerable.Range(0, 6).Select(Storage.Vec),
            .. Enumerable.Range(0, 9).Select(i => new Storage(Bank.Temp, 200 + i, 8))],
    };

    public int Lift(ulong address, List<Stmt> output)
    {
        if (!Image.IsExecutable(address)) return 0;
        var bytes = Image.ReadUpTo(address, 15);
        if (bytes.IsEmpty) return 0;
        LiftedInstruction insn;
        try { insn = decoder.DecodeCached(address, bytes); }
        catch (InvalidDataException ex)
        {
            output.Add(new Opaque(address, "sleigh: " + ex.Message));
            return 0;
        }
        PcodeLowerer.Lower(insn, output);
        return insn.Length;
    }
}

/// <summary>原始 P-code 到机器 IR 的转换，保留指令地址、位宽和寄存器别名。</summary>
public static class PcodeLowerer
{
    private sealed class Scope(ulong address, List<Stmt> output)
    {
        private readonly List<(ulong Start, ulong End, Storage Storage)> unique = [];
        private readonly HashSet<ulong> initialized = [];
        private int nextTemp = 1000;
        private Expr? guard;

        public void Guard(PcodeVarnode condition)
        {
            if (guard is not null) { Fail("nested P-code condition"); return; }
            var storage = new Storage(Bank.Temp, nextTemp++, 1);
            output.Add(new Assign(address, storage, new Compare(Cond.Eq, Value(condition), Expr.C(0, condition.Size * 8))));
            guard = new Read(storage, 1);
        }

        private void Assign(Storage storage, Expr value)
        {
            if (guard is not null) value = new Select(guard, ConvertToWidth(value, storage.Width), new Read(storage, storage.Width), storage.Width);
            output.Add(new Assign(address, storage, Cpp2CS.Ir.Fold.Simplify(value)));
        }

        public void Prepare(IEnumerable<PcodeOperation> operations)
        {
            foreach (var node in operations.SelectMany(op => op.Inputs.Append(op.Output)).OfType<PcodeVarnode>()
                .Where(v => v.Space == "unique").OrderBy(v => v.Offset))
            {
                if (node.Size is <= 0 or > 16 || node.Offset > ulong.MaxValue - 16) { Fail("invalid unique range"); continue; }
                var end = node.Offset + (ulong)node.Size;
                if (unique.Count > 0 && node.Offset < unique[^1].End)
                {
                    var last = unique[^1];
                    end = Math.Max(last.End, end);
                    if (end - last.Start > 16) { Fail("unique alias group exceeds 128 bits"); continue; }
                    unique[^1] = (last.Start, end, new Storage(Bank.Temp, last.Storage.Index, (int)(end - last.Start) * 8));
                }
                else unique.Add((node.Offset, end, new Storage(Bank.Temp, nextTemp++, node.Size * 8)));
            }
        }

        private (Storage Storage, int Low) Unique(PcodeVarnode node)
        {
            foreach (var range in unique)
                if (node.Offset >= range.Start && node.Offset + (ulong)node.Size <= range.End)
                    return (range.Storage, (int)(node.Offset - range.Start) * 8);
            Fail("unknown unique range");
            return (Storage.Temp(0), 0);
        }
        public string? Problem { get; private set; }
        private void Fail(string reason) => Problem ??= reason;
        private Expr Unknown(string reason, int width) { Fail(reason); return new Unknown(reason, width); }


        private static readonly string[] GprNames =
            ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"];
        private static readonly string[] ENames =
            ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"];
        private static readonly string[] WNames =
            ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"];
        private static readonly string[] LNames =
            ["AL", "CL", "DL", "BL", "SPL", "BPL", "SIL", "DIL"];
        private static readonly string[] HNames = ["AH", "CH", "DH", "BH"];
        private static readonly string[] FlagNames = ["CF", "ZF", "SF", "OF", "PF", "AF", "TF", "IF", "DF"];

        private (Storage Storage, int Low) Register(PcodeVarnode v)
        {
            var name = v.Register?.ToUpperInvariant();
            if (name is null) { Fail($"unnamed register 0x{v.Offset:x}:{v.Size}"); return (Storage.Temp(0), 0); }
            for (var i = 0; i < 8; i++)
            {
                if (name == GprNames[i] || name == ENames[i] || name == WNames[i] || name == LNames[i])
                    return (Storage.Gpr(i), 0);
                if (i < 4 && name == HNames[i]) return (Storage.Gpr(i), 8);
            }
            for (int i = 8; i < 16; i++)
            {
                var baseName = $"R{i}";
                if (name is var n && (n == baseName || n == baseName + "D" || n == baseName + "W" || n == baseName + "B"))
                    return (Storage.Gpr(i), 0);
            }
            if (name.StartsWith("XMM", StringComparison.Ordinal))
            {
                var parts = name[3..].Split('_');
                if (int.TryParse(parts[0], out var vec) && vec is >= 0 and < 16)
                {
                    if (parts.Length == 1 && v.Size == 16) return (Storage.Vec(vec), 0);
                    if (parts is [_, { Length: 2 } lane])
                    {
                        var size = lane[0] switch { 'Q' => 8, 'D' => 4, 'W' => 2, 'B' => 1, _ => 0 };
                        var index = lane[1] - 'A';
                        if (size == v.Size && index >= 0 && (index + 1) * size <= 16)
                            return (Storage.Vec(vec), index * size * 8);
                    }
                }
            }
            var flag = Array.IndexOf(FlagNames, name);
            if (flag >= 0) return (new Storage(Bank.Temp, 200 + flag, 8), 0);
            Fail($"register {name} ({v.Size * 8} bits) is not modeled");
            return (Storage.Temp(0), 0);
        }

        private Storage Location(PcodeVarnode v)
        {
            if (v.Size is <= 0 or > 16) { Fail($"Varnode width {v.Size} bytes"); return Storage.Temp(0); }
            if (v.Space == "unique") return Unique(v).Storage;
            if (v.Space == "register") return Register(v).Storage;
            Fail($"Varnode space '{v.Space}' cannot be written as a register");
            return Storage.Temp(0);
        }

        private Expr Value(PcodeVarnode v)
        {
            var width = checked(v.Size * 8);
            if (width is <= 0 or > 128) return Unknown($"read width {width}", width);
            if (v.Space == "const")
            {
                if (width > 64) return Unknown("constant wider than 64 bits", width);
                return Expr.C(v.Offset, width);
            }
            if (v.Space == "register")
            {
                var (storage, low) = Register(v);
                if (low == 0 && width == storage.Width) return new Read(storage, width);
                if (low == 0 && width < storage.Width) return new Read(storage, width);
                if (low + width > storage.Width) return Unknown("register slice outside physical register", width);
                return new Extract(new Read(storage, storage.Width), low, width);
            }
            if (v.Space == "unique")
            {
                if (Enumerable.Range(0, v.Size).Any(i => !initialized.Contains(v.Offset + (ulong)i)))
                    return Unknown("unique read before definition", width);
                var (storage, low) = Unique(v);
                return low == 0 ? new Read(storage, width) : new Extract(new Read(storage, storage.Width), low, width);
            }
            if (v.Space == "ram") return new Load(Expr.C(v.Offset, 64), width);
            return Unknown($"Unknown value space: {v.Space}", width);
        }

        private void Write(PcodeVarnode target, Expr value)
        {
            var width = checked(target.Size * 8);
            if (value.Width != width) { Fail($"write {width}-bit target from {value.Width}-bit expression"); return; }
            if (target.Space == "ram")
            {
                if (guard is not null) { Fail("conditional memory store"); return; }
                output.Add(new Store(address, Expr.C(target.Offset, 64), value));
                return;
            }
            var storage = Location(target);
            if (target.Space == "unique")
            {
                var (_, low) = Unique(target);
                if (width != storage.Width) value = new Insert(new Read(storage, storage.Width), value, low);
                for (var i = 0; i < target.Size; i++) initialized.Add(target.Offset + (ulong)i);
            }
            if (target.Space == "register")
            {
                var (_, low) = Register(target);
                if (low == 0 && width == 32 && storage.Bank == Bank.Gpr)
                {
                    // x64 的 32 位通用寄存器写入清零高位。
                    Assign(storage, value);
                    return;
                }
                if (width != storage.Width)
                {
                    value = new Insert(new Read(storage, storage.Width), value, low);
                }
            }
            Assign(storage, value);
        }

        private static Expr ConvertToWidth(Expr value, int width, bool signed = false)
        {
            if (value.Width == width) return value;
            return new Cpp2CS.Ir.Convert(width < value.Width ? ConvKind.Truncate : signed ? ConvKind.SignExtend : ConvKind.ZeroExtend, value, width);
        }

        private ulong DirectTarget(PcodeVarnode node)
        {
            if (node.Space != "ram")
                { Fail("intra-instruction P-code flow cannot be used as a native branch"); return 0; }
            return node.Offset;
        }

        public void Apply(PcodeOperation op)
        {
            string name = op.Name;
            var vars = op.Inputs;
            // 普通运算中只有 STORE 无输出，其他运算缺少输出时拒绝。
            if (name == "STORE")
            {
                if (guard is not null) { Fail("conditional memory store"); return; }
                if (vars.Length != 3 || vars[0].Space != "const" || vars[0].ReferencedSpace != "ram") { Fail("STORE requires ram space"); return; }
                output.Add(new Store(address, ConvertToWidth(Value(vars[1]), 64), Value(vars[2])));
                return;
            }
            if (op.Output is not { } target) { Fail($"{name} requires an output"); return; }
            Expr Unary(Func<Expr, Expr> calc) => calc(Value(vars[0]));
            Expr Binary(BinOp kind) => new Binary(kind, Value(vars[0]), Value(vars[1]), target.Size * 8);
            Expr Compare(Cond condition) => new Cpp2CS.Ir.Compare(condition, Value(vars[0]), Value(vars[1]));
            Expr Boolean(PcodeVarnode node) => new Compare(Cond.Ne, Value(node), Expr.C(0, node.Size * 8));
            switch (name)
            {
                case "CALLOTHER" when op.UserOp == "sqrtpd":
                    {
                        if (target.Size != 16 || vars is not [{ Space: "const" }, { Size: 16 }, { Size: 16 }])
                        { Fail("sqrtpd requires two packed doubles"); return; }
                        // SSE2 SQRTPD 覆盖两个 64 位通道；规格的旧目标输入不参与计算。
                        var source = Value(vars[2]);
                        var low = new Unary(UnOp.FSqrt, new Extract(source, 0, 64), 64);
                        var high = new Unary(UnOp.FSqrt, new Extract(source, 64, 64), 64);
                        Write(target, new Insert(new Cpp2CS.Ir.Convert(ConvKind.ZeroExtend, low, 128), high, 64));
                        return;
                    }
                case "COPY": Write(target, Value(vars[0])); return;
                case "INT_ADD": Write(target, Binary(BinOp.Add)); return;
                case "INT_SUB": Write(target, Binary(BinOp.Sub)); return;
                case "INT_MULT": Write(target, Binary(BinOp.Mul)); return;
                case "INT_DIV": Write(target, Binary(BinOp.UDiv)); return;
                case "INT_SDIV": Write(target, Binary(BinOp.SDiv)); return;
                case "INT_REM": Write(target, Binary(BinOp.URem)); return;
                case "INT_SREM": Write(target, Binary(BinOp.SRem)); return;
                case "INT_AND": Write(target, Binary(BinOp.And)); return;
                case "INT_OR": Write(target, Binary(BinOp.Or)); return;
                case "INT_XOR": Write(target, Binary(BinOp.Xor)); return;
                case "BOOL_XOR": Write(target, Binary(BinOp.Xor)); return;
                case "INT_CARRY":
                    Write(target, ConvertToWidth(new Compare(Cond.Ult,
                        new Binary(BinOp.Add, Value(vars[0]), Value(vars[1]), vars[0].Size * 8), Value(vars[0])), target.Size * 8)); return;
                case "INT_SCARRY":
                case "INT_SBORROW":
                    {
                        var left = Value(vars[0]);
                        var right = Value(vars[1]);
                        var subtract = name == "INT_SBORROW";
                        var result = new Binary(subtract ? BinOp.Sub : BinOp.Add, left, right, left.Width);
                        Expr Xor(Expr a, Expr b) => new Binary(BinOp.Xor, a, b, left.Width);
                        var signs = Xor(left, right);
                        var bits = new Binary(BinOp.And, subtract ? signs : new Unary(UnOp.Not, signs, left.Width), Xor(left, result), left.Width);
                        Write(target, ConvertToWidth(new Extract(bits, left.Width - 1, 1), target.Size * 8)); return;
                    }
                case "POPCOUNT": Write(target, Unary(v => ConvertToWidth(new Unary(UnOp.PopCount, v, v.Width), target.Size * 8))); return;
                case "LZCOUNT": Write(target, Unary(v => ConvertToWidth(new Unary(UnOp.Clz, v, v.Width), target.Size * 8))); return;
                case "FLOAT_ADD": Write(target, Binary(BinOp.FAdd)); return;
                case "FLOAT_SUB": Write(target, Binary(BinOp.FSub)); return;
                case "FLOAT_MULT": Write(target, Binary(BinOp.FMul)); return;
                case "FLOAT_DIV": Write(target, Binary(BinOp.FDiv)); return;
                case "FLOAT_NEG": Write(target, Unary(v => new Unary(UnOp.FNeg, v, target.Size * 8))); return;
                case "FLOAT_ABS": Write(target, Unary(v => new Unary(UnOp.FAbs, v, target.Size * 8))); return;
                case "FLOAT_SQRT": Write(target, Unary(v => new Unary(UnOp.FSqrt, v, target.Size * 8))); return;
                case "CEIL": Write(target, Unary(v => new Unary(UnOp.FCeil, v, target.Size * 8))); return;
                case "FLOOR": Write(target, Unary(v => new Unary(UnOp.FFloor, v, target.Size * 8))); return;
                case "ROUND": Write(target, Unary(v => new Unary(UnOp.FRoundAway, v, target.Size * 8))); return;
                case "FLOAT_EQUAL": Write(target, ConvertToWidth(Compare(Cond.FEq), target.Size * 8)); return;
                case "FLOAT_NOTEQUAL": Write(target, ConvertToWidth(Compare(Cond.FNe), target.Size * 8)); return;
                case "FLOAT_LESS": Write(target, ConvertToWidth(Compare(Cond.FLt), target.Size * 8)); return;
                case "FLOAT_LESSEQUAL": Write(target, ConvertToWidth(Compare(Cond.FLe), target.Size * 8)); return;
                case "FLOAT_NAN": Write(target, ConvertToWidth(new Compare(Cond.FUnordered, Value(vars[0]), Value(vars[0])), target.Size * 8)); return;
                case "INT2FLOAT": Write(target, Unary(v => new Cpp2CS.Ir.Convert(ConvKind.SIntToFloat, v, target.Size * 8))); return;
                case "FLOAT2FLOAT": Write(target, Unary(v => new Cpp2CS.Ir.Convert(ConvKind.FloatToFloat, v, target.Size * 8))); return;
                case "TRUNC":
                    {
                        var value = Value(vars[0]);
                        var width = target.Size * 8;
                        if (value.Width is not (32 or 64) || width is not (32 or 64)) { Fail("unsupported x64 float truncation width"); return; }
                        var limit = Math.Pow(2, width - 1);
                        Expr Floating(double number) => Expr.C(value.Width == 32 ? BitConverter.SingleToUInt32Bits((float)number) : BitConverter.DoubleToUInt64Bits(number), value.Width);
                        var valid = new Logical(true, new Compare(Cond.FGe, value, Floating(-limit)), new Compare(Cond.FLt, value, Floating(limit)));
                        Write(target, new Select(valid, new Cpp2CS.Ir.Convert(ConvKind.FloatToSInt, value, width), Expr.C(1UL << (width - 1), width), width));
                        return;
                    }
                case "INT_LEFT":
                case "INT_RIGHT":
                case "INT_SRIGHT":
                    {
                        var value = Value(vars[0]);
                        var amount = Value(vars[1]);
                        var kind = name == "INT_LEFT" ? BinOp.Shl : name == "INT_RIGHT" ? BinOp.LShr : BinOp.AShr;
                        var shifted = new Binary(kind, value, amount, value.Width);
                        Expr outside = kind == BinOp.AShr
                            ? new Binary(BinOp.AShr, value, Expr.C((ulong)value.Width - 1, value.Width), value.Width)
                            : Expr.C(0, value.Width);
                        // P-code 超宽移位不按模折返，机器 IR 的移位需要显式边界。
                        Write(target, new Select(new Compare(Cond.Ult, amount, Expr.C((ulong)value.Width, amount.Width)), shifted, outside, value.Width));
                        return;
                    }
                case "INT_2COMP": Write(target, Unary(v => new Unary(UnOp.Neg, v, target.Size * 8))); return;
                case "INT_NEGATE": Write(target, Unary(v => new Unary(UnOp.Not, v, target.Size * 8))); return;
                case "INT_ZEXT": Write(target, Unary(v => ConvertToWidth(v, target.Size * 8))); return;
                case "INT_SEXT": Write(target, Unary(v => ConvertToWidth(v, target.Size * 8, true))); return;
                case "INT_EQUAL": Write(target, ConvertToWidth(Compare(Cond.Eq), target.Size * 8)); return;
                case "INT_NOTEQUAL": Write(target, ConvertToWidth(Compare(Cond.Ne), target.Size * 8)); return;
                case "INT_LESS": Write(target, ConvertToWidth(Compare(Cond.Ult), target.Size * 8)); return;
                case "INT_LESSEQUAL": Write(target, ConvertToWidth(Compare(Cond.Ule), target.Size * 8)); return;
                case "INT_SLESS": Write(target, ConvertToWidth(Compare(Cond.Slt), target.Size * 8)); return;
                case "INT_SLESSEQUAL": Write(target, ConvertToWidth(Compare(Cond.Sle), target.Size * 8)); return;
                case "BOOL_NEGATE": Write(target, ConvertToWidth(new Not(Boolean(vars[0])), target.Size * 8)); return;
                case "BOOL_AND": Write(target, ConvertToWidth(new Logical(true, Boolean(vars[0]), Boolean(vars[1])), target.Size * 8)); return;
                case "BOOL_OR": Write(target, ConvertToWidth(new Logical(false, Boolean(vars[0]), Boolean(vars[1])), target.Size * 8)); return;
                case "SUBPIECE":
                    {
                        if (vars[1].Space != "const") { Fail("dynamic subpiece offset"); return; }
                        var offset = checked((int)(vars[1].Offset * 8));
                        Write(target, new Extract(Value(vars[0]), offset, target.Size * 8));
                        return;
                    }
                case "PIECE":
                    {
                        var upper = Value(vars[0]);
                        var lower = Value(vars[1]);
                        var total = target.Size * 8;
                        if (upper.Width + lower.Width != total) { Fail("PIECE width mismatch"); return; }
                        Write(target, new Insert(ConvertToWidth(lower, total), upper, lower.Width));
                        return;
                    }
                case "LOAD":
                    if (vars.Length != 2 || vars[0].Space != "const" || vars[0].ReferencedSpace != "ram") { Fail("LOAD requires ram space"); return; }
                    Write(target, new Load(ConvertToWidth(Value(vars[1]), 64), target.Size * 8));
                    return;
                default: Fail($"Untranslated P-code op {name}"); return;
            }
        }

        public void ApplyFlow(PcodeOperation op, ulong next)
        {
            var a = op.Inputs;
            switch (op.Name)
            {
                case "BRANCH": output.Add(new Jump(address, DirectTarget(a[0]))); break;
                case "CBRANCH": output.Add(new Branch(address, new Compare(Cond.Ne, Value(a[1]), Expr.C(0, a[1].Size * 8)), DirectTarget(a[0]), next)); break;
                case "BRANCHIND": output.Add(new IndirectJump(address, Value(a[0]))); break;
                case "CALL": output.Add(new Call(address, CallKind.Direct, Expr.C(DirectTarget(a[0]), 64))); break;
                case "CALLIND": output.Add(new Call(address, CallKind.Indirect, Value(a[0]))); break;
                case "RETURN": output.Add(new Return(address)); break;
                default: Fail(op.Name); break;
            }
        }
    }

    public static void Lower(LiftedInstruction instruction, List<Stmt> output)
    {
        // SLEIGH 的 swi(3) 返回调度地址；整条 INT3 作为断点陷阱保留，不按普通间接调用解释。
        if (instruction is { Length: 1, Mnemonic: "INT3", Operations: [
            { Name: "CALLOTHER", UserOp: "swi", Output: { Space: "unique" } dispatch,
                Inputs: [{ Space: "const" }, { Space: "const", Offset: 3, Size: 1 }] },
            { Name: "CALLIND", Inputs: [var destination] },
            { Name: "RETURN", Inputs: [{ Space: "const", Offset: 0 }] }] }
            && dispatch == destination)
        {
            output.Add(new Trap(instruction.Address, "breakpoint"));
            return;
        }
        // x86 SLEIGH 的栅栏构造没有 P-code；助记符必须保留这类显式内存顺序效果。
        if (instruction.Mnemonic?.ToUpperInvariant() is "MFENCE" or "LFENCE" or "SFENCE")
        {
            if (instruction.Mnemonic.Equals("MFENCE", StringComparison.OrdinalIgnoreCase) && instruction.Operations.Length == 0)
                output.Add(new Call(instruction.Address, CallKind.Direct, Expr.C(0, 64)) { Op = new(OpKind.MemoryBarrier, null) });
            else output.Add(new Opaque(instruction.Address, $"{instruction.Mnemonic}: 定向内存栅栏尚未建模"));
            return;
        }
        var operations = instruction.Operations;
        if (operations.FirstOrDefault(op => op.Name == "CALLOTHER" && op.UserOp != "sqrtpd") is { } user)
        {
            output.Add(new Opaque(instruction.Address, $"pcode[{user.Index}] CALLOTHER {user.UserOp ?? "<unnamed>"}: 用户操作尚未建模"));
            return;
        }
        if (operations.LastOrDefault() is { Name: "CALL" or "CALLIND" } && operations.Length > 1)
        {
            var push = Array.FindIndex(operations, op => op is { Name: "INT_SUB", Output.Register: "RSP", Inputs: [{ Register: "RSP" }, { Space: "const", Offset: 8 }] });
            if (push < 0 || push + 2 != operations.Length - 1 || operations[push + 1] is not
                { Name: "STORE", Inputs: [{ ReferencedSpace: "ram" }, { Register: "RSP" }, { Space: "const", Size: 8 } saved] }
                || saved.Offset != instruction.Address + (ulong)instruction.Length)
            {
                output.Add(new Opaque(instruction.Address, "无法核实调用的返回地址入栈模式"));
                return;
            }
            // Call 表示执行后返回的完整调用；它的实参栈基址是压入返回地址之前的 RSP。
            operations = [.. operations.Take(push), operations[^1]];
        }
        if (operations.LastOrDefault() is { Name: "RETURN" })
        {
            // RET imm16 的零清栈量与 RET 相同；非零量需要另行建模调用约定。
            if (operations.Length == 4 && operations[2] is
                { Name: "INT_ADD", Output: { Register: "RSP", Size: 8 },
                    Inputs: [{ Register: "RSP", Size: 8 }, { Space: "const", Offset: 0 }] })
                operations = [operations[0], operations[1], operations[3]];
            if (operations is not [
                { Name: "LOAD", Output: { Register: "RIP", Size: 8 }, Inputs: [{ ReferencedSpace: "ram" }, { Register: "RSP" }] },
                { Name: "INT_ADD", Output.Register: "RSP", Inputs: [{ Register: "RSP" }, { Space: "const", Offset: 8 }] },
                { Name: "RETURN", Inputs: [{ Register: "RIP" }] }])
            {
                output.Add(new Opaque(instruction.Address, "无法核实返回的栈恢复模式"));
                return;
            }
            operations = [operations[^1]];
        }
        var pending = new List<Stmt>();
        var scope = new Scope(instruction.Address, pending);
        scope.Prepare(operations);
        foreach (var op in operations)
        {
            if (op is { Name: "CBRANCH", Inputs: [var relative, var condition] }
                && (relative.Space == "const" && relative.Offset <= int.MaxValue && op.Index + (long)relative.Offset == instruction.Operations.Length
                    || relative.Space == "ram" && relative.Offset == instruction.Address + (ulong)instruction.Length && op != operations[^1]))
            {
                scope.Guard(condition);
                continue;
            }
            var flow = op.Name is "BRANCH" or "CBRANCH" or "BRANCHIND" or "CALL" or "CALLIND" or "RETURN";
            var count = op.Name switch
            {
                "STORE" => 3,
                "CALLOTHER" when op.UserOp == "sqrtpd" => 3,
                "CBRANCH" or "LOAD" or "PIECE" or "SUBPIECE" => 2,
                "COPY" or "BRANCH" or "BRANCHIND" or "CALL" or "CALLIND" or "RETURN"
                    or "INT_2COMP" or "INT_NEGATE" or "INT_ZEXT" or "INT_SEXT" or "BOOL_NEGATE"
                    or "POPCOUNT" or "LZCOUNT" or "FLOAT_NEG" or "FLOAT_ABS" or "FLOAT_SQRT"
                    or "CEIL" or "FLOOR" or "ROUND" or "FLOAT_NAN"
                    or "INT2FLOAT" or "FLOAT2FLOAT" or "TRUNC" => 1,
                _ => 2,
            };
            string? problem = op.Inputs.Length != count ? "invalid operand count" : null;
            if (flow && op != operations[^1]) problem = "nonterminal P-code control flow";
            if (!flow && op.Inputs.Append(op.Output).OfType<PcodeVarnode>().Any(v => v.Size is <= 0 or > 16 || v.Space == "unique" && v.Offset > ulong.MaxValue - 16))
                problem = "invalid varnode size or offset";
            if (op.Name == "SUBPIECE" && op.Inputs.Length == 2 && op.Output is { } sub &&
                (op.Inputs[1].Offset > 16 || op.Inputs[1].Offset + (ulong)sub.Size > (ulong)op.Inputs[0].Size))
                problem = "SUBPIECE outside input";
            if (problem is null)
            {
                if (flow) scope.ApplyFlow(op, instruction.Address + (ulong)instruction.Length);
                else scope.Apply(op);
                problem = scope.Problem;
            }
            if (problem is not null)
            {
                // 一条指令必须整体提升；不能把失败前的部分写入当作完整语义。
                output.Add(new Opaque(instruction.Address, $"pcode[{op.Index}] {op.Name}: {problem}"));
                return;
            }
        }
        if (scope.Problem is { } remaining)
        {
            output.Add(new Opaque(instruction.Address, remaining));
            return;
        }
        output.AddRange(pending);
    }
}
