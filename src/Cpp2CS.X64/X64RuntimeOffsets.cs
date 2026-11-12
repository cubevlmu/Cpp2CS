using Cpp2CS.Facts;
using Cpp2CS.Ir;

namespace Cpp2CS.X64;

/// <summary>从导出的字段访问与类初始化快速返回条件提取布局，不依赖 Unity 版本猜测。</summary>
public static class X64RuntimeOffsets
{
    public static RuntimeOffsets Identify(PcodeMachine machine, IEnumerable<RuntimeHelper> helpers, double? metadataVersion = null)
    {
        var flags = helpers.Where(h => h.Kind == HelperKind.ClassInit).Select(h => CctorFlag(machine, h.Address))
            .OfType<int>().Distinct().ToArray();
        int? fields = null;
        if (machine.Image.Exports.TryGetValue("il2cpp_class_get_static_field_data", out var address))
        {
            var statements = new List<Stmt>();
            var size = machine.Lift(address, statements);
            // 叶访问器只有一次字段读取和返回；其余形态不推断。
            var values = new Dictionary<Storage, Expr>();
            if (size > 0 && statements.All(s => s is Assign))
            {
                foreach (var assign in statements.Cast<Assign>()) values[assign.Target] = Expand(assign.Value, values);
                var end = new List<Stmt>();
                machine.Lift(address + (ulong)size, end);
                if (end is [Return] && values.GetValueOrDefault(Storage.Gpr(0)) is Load { Width: 64 } load)
                    fields = Offset(load.Address);
            }
        }
        int? initialization = null, methodClass = null;
        if (machine.Image.Exports.TryGetValue("il2cpp_class_is_inited", out var flagAccessor))
        {
            var bytes = machine.Image.ReadUpTo(flagAccessor, 12);
            if (bytes.Length == 12 && bytes[..3].SequenceEqual(System.Convert.FromHexString("0FB681"))
                && bytes[7..].SequenceEqual(System.Convert.FromHexString("D0E82401C3")))
            {
                var offset = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes[3..7]);
                if (offset is > 0 and < 4096) initialization = offset;
            }
        }
        if (machine.Image.Exports.TryGetValue("il2cpp_method_get_class", out var methodAccessor))
        {
            var seen = new HashSet<ulong>();
            for (var hop = 0; hop < 8 && machine.Image.IsExecutable(methodAccessor) && seen.Add(methodAccessor); hop++)
            {
                var jumpStatements = new List<Stmt>();
                machine.Lift(methodAccessor, jumpStatements);
                if (jumpStatements is not [Jump jump]) break;
                methodAccessor = jump.Target;
            }
            var statements = new List<Stmt>();
            var size = machine.Lift(methodAccessor, statements);
            var values = new Dictionary<Storage, Expr>();
            if (size > 0 && statements.All(s => s is Assign))
            {
                foreach (var assign in statements.Cast<Assign>()) values[assign.Target] = Expand(assign.Value, values);
                var end = new List<Stmt>();
                machine.Lift(methodAccessor + (ulong)size, end);
                if (end is [Return] && values.GetValueOrDefault(Storage.Gpr(0)) is Load { Width: 64 } load)
                    methodClass = Offset(load.Address);
            }
        }
        // HeaderConstants 的类声明给出 RGCTX 与尾部虚表；只启用经四个导出位置核对的元数据 31 Win64 配置。
        var rgctxProfile = metadataVersion == 31 && fields == 0xb8 && methodClass == 0x20
            && initialization == 0x135 && flags is [0xe4];
        var fieldTable = FieldTable(machine);
        return new(flags.Length == 1 ? flags[0] : null, fields,
            "PE 导出：类初始化条件及静态字段、初始化标志、方法声明类访问器"
            + (rgctxProfile ? "；元数据 31 Win64 布局配置：rgctx_data 紧接 static_fields，尾部 vtable 位于 0x138" : "")
            + (fieldTable is not null ? "；字段枚举导出的完整迭代体核对字段表及元素步长" : ""))
            { ClassInitializationFlags = initialization, MethodClass = methodClass, ClassRgctxData = rgctxProfile ? fields + 8 : null,
                ClassVtable = rgctxProfile ? 0x138 : null,
                // 同一元数据 31 配置的 MethodInfo 以三个指针开头；未知配置不消费 invoker 字段。
                MethodPointer = rgctxProfile ? 0 : null, MethodVirtualPointer = rgctxProfile ? 8 : null,
                MethodInvoker = rgctxProfile ? 16 : null,
                ClassFields = fieldTable, FieldInfoSize = fieldTable is not null ? 32 : null };
    }

    private static int? FieldTable(PcodeMachine machine)
    {
        if (!machine.Image.Exports.TryGetValue("il2cpp_class_get_fields", out var entry)) return null;
        var seen = new HashSet<ulong>();
        for (var depth = 0; depth < 8 && machine.Image.IsExecutable(entry) && seen.Add(entry); depth++)
        {
            var statements = new List<Stmt>();
            if (machine.Lift(entry, statements) <= 0) return null;
            if (statements is [Jump jump]) { entry = jump.Target; continue; }
            // 完整的首项、计数、32 字节步进、边界检查及三条返回路径；仅初始化调用位移不固定。
            var expected = System.Convert.FromHexString("48895C2408574883EC20488BFA488BD94885D2745D48833A00752BE8000000006683BB24010000007448488B8380000000488907488B8380000000488B5C24304883C4205FC30FB78924010000488B0248C1E1054883C02048038B80000000483BC1730E488902488B5C24304883C4205FC3488B5C243033C04883C4205FC3");
            var body = machine.Image.ReadUpTo(entry, expected.Length);
            if (body.Length != expected.Length) return null;
            var initialize = unchecked(entry + 32 + (ulong)(long)System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(body[28..32]));
            if (!machine.Image.IsExecutable(initialize)) return null;
            body[28..32].CopyTo(expected.AsSpan(28));
            return body.SequenceEqual(expected) ? 0x80 : null;
        }
        return null;
    }

    private static int? CctorFlag(PcodeMachine machine, ulong entry)
    {
        var values = new Dictionary<Storage, Expr>();
        var pc = entry;
        for (var i = 0; i < 16; i++)
        {
            var statements = new List<Stmt>();
            var size = machine.Lift(pc, statements);
            if (size <= 0) return null;
            foreach (var stmt in statements)
            {
                switch (stmt)
                {
                    case Assign assign: values[assign.Target] = Expand(assign.Value, values); break;
                    case Store store when Stack(Expand(store.Target, values)): break;
                    case Branch branch:
                    {
                        var condition = Expand(branch.Condition, values);
                        var loads = ExprMap.Walk(condition).OfType<Load>().Distinct().ToArray();
                        if (loads is not [{ Width: 32 } load] || Offset(load.Address) is not { } offset) return null;
                        Expr Test(ulong value) => Fold.Simplify(ExprMap.Map(condition, e => e == load ? Expr.C(value, 32) : null));
                        if (Test(0) is not Const zero || Test(1) is not Const one || zero.Value == one.Value) return null;
                        var fast = one.Value != 0 ? branch.Target : branch.Fallthrough;
                        return ReturnsWithoutEffects(machine, fast) ? offset : null;
                    }
                    // 纯跳板不修改传入类指针。
                    case Jump jump when i == 0: pc = jump.Target; size = 0; break;
                    default: return null;
                }
            }
            pc += (ulong)size;
        }
        return null;
    }

    private static bool ReturnsWithoutEffects(PcodeMachine machine, ulong pc)
    {
        var values = new Dictionary<Storage, Expr>();
        for (var i = 0; i < 12; i++)
        {
            var statements = new List<Stmt>();
            var size = machine.Lift(pc, statements);
            if (size <= 0) return false;
            foreach (var stmt in statements)
            {
                if (stmt is Return) return true;
                if (stmt is not Assign assign) return false;
                var value = Expand(assign.Value, values);
                if (ExprMap.Walk(value).OfType<Load>().Any(l => !Stack(l.Address))) return false;
                values[assign.Target] = value;
            }
            pc += (ulong)size;
        }
        return false;
    }

    private static Expr Expand(Expr e, Dictionary<Storage, Expr> values) => Fold.Simplify(ExprMap.Map(e,
        part => part is Read read && values.TryGetValue(read.Storage, out var value)
            ? value.Width == read.Width ? value : new Cpp2CS.Ir.Convert(read.Width < value.Width ? ConvKind.Truncate : ConvKind.ZeroExtend, value, read.Width) : null));
    private static int? Offset(Expr e) => e is Binary { Op: BinOp.Add, Left: Read { Storage.Bank: Bank.Gpr, Storage.Index: 1 }, Right: Const { Value: > 0 and < 4096 } offset } ? (int)offset.Value : null;
    private static bool Stack(Expr e) => e is Read { Storage.Bank: Bank.Gpr, Storage.Index: 4 }
        || e is Binary { Op: BinOp.Add, Left: Read { Storage.Bank: Bank.Gpr, Storage.Index: 4 }, Right: Const };
}
