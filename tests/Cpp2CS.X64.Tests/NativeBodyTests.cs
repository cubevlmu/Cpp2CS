using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Machine.Ssa;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class NativeBodyTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000, stack = 0x20000;
        var cases = 0;
        foreach (var variant in new[] { "", "return-address", "register-write", "unbalanced", "dynamic-stack", "merge", "recursive", "tail-unbalanced", "indirect", "opaque", "exception", "heap-argument", "boundary", "helper" })
        {
            var bytes = original.ToArray();
            var caller = System.Convert.FromHexString(variant == "heap-argument"
                ? "4883EC484889C19090E8720000004883C448C3" : "4883EC48488D4C2420E8720000004883C448C3");
            // 零值路径写零，其他路径按原生顺序搬运三个字段；真实保存并恢复 RBX。
            var body = System.Convert.FromHexString("534883EC20488BD98B0285C0741089038B42048943048B4208894308EB1148C70300000000C7430800000000909090488BC34883C4205BC3");
            if (variant == "return-address") body = System.Convert.FromHexString("534883EC20488BD9488B442428488903C7430800000000488BC34883C4205BC3");
            if (variant == "register-write") body = System.Convert.FromHexString("41BC78563412" + System.Convert.ToHexString(body));
            if (variant == "unbalanced") body = System.Convert.FromHexString("4883EC08C3");
            if (variant == "dynamic-stack") body = System.Convert.FromHexString("4889C4C3");
            if (variant == "merge") body = System.Convert.FromHexString("85D274044883EC08C3");
            if (variant == "recursive") body = System.Convert.FromHexString("E8FBFFFFFFC3");
            if (variant == "tail-unbalanced") body = System.Convert.FromHexString("4883EC08E967000000");
            if (variant == "indirect") body = System.Convert.FromHexString("FFE0");
            if (variant == "opaque") body = System.Convert.FromHexString("0F05C3");
            caller.CopyTo(bytes, 0x200); body.CopyTo(bytes, 0x280); bytes[0x2f0] = 0xc3;
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + caller.Length)); U32(0x708, 0x3140);
            U32(0x70c, 0x1080); U32(0x710, (uint)(0x1080 + body.Length - (variant == "boundary" ? 1 : 0))); U32(0x714, 0x3150);
            bytes[0x740] = 1; bytes[0x750] = variant == "exception" ? (byte)9 : (byte)1;
            if (variant == "exception") U32(0x754, 0x10f0);
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [], Methods = [], Fields = [],
                RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var code = CodeMap.BuildPe(image, [basis + 0x1000]);
            var scan = CodeScan.Unscanned(code);
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = [], ByAddress = new Dictionary<ulong, CodeEntry[]>(),
                Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var machine = new PcodeMachine(image, decoder);
            RuntimeHelper[] helpers = variant == "helper" ? [new(basis + 0x1080, HelperKind.InitMetadata, null, "独立 helper 契约", 1)] : [];
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations,
                Helpers = RuntimeHelpers.FromEvidence(code, scan, helpers), Layouts = new FieldLayouts(model), MachineFactory = () => machine }, new());
            var cfg = new CfgBuilder(machine, code);
            var function = cfg.Build(basis + 0x1000);
            var sentinel = new Storage(Bank.Temp, 7000, 64);
            function.EntryBlock.Statements.Insert(0, new Assign(function.Entry, sentinel, Expr.C(0x123456789abcdef0, 64)));
            new NativeBodyInlining(facts, cfg, new FactsCallModel(facts, machine.Convention)).Run(function);
            var valid = variant is "" or "return-address" or "register-write" or "heap-argument";
            Check(function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any() != valid, "受限原生展开：" + variant);
            if (!valid) continue;
            Check(new FunctionLifter(facts).Lift(function.Entry, simplify: false).Function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any(),
                "事实提升默认保留原生边界");
            var lifted = new FunctionLifter(facts) { InlinesNativeBodies = true }.Lift(function.Entry, new Read(Storage.Gpr(0), 64));
            Check(lifted.Succeeded && SsaCheck.Verify(lifted.Function, Dominators.Compute(lifted.Function)).Count == 0, "展开接入公共 SSA");
            var random = new Random(77251);
            foreach (var displacement in new[] { -8, -4, 0, 4, 8, 32 })
            for (var iteration = 0; iteration < 64; iteration++)
            {
                var expected = new byte[64]; random.NextBytes(expected);
                var destination = 16; var source = destination + displacement;
                if (iteration % 3 == 0) BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(source), 0);
                var evaluator = new Evaluator();
                const ulong memory = stack - 0x28 - 16;
                for (var i = 0; i < expected.Length; i++) evaluator.Written[memory + (ulong)i] = expected[i];
                evaluator.Registers[Storage.Gpr(4)] = stack;
                evaluator.Registers[Storage.Gpr(2)] = memory + (ulong)source;
                evaluator.Registers[Storage.Gpr(0)] = stack - 0x28;
                evaluator.Registers[Storage.Gpr(3)] = 0x1122334455667788;
                evaluator.Registers[Storage.Gpr(12)] = 0x8877665544332211;
                if (variant == "return-address")
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(destination), basis + 0x100e);
                    BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(destination + 8), 0);
                }
                else if (BinaryPrimitives.ReadUInt32LittleEndian(expected.AsSpan(source)) == 0) expected.AsSpan(destination, 12).Clear();
                else for (var field = 0; field < 3; field++)
                {
                    var value = BinaryPrimitives.ReadUInt32LittleEndian(expected.AsSpan(source + field * 4));
                    BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(destination + field * 4), value);
                }
                Execute(function, evaluator);
                Check(Enumerable.Range(0, expected.Length).All(i => evaluator.Written[memory + (ulong)i] == expected[i]), "分支及重叠缓冲区实际访存顺序：" + variant);
                Check(evaluator.Get(Storage.Gpr(4)) == stack && evaluator.Get(Storage.Gpr(3)) == 0x1122334455667788,
                    "Call/Ret 栈偏移及非易失寄存器真实恢复");
                Check(evaluator.Get(Storage.Gpr(0)) == stack - 0x28 && evaluator.Get(sentinel) == 0x123456789abcdef0,
                    $"返回指针及 SLEIGH 临时存储隔离：{variant}, RAX={evaluator.Get(Storage.Gpr(0)):x}, 临时值={evaluator.Get(sentinel):x}");
                Check(evaluator.Get(Storage.Gpr(12)) == (variant == "register-write" ? 0x12345678u : 0x8877665544332211),
                    "不得重命名并隐藏原生非易失寄存器写入");
                cases++;
            }
        }
        Console.WriteLine($"原生分支体展开、栈及内存顺序对照通过：{cases} 组输入");
        TailCalls(original, decoder);
    }

    private static void TailCalls(byte[] original, SleighDecoder decoder)
    {
        foreach (var indirect in new[] { false, true }) TailCall(original, decoder, indirect);
        Console.WriteLine("原生直接及间接尾调用栈参数对照通过：512 组输入");
    }

    private static void TailCall(byte[] original, SleighDecoder decoder, bool indirect)
    {
        const ulong basis = 0x180000000, stack = 0x20000;
        var bytes = original.ToArray();
        // 调用者把第 5 个参数写在 Call 前 SP+0x20；被调体尾跳转前恢复自身栈帧。
        var caller = System.Convert.FromHexString("4883EC484889542420488D4C2430E86D0000004883C448C3");
        var body = System.Convert.FromHexString("4883EC284883C428E963000000");
        if (indirect)
        {
            caller = System.Convert.FromHexString("4883EC484889542420488D4C243049B8F010008001000000E8630000004883C448C3");
            body = System.Convert.FromHexString("4883EC284883C42841FFE0");
        }
        var target = System.Convert.FromHexString("488B442428488901C3");
        caller.CopyTo(bytes, 0x200); body.CopyTo(bytes, 0x280); target.CopyTo(bytes, 0x2f0);
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + caller.Length)); U32(0x708, 0x3140);
        U32(0x70c, 0x1080); U32(0x710, (uint)(0x1080 + body.Length)); U32(0x714, 0x3150);
        bytes[0x740] = 1; bytes[0x750] = 1;
        var image = ImageDocument.Parse(bytes);
        var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [], Methods = [], Fields = [],
            RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
        var code = CodeMap.BuildPe(image, [basis + 0x1000]);
        var scan = CodeScan.Unscanned(code);
        var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = [], ByAddress = new Dictionary<ulong, CodeEntry[]>(),
            Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
        var machine = new PcodeMachine(image, decoder);
        var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations,
            Helpers = RuntimeHelpers.FromEvidence(code, scan, []), Layouts = new FieldLayouts(model), MachineFactory = () => machine }, new());
        var cfg = new CfgBuilder(machine, code);
        var function = cfg.Build(basis + 0x1000);
        new NativeBodyInlining(facts, cfg, new FactsCallModel(facts, machine.Convention)).Run(function);
        var calls = function.Blocks.SelectMany(b => b.Statements).OfType<Call>().ToArray();
        Check(indirect ? calls is [{ Kind: CallKind.Indirect, Target: Read { Storage: var targetRegister } }] && targetRegister == Storage.Gpr(8)
            : calls is [{ Kind: CallKind.Direct, Target: Const { Value: basis + 0x10f0 } }], "短原生尾调用保留真正目标及分派方式");
        var targetStatements = new List<Stmt>();
        for (var pc = basis + 0x10f0; pc < basis + 0x10f0 + (ulong)target.Length;)
        {
            var size = machine.Lift(pc, targetStatements);
            Check(size > 0, "独立尾调用目标提升完成"); pc += (ulong)size;
        }
        var random = new Random(51239);
        for (var iteration = 0; iteration < 256; iteration++)
        {
            var value = iteration == 0 ? 0 : iteration == 1 ? ulong.MaxValue : (ulong)random.NextInt64();
            var evaluator = new Evaluator();
            evaluator.Registers[Storage.Gpr(4)] = stack;
            evaluator.Registers[Storage.Gpr(2)] = value;
            var block = function.EntryBlock; var executed = 0;
            for (var step = 0; step < 32; step++)
            {
                evaluator.NextPc = null;
                foreach (var statement in block.Statements)
                {
                    if (statement is Return) break;
                    if (statement is Call call)
                    {
                        // 按机器 Call 的入口 SP 契约执行独立目标，检查栈参数而非复用展开器的偏移公式。
                        var before = evaluator.Get(Storage.Gpr(4));
                        Check(evaluator.Eval(call.Target) == basis + 0x10f0, "间接尾调用保留原生目标寄存器");
                        Check(before == stack - 0x48, "尾调用转普通调用的实参基址");
                        evaluator.Registers[Storage.Gpr(4)] = before - 8;
                        evaluator.Run(targetStatements.Where(s => s is not Return).ToArray(), basis + 0x10f0, 0);
                        evaluator.Registers[Storage.Gpr(4)] += 8;
                        evaluator.NextPc = null; executed++;
                    }
                    else evaluator.Run([statement], block.Start, block.Start);
                    // 顺序语句的 NextPc 是求值器的默认落空值；分支与跳转在块末单独处理。
                    if (statement is not Branch and not Jump) evaluator.NextPc = null;
                }
                Check(evaluator.Failure is null, "尾调用执行失败：" + evaluator.Failure);
                if (block.Statements.LastOrDefault() is Return) break;
                block = evaluator.NextPc is { } pc ? function.Blocks.Single(b => b.Start == pc) : block.NormalSuccessors.Single();
            }
            ulong Read(ulong address)
            {
                ulong result = 0;
                for (var i = 0; i < 8; i++) result |= (ulong)evaluator.Written[address + (ulong)i] << (i * 8);
                return result;
            }
            Check(executed == 1 && evaluator.Get(Storage.Gpr(4)) == stack, "尾调用恰好执行一次且调用者栈平衡");
            Check(Read(stack - 0x18) == value && evaluator.Get(Storage.Gpr(0)) == value, "尾调用目标从原生第 5 参数位置取值");
        }
    }

    private static void Execute(MachineFunction function, Evaluator evaluator)
    {
        var block = function.EntryBlock;
        var blocks = function.Blocks.ToDictionary(b => b.Start);
        for (var step = 0; step < 128; step++)
        {
            var terminal = block.Statements.LastOrDefault() is Return;
            evaluator.NextPc = null;
            evaluator.Run(block.Statements.Where(s => s is not Return).ToArray(), block.Start, block.Successors.FirstOrDefault()?.Start ?? 0);
            Check(evaluator.Failure is null, "展开 IR 求值失败：" + evaluator.Failure);
            if (terminal) return;
            Check(evaluator.NextPc is { } next && blocks.ContainsKey(next), "展开边缺少目标");
            block = blocks[evaluator.NextPc!.Value];
        }
        throw new InvalidOperationException("展开夹具未结束");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
