using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Machine.Ssa;
using Cpp2CS.Model;
using Cpp2CS.X64;
using Cpp2CS.Recovery.Calls;
using Cpp2CS.Machine.Storage;

namespace Cpp2CS.X64.Tests;

internal static class NativeLeafTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        const string copy = "8B0289018B42048941048B42088941084889C8C3";
        foreach (var invalid in new[] { "", "padding", "read-only", "write-only", "saved", "stack-read", "stack-write", "branch", "call", "opaque", "exception", "trailing", "single", "helper", "tail", "recursive" })
        {
            var bytes = original.ToArray();
            var body = System.Convert.FromHexString(invalid switch {
                "saved" => "488BDA" + copy,
                "stack-read" => "488B0424" + copy,
                "stack-write" => "4883EC08" + copy,
                "branch" => "EB00" + copy,
                "call" => "E86B000000" + copy,
                "opaque" => "0F0B" + copy,
                "padding" => copy + "90CCCC",
                "read-only" => "8B4104C3",
                "write-only" => "8951084889C8C3",
                "trailing" => copy + "8901",
                _ => copy,
            });
            System.Convert.FromHexString("E87B000000C3").CopyTo(bytes, 0x200);
            body.CopyTo(bytes, 0x280); bytes[0x2f0] = 0xc3;
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, 0x1006); U32(0x708, 0x3140);
            U32(0x70c, 0x1080); U32(0x710, (uint)(0x1080 + body.Length)); U32(0x714, 0x3140); bytes[0x740] = 1;
            if (invalid == "exception") { bytes[0x740] = 9; U32(0x744, 0x10f0); }
            var owner = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000001,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
            var methods = Enumerable.Range(0, invalid == "single" ? 1 : 2).Select(i => MethodRef.Open(new MethodDef {
                Index = i, Owner = owner, Name = "Copy" + i, Token = (uint)(0x06000001 + i), Address = basis + 0x1080,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
                ReturnType = new DefinitionRef(owner, []),
            })).ToArray();
            var image = ImageDocument.Parse(bytes);
            var code = CodeMap.BuildPe(image, [basis + 0x1000, basis + 0x1080]);
            var scan = CodeScan.Unscanned(code);
            var entries = methods.Select(m => new CodeEntry(basis + 0x1080, EntryKind.Method, m, 0, null)).ToArray();
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = new Dictionary<ulong, CodeEntry[]> { [basis + 0x1080] = entries }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [owner], Methods = methods.Select(m => m.Method).ToArray(),
                Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var machine = new PcodeMachine(image, decoder);
            RuntimeHelper[] helpers = invalid == "helper" ? [new(basis + 0x1080, HelperKind.InitMetadata, null, "独立辅助函数契约", 1)] : [];
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations,
                Helpers = RuntimeHelpers.FromEvidence(code, scan, helpers), Layouts = new FieldLayouts(model), MachineFactory = () => machine }, new());
            var summary = facts.NativeCalls.At(basis + 0x1080);
            if (invalid is "saved" or "stack-read" or "stack-write" or "branch" or "call" or "opaque" or "exception" or "trailing" or "helper")
                Check(summary is null, "不完整体、异常、调用、未知操作和非易失寄存器写入不能生成摘要：" + invalid);
            if (invalid is "" or "padding" or "read-only" or "write-only")
            {
                Check(summary is not null && summary.WritesMemory == (invalid != "read-only"), "摘要区分读取和写入完整效果");
                var snapshots = Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => facts.NativeCalls.At(basis + 0x1080)))).GetAwaiter().GetResult();
                Check(snapshots.All(s => ReferenceEquals(s, summary)), "同一映像并发消费复用同一个完整摘要");
                var argument = new Call(basis + 0x1000, CallKind.Direct, Expr.C(basis + 0x1080, 64)) {
                    Sources = [Storage.Gpr(1)], Arguments = [new FrameAddress(-32)] };
                var effects = new CallMemoryEffects(c => new(c, [], null) { NativeSummary = summary }, facts.CreateAbi());
                if (invalid == "read-only")
                    Check(effects.Argument(argument, 0) == new ArgumentUse(8, MemoryAccess.Read, false) && !effects.WritesEscaped(argument),
                        "完整只读证明以含偏移范围供公共帧内存模型消费");
                else Check(effects.Argument(argument, 0).Retained && effects.WritesEscaped(argument), "带存储和回传别名不能当作无效果读取");
            }
            var function = new CfgBuilder(machine, code).Build(basis + 0x1000);
            if (invalid is "tail" or "recursive")
                function.EntryBlock.Statements[0] = ((Call)function.EntryBlock.Statements[0]) with {
                    Kind = invalid == "tail" ? CallKind.Tail : CallKind.Direct,
                    Target = Expr.C(invalid == "recursive" ? function.Entry : basis + 0x1080, 64),
                };
            var sentinel = new Storage(Bank.Temp, 1000, 64);
            function.EntryBlock.Statements.Insert(0, new Assign(function.Entry, sentinel, Expr.C(0x123456789abcdef0, 64)));
            var valid = invalid is "" or "padding" or "read-only" or "write-only";
            Check(new NativeLeafInlining(facts, machine).Run(function) == (valid && invalid != "read-only" ? 1 : 0), "受限搬运体边界：" + invalid);
            if (!valid) continue;
            Check(function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any() == (invalid == "read-only"), "只读入口延后到分派求解之后");
            Check(function.EntryBlock.Statements.OfType<Store>().Count() == (invalid == "read-only" ? 0 : invalid == "write-only" ? 1 : 3), "保留实际原生存储");
            Check(function.EntryBlock.Statements.OfType<Assign>().Where(a => ExprMap.Walk(a.Value).Any(e => e is Load)).All(a => a.PreserveRead),
                "展开的读取必须保留求值");
            Check(new NativeLeafInlining(facts, machine).Run(function) == 0, "展开幂等");
            Check(new FunctionLifter(facts).Lift(function.Entry, new Read(Storage.Gpr(0), 64), simplify: false)
                .Function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any(), "原生事实证明默认保留调用边界");
            var lifted = new FunctionLifter(facts) { InlinesNativeLeaves = true }.Lift(function.Entry, new Read(Storage.Gpr(0), 64));
            if (invalid == "read-only")
            {
                var at = lifted.Function.EntryBlock.Statements.FindIndex(s => s is Call);
                var call = (Call)lifted.Function.EntryBlock.Statements[at];
                var ignored = new Variable(Storage.Temp(9000), 1);
                lifted.Function.EntryBlock.Statements.Insert(at, new Define(call.Address, ignored, new Load(Expr.C(0x50000, 64), 64)));
                lifted.Function.EntryBlock.Statements[at + 1] = call with {
                    Arguments = [.. call.Arguments, new Use(ignored, 64)], Sources = [.. call.Sources, Storage.Gpr(2)] };
                var reads = new NativeLeafInlining(facts, machine);
                Check(reads.RunReads(lifted.Function, _ => false) == 0, "已解析调用应保留托管契约");
                Check(reads.RunReads(lifted.Function, _ => true) == 1 && reads.RunReads(lifted.Function, _ => true) == 0, "未解析只读调用在 SSA 中展开且幂等");
                Check(Lowering.Cleanup(lifted.Function).Count == 0, "只读展开维持 SSA");
                Check(lifted.Function.Blocks.SelectMany(b => b.Statements).OfType<Define>().Any(d => d.Target == ignored && d.PreserveRead),
                    "原调用已求值但原生体未用的实参读取不能随签名收窄丢失");
            }
            Check(lifted.Succeeded && !lifted.Function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any(), "接入公共 SSA 提升");
            if (invalid is "read-only" or "write-only") continue;
            // 独立逐字段内存模型包含重叠缓冲区，不能用 memcpy/memmove 的假定替代指令顺序。
            var random = new Random(81173);
            foreach (var displacement in new[] { -8, -4, 0, 4, 8, 64 })
            for (var iteration = 0; iteration < 64; iteration++)
            {
                var expected = new byte[128]; random.NextBytes(expected);
                var source = 24; var destination = source + displacement;
                var evaluator = new Evaluator();
                for (var i = 0; i < expected.Length; i++) evaluator.Written[0x10000 + (ulong)i] = expected[i];
                evaluator.Registers[Storage.Gpr(1)] = (uint)(0x10000 + destination);
                evaluator.Registers[Storage.Gpr(2)] = (uint)(0x10000 + source);
                for (var field = 0; field < 3; field++)
                {
                    var value = BinaryPrimitives.ReadUInt32LittleEndian(expected.AsSpan(source + field * 4));
                    BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(destination + field * 4), value);
                }
                evaluator.Run(function.EntryBlock.Statements.Where(s => s is not Return).ToArray(), function.Entry, function.Entry + 6);
                Check(evaluator.Failure is null && Enumerable.Range(0, expected.Length).All(i => evaluator.Written[0x10000 + (ulong)i] == expected[i]), "重叠与非重叠复制按原生顺序执行");
                Check(evaluator.Get(Storage.Gpr(0)) == (uint)(0x10000 + destination) && evaluator.Get(sentinel) == 0x123456789abcdef0,
                    "回传缓冲区地址并隔离调用方临时值");
            }
        }
        Console.WriteLine("共享搬运体边界及内存顺序对照通过：768 组输入");
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}
