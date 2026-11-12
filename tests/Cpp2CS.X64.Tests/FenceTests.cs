using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Ssa;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class FenceTests
{
    public static void Run(SleighDecoder decoder)
    {
        LiftedInstruction Decode(string bytes) => decoder.Decode(0x1000, System.Convert.FromHexString(bytes));
        List<Stmt> Lower(LiftedInstruction instruction)
        {
            var result = new List<Stmt>();
            PcodeLowerer.Lower(instruction, result);
            return result;
        }
        var full = Decode("0FAEF0");
        Check(full.Mnemonic == "MFENCE" && full.Operations.Length == 0, "规格空语义必须保留助记符");
        var lowered = Lower(full);
        Check(lowered is [Call { Op.Kind: OpKind.MemoryBarrier }], "MFENCE 保留内存顺序效果");
        foreach (var bytes in new[] { "0FAEE8", "0FAEF8" })
            Check(Lower(Decode(bytes)) is [Opaque], "定向栅栏不得静默丢弃");
        foreach (var bytes in new[] { "F0830C2400", "F0480FC10A" })
        {
            var locked = Decode(bytes);
            Check(locked.Operations.First().UserOp == "LOCK" && locked.Operations.Last().UserOp == "UNLOCK", "用户操作名称来自当前规格");
            Check(Lower(locked) is [Opaque { Text: var text }] && text.Contains("LOCK"), "锁定读改写不得拆成非原子访存");
        }
        var breakpoint = Decode("CC");
        Check(Lower(breakpoint) is [Trap { Kind: "breakpoint" }], "INT3 保留断点陷阱，不能按普通返回解释");
        var changed = breakpoint.Operations.ToArray();
        changed[0] = changed[0] with { Inputs = [changed[0].Inputs[0], changed[0].Inputs[1] with { Offset = 4 }] };
        Check(Lower(breakpoint with { Operations = changed }) is [Opaque], "不同软件中断不得冒充 INT3");
        Check(Lower(Decode("90")).Count == 0, "NOP 的空语义仍有效");

        var rax = Storage.Gpr(0);
        var block = new Block(0x1000) { End = 0x1010 };
        block.Statements.Add(new Assign(0x1000, rax, Expr.C(42, 64)));
        block.Statements.AddRange(lowered);
        block.Statements.Add(new Return(0x100f) { Value = new Read(rax, 64) });
        var function = new MachineFunction { Entry = 0x1000, Range = new(0x1000, 0x1010, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
        var convention = new CallingConvention { StackPointer = Storage.Gpr(4), IntegerArguments = [Storage.Gpr(1)], FloatArguments = [], IntegerResults = [rax], FloatResults = [], Clobbered = [rax] };
        var model = new ConservativeCallModel(convention);
        SsaBuilder.PrepareCalls(function, model, null);
        var dom = Dominators.Compute(function);
        SsaBuilder.Build(function, dom, _ => true, model, Storage.Gpr(4));
        Propagate.Run(function, dom);
        Check(block.Statements.OfType<Call>().Single() is { Op.Kind: OpKind.MemoryBarrier, Arguments.Length: 0, Results.Length: 0 }, "SSA 传播不能删除屏障");
        Check(block.Statements[^1] is Return { Value: Const { Value: 42 } }, "屏障不破坏机器寄存器");
        Console.WriteLine("SLEIGH 用户操作与屏障测试通过");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
