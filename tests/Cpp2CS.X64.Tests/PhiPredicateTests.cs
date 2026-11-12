using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Ssa;

namespace Cpp2CS.X64.Tests;

internal static class PhiPredicateTests
{
    internal static void Run()
    {
        var cases = 0;
        foreach (var variant in new[] { "valid", "zero-slow", "other-condition", "load-high", "intrinsic-high", "partial" })
        foreach (var fullUse in new[] { false, true })
        {
            var head = new Block(0x1000); var init = new Block(0x1100); var merge = new Block(0x1200);
            var yes = new Block(0x1300); var no = new Block(0x1400);
            var read = new Variable(Storage.Gpr(1), 1); var copy = read with { Version = 2 }; var set = read with { Version = 3 }; var joined = read with { Version = 4 };
            var high = new Variable(Storage.Gpr(3), 0); var loadedHigh = high with { Version = 1 };
            var other = new Variable(Storage.Gpr(2), 0);
            var flag = new Variable(new Storage(Bank.Temp, 1, 8), 1);
            var tested = variant == "other-condition" ? new Use(other, 8) : new Use(read, 8);
            head.Statements = [new Define(0x1000, read, new Cpp2CS.Ir.Convert(ConvKind.ZeroExtend, new Load(Expr.C(0x4000, 64), 8), 64)),
                new Define(0x1001, copy, new Cpp2CS.Ir.Convert(ConvKind.ZeroExtend, new Use(read, 32), 64)),
                new Define(0x1002, flag, new Cpp2CS.Ir.Convert(ConvKind.ZeroExtend, new Compare(Cond.Ne, tested, Expr.C(0, 8)), 8)),
                new Branch(0x1003, new Compare(Cond.Ne, new Use(flag, 8), Expr.C(0, 8)), merge.Start, init.Start)];
            init.Statements = [new Call(0x1100, CallKind.Direct, Expr.C(0x2000, 64))];
            if (variant == "load-high") init.Statements.Add(new Define(0x1101, loadedHigh, new Load(Expr.C(0x6000, 64), 64)));
            if (variant == "intrinsic-high") init.Statements.Add(new Define(0x1101, loadedHigh, new Intrinsic("unmodeled_effect", [], 64)));
            var slow = variant == "zero-slow" ? 0UL : 1UL;
            init.Statements.AddRange([new Define(0x1102, set, new Insert(new Use(variant is "load-high" or "intrinsic-high" ? loadedHigh : high, 64), Expr.C(slow, 8), 0)),
                new Store(0x1103, Expr.C(0x4000, 64), Expr.C(1, 8)), new Jump(0x1104, merge.Start)]);
            var width = variant == "partial" ? 16 : 8;
            merge.Statements = [new Phi(0x1200, joined, [copy, set])];
            if (fullUse) merge.Statements.Add(new Store(0x1201, Expr.C(0x5000, 64), new Use(joined, 64)));
            merge.Statements.Add(new Branch(0x1202, new Compare(Cond.Ne, new Use(joined, width), Expr.C(0, width)), yes.Start, no.Start));
            yes.Statements = [new Return(yes.Start) { Value = Expr.C(1, 8) }]; no.Statements = [new Return(no.Start) { Value = Expr.C(0, 8) }];
            MachineFunction.AddEdge(head, merge); MachineFunction.AddEdge(head, init); MachineFunction.AddEdge(init, merge);
            MachineFunction.AddEdge(merge, yes); MachineFunction.AddEdge(merge, no);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, no.Start + 1, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, init, merge, yes, no] };
            function.Renumber(); Propagate.Run(function, Dominators.Compute(function));
            Check(SsaCheck.Verify(function, Dominators.Compute(function)).Count == 0, "入边谓词折叠保持 SSA");
            Check((merge.Statements.OfType<Branch>().Single().Condition is Const { Value: 1 }) == (variant is "valid" or "load-high"),
                "只折叠每条入边都证明成立的低位判定：" + variant);
            foreach (var initialFlag in new[] { 0UL, 1UL, 2UL, 128UL, 255UL })
            foreach (var otherValue in new[] { 0UL, 1UL })
            {
                const ulong highBits = 0x89abcdef00000100;
                var values = new Dictionary<Variable, ulong> { [high] = highBits, [other] = otherValue };
                var evaluator = new Evaluator(); evaluator.Written[0x4000] = (byte)initialFlag;
                for (var i = 0; i < 8; i++) evaluator.Written[0x6000UL + (ulong)i] = (byte)(highBits >> (8 * i));
                ulong Eval(Expr expression) => (ulong)evaluator.Eval(ExprMap.Map(expression, part => part is Use use ? Expr.C(values[use.Variable], use.Width) : null));
                var block = head; Block? previous = null; ulong actual = 0; ulong? stored = null; var calls = 0; var reads = 0; var intrinsics = 0;
                for (var steps = 0; block is not null && steps < 8; steps++)
                {
                    Block? next = null;
                    foreach (var statement in block.Statements)
                        switch (statement)
                        {
                            case Phi phi: values[phi.Target] = values[phi.Sources[block.Predecessors.IndexOf(previous!)]]; break;
                            case Define { Value: Intrinsic } d: values[d.Target] = highBits; intrinsics++; break;
                            case Define d:
                                reads += ExprMap.Walk(d.Value).OfType<Load>().Count(); values[d.Target] = Eval(d.Value); break;
                            case Store store:
                                var at = Eval(store.Target); var value = Eval(store.Value);
                                if (at == 0x5000) stored = value;
                                for (var i = 0; i < store.Value.Width / 8; i++) evaluator.Written[at + (ulong)i] = (byte)(value >> (8 * i));
                                break;
                            case Call: calls++; break;
                            case Branch branch: next = function.Blocks.Single(b => b.Start == (Eval(branch.Condition) != 0 ? branch.Target : branch.Fallthrough)); break;
                            case Jump jump: next = function.Blocks.Single(b => b.Start == jump.Target); break;
                            case Return ret: actual = Eval(ret.Value!); break;
                        }
                    previous = block; block = next;
                }
                var fast = (variant == "other-condition" ? otherValue : initialFlag) != 0;
                var expectedValue = fast ? initialFlag : (highBits & ~255UL) | slow;
                var expected = (expectedValue & Expr.Mask(width)) != 0 ? 1UL : 0UL;
                Check(actual == expected && (!fullUse || stored == expectedValue), "不能把非零标志值 2、128、255 改成 1，也不能改写高位");
                Check(reads == 1 + (!fast && variant == "load-high" ? 1 : 0) && calls == (fast ? 0 : 1)
                    && intrinsics == (!fast && variant == "intrinsic-high" ? 1 : 0) && evaluator.Failure is null,
                    "保留路径上的读取、调用和未知操作次数");
                cases++;
            }
        }
        Console.WriteLine($"φ 入边判零执行对照通过：{cases} 组输入，含非规范非零字节、高位与读取效果保留");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
