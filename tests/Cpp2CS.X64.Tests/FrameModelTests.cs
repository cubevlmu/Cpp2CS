using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Storage;

namespace Cpp2CS.X64.Tests;

internal static class FrameModelTests
{
    internal static void Run()
    {
        foreach (var loop in new[] { false, true })
        {
            var seed = new Variable(Storage.Gpr(1), 1);
            var joined = new Variable(Storage.Gpr(2), 1);
            var next = new Variable(Storage.Gpr(3), 1);
            var block = new Block(0x1000) { End = 0x1010 };
            block.Statements.Add(new Define(0x1000, seed, new FrameAddress(-32)));
            if (loop)
            {
                block.Statements.Add(new Phi(0x1001, joined, [seed, next]));
                block.Statements.Add(new Define(0x1002, next, new Binary(BinOp.Add, new Use(joined, 64), Expr.C(8, 64), 64)));
            }
            var store = new Store(0x1003, new FrameAddress(-8), Expr.C(7, 32));
            block.Statements.Add(store);
            block.Statements.Add(new Return(0x1004) { Value = new Load(new FrameAddress(-8), 32) });
            var function = new MachineFunction { Entry = block.Start,
                Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            if (loop)
            {
                var entry = new Block(0xff0) { End = 0x1000 };
                entry.Statements.Add(block.Statements[0]);
                block.Statements.RemoveAt(0);
                entry.Statements.Add(new Jump(0xff1, block.Start));
                var exit = new Block(0x1010) { End = 0x1011 };
                exit.Statements.Add(block.Statements[^1]);
                block.Statements[^1] = new Branch(0x1004,
                    new Compare(Cond.Ne, new Use(new Variable(Storage.Gpr(7), 0), 64), Expr.C(0, 64)), block.Start, exit.Start);
                MachineFunction.AddEdge(entry, block);
                MachineFunction.AddEdge(block, block);
                MachineFunction.AddEdge(block, exit);
                function = new MachineFunction { Entry = entry.Start,
                    Range = new(entry.Start, exit.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [entry, block, exit] };
            }
            var model = new FrameModel(function, new NoCalls());
            if (loop)
            {
                Check(!model.PointerAnalysisComplete && model.Slot(new FrameAddress(-8)) is null,
                    "无限递增的指针集合必须终止，不能保留部分精确结果");
                Check(model.Escaped(-8, 4) && !model.Unobserved(-8, 4) && model.Reach(block, 4, -8, 4).Exhausted,
                    "未完成指向分析时不得证明私有、未观察或完整来源");
                Check(!FrameForwarding.Run(function, new NoCalls()) && block.Statements.Contains(store),
                    "预算耗尽保留原始读写，不作为恢复成功依据");
            }
            else Check(model.PointerAnalysisComplete && model.Slot(new Use(seed, 64)) == -32
                && model.Reach(block, 2, -8, 4).Complete, "有限指向集合仍提供精确帧来源");
        }
        foreach (var unknown in new[] { false, true })
        {
            var left = new Block(0x2000) { End = 0x2010 }; var right = new Block(0x2020) { End = 0x2030 };
            var join = new Block(0x2040) { End = 0x2050 };
            var a = new Variable(Storage.Gpr(1), 1); var b = new Variable(Storage.Gpr(2), 1); var p = new Variable(Storage.Gpr(3), 1);
            left.Statements.Add(new Define(left.Start, a, new FrameAddress(-8)));
            right.Statements.Add(new Define(right.Start, b, unknown ? new Entry(Storage.Gpr(8)) : new FrameAddress(-8)));
            left.Statements.Add(new Jump(0x2001, join.Start)); right.Statements.Add(new Jump(0x2021, join.Start));
            join.Statements.Add(new Phi(join.Start, p, [a, b]));
            var write = new Store(0x2041, new Use(p, 64), Expr.C(9, 32));
            join.Statements.Add(write); join.Statements.Add(new Return(0x2042) { Value = new Load(new FrameAddress(-8), 32) });
            MachineFunction.AddEdge(left, join); MachineFunction.AddEdge(right, join);
            var function = new MachineFunction { Entry = left.Start,
                Range = new(left.Start, join.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [left, right, join] };
            var model = new FrameModel(function, new NoCalls());
            Check((model.Slot(new Use(p, 64)) == -8) == !unknown, "部分帧候选不能覆盖未知 φ 入边");
            var reach = model.Reach(join, 2, -8, 4);
            Check(unknown ? !reach.Complete && reach.Clobber == write : reach.Complete && reach.Stores.Single() == write,
                "可能写入帧不能伪装成每条路径都确定写入");
        }
    }

    private sealed class NoCalls : IFrameCallEffects
    {
        public ArgumentUse Argument(Call call, int index) => ArgumentUse.Unknown;
        public bool WritesEscaped(Call call) => true;
        public int? StackRead(Call call) => null;
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
