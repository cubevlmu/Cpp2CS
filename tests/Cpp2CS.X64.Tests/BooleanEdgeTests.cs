using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Ssa;

namespace Cpp2CS.X64.Tests;

internal static class BooleanEdgeTests
{
    internal static void Run()
    {
        foreach (var width in new[] { 32, 64 })
        foreach (var condition in new[] { Cond.Eq, Cond.Ne, Cond.FEq })
        foreach (var bound in new ulong[] { 0, 0x100000001 })
        foreach (var reversed in new[] { false, true })
        {
            var input = new Variable(Storage.Gpr(1), 0);
            var first = new Variable(Storage.Temp(1000), 1);
            var second = new Variable(Storage.Temp(1001), 1);
            var head = new Block(0x1000) { End = 0x1010 };
            var yes = new Block(0x1010) { End = 0x1020 };
            var no = new Block(0x1020) { End = 0x1030 };
            var compared = Expr.C(bound, width);
            var value = new Use(input, width);
            head.Statements.AddRange([
                new Define(0x1000, first, new Ir.Convert(ConvKind.ZeroExtend,
                    new Compare(condition, reversed ? compared : value, reversed ? value : compared), 8)),
                new Define(0x1001, second, new Ir.Convert(ConvKind.ZeroExtend, new Compare(Cond.Eq, new Use(first, 8), Expr.C(0, 8)), 8)),
                new Branch(0x1002, new Compare(Cond.Ne, new Use(second, 8), Expr.C(0, 8)), no.Start, yes.Start),
            ]);
            yes.Statements.AddRange([new Store(0x1010, Expr.C(0x2000, 64), Expr.C(7, 32)), new Return(0x1011) { Value = new Use(input, 32) }]);
            no.Statements.Add(new Return(0x1020) { Value = new Use(input, 64) });
            MachineFunction.AddEdge(head, no); MachineFunction.AddEdge(head, yes);
            var function = new MachineFunction { Entry = head.Start,
                Range = new(head.Start, no.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, yes, no] };
            function.Renumber();
            Propagate.Run(function, Dominators.Compute(function));
            var equality = condition == Cond.Eq ? yes : no;
            var unequal = condition == Cond.Eq ? no : yes;
            var returned = ((Return)equality.Statements[^1]).Value;
            Check(width == 64 && condition != Cond.FEq ? returned is Const constant && constant.Value == (condition == Cond.Eq ? (uint)bound : bound)
                : returned is Use, "P-code 字节布尔链只在完整整数相等边提供位型；低32位为零不能证明64位指针为空，浮点相等也不提供位型");
            Check(((Return)unequal.Statements[^1]).Value is Use, "不等边不应产生任意常量");
            Check(yes.Statements.OfType<Store>().Count() == 1, "条件传播保留写入效果");
            Check(SsaCheck.Verify(function, Dominators.Compute(function)).Count == 0, "布尔链推导须保持 SSA");
        }
        foreach (var isAnd in new[] { false, true })
        {
            var head = new Block(0x1000) { End = 0x1010 };
            var yes = new Block(0x1010) { End = 0x1020 };
            var no = new Block(0x1020) { End = 0x1030 };
            var input = new Use(new Variable(Storage.Gpr(1), 0), 64);
            head.Statements.Add(new Branch(0x1000, new Logical(isAnd,
                new Compare(Cond.Eq, input, Expr.C(0, 64)), new Compare(Cond.Ne, new Use(new Variable(Storage.Gpr(2), 0), 64), Expr.C(0, 64))), yes.Start, no.Start));
            yes.Statements.Add(new Return(yes.Start) { Value = input }); no.Statements.Add(new Return(no.Start) { Value = input });
            MachineFunction.AddEdge(head, yes); MachineFunction.AddEdge(head, no);
            var function = new MachineFunction { Entry = head.Start,
                Range = new(head.Start, no.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, yes, no] };
            function.Renumber(); EdgeConstants.Run(function);
            Check((((Return)yes.Statements[^1]).Value is Const { Value: 0 }) == isAnd, "合取为真才保证每个条件，析取为真不保证任一条件");
            Check(((Return)no.Statements[^1]).Value is Use, "析取为假只能证明指针不等于零，不能推断其具体值");
        }
        foreach (var width in new[] { 8, 16, 32, 64 })
        foreach (var partial in new[] { false, true })
        foreach (var bound in new ulong[] { 0, 1, 0x80000000, ulong.MaxValue })
        {
            var fullWidth = partial ? 64 : width;
            var input = new Variable(new Storage(Bank.Temp, 7000, fullWidth), 0);
            var other = new Variable(new Storage(Bank.Temp, 7001, fullWidth), 1);
            var joined = new Variable(new Storage(Bank.Temp, 7002, fullWidth), 1);
            var head = new Block(0x1000); var alternate = new Block(0x1100); var merge = new Block(0x1200);
            var constant = Expr.C(bound, width);
            head.Statements = [new Branch(head.Start, new Compare(Cond.Eq, new Use(input, width), constant), merge.Start, alternate.Start)];
            alternate.Statements = [new Define(alternate.Start, other, Expr.C(~bound, fullWidth)), new Jump(alternate.Start + 1, merge.Start)];
            merge.Statements = [new Phi(merge.Start, joined, [input, other]), new Return(merge.Start + 1) { Value = new Use(joined, fullWidth) }];
            MachineFunction.AddEdge(head, merge); MachineFunction.AddEdge(head, alternate); MachineFunction.AddEdge(alternate, merge);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, merge.Start + 2, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, alternate, merge] };
            function.Renumber();
            EdgeConstants.Run(function);
            Check(SsaCheck.Verify(function, Dominators.Compute(function)).Count == 0, "窄存储的边常量与 φ 来源宽度一致");
            var phi = merge.Statements.OfType<Phi>().Single();
            if (width == fullWidth)
            {
                var definition = head.Statements.OfType<Define>().Single();
                Check(phi.Sources[0] == definition.Target && definition.Target.Width == width && definition.Value == constant,
                    "完整 8/16/32/64 位存储的相等边提供精确位型");
            }
            else Check(phi.Sources[0] == input && !head.Statements.OfType<Define>().Any(), "窄比较不替换完整寄存器的 φ 输入");
        }
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
