using Cpp2CS.Ir;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Recovery.Control;

namespace Cpp2CS.X64.Tests;

internal static class StateComparisonTests
{
    internal static void Run(TypeDef[] core)
    {
        var integer = new DefinitionRef(core.Single(t => t.Name == "Int32"), []);
        var unsigned = new DefinitionRef(core.Single(t => t.Name == "UInt32"), []);
        var boolean = new DefinitionRef(core.Single(t => t.Name == "Boolean"), []);
        var single = new DefinitionRef(core.Single(t => t.Name == "Single"), []);
        var state = new LocalValue(new Variable(Storage.Gpr(0), 1), integer, 32);
        var random = new Random(617);
        uint[] edges = [0, 1, 0x7fffffff, 0x80000000, 0xffffffff];
        foreach (var subtract in new[] { false, true })
        foreach (var reverse in new[] { false, true })
        foreach (var condition in new[] { Cond.Eq, Cond.Ne })
        foreach (var offset in edges)
        foreach (var bound in edges)
        {
            ManagedValue term = new ConversionValue(ConvKind.Bitcast,
                new BinaryValue(subtract ? BinOp.Sub : BinOp.Add, new ConversionValue(ConvKind.Bitcast, state, unsigned, 32),
                    new ConstantValue(offset, unsigned, 32), unsigned, 32), integer, 32);
            var constant = new ConstantValue(bound, integer, 32);
            var original = new ComparisonValue(condition, reverse ? constant : term, reverse ? term : constant, boolean);
            var normalized = StateComparisons.Normalize(original, state);
            Check(normalized is ComparisonValue { Left: LocalValue, Right: ConstantValue }, "同宽整数偏移必须转成状态与常量直接比较");
            var actualBound = (uint)((ConstantValue)((ComparisonValue)normalized).Right).Bits;
            foreach (var value in edges.Concat(Enumerable.Range(0, 64).Select(_ => (uint)random.NextInt64(0, 1L << 32))).Append(actualBound))
            {
                var bits = subtract ? unchecked(value - offset) : unchecked(value + offset);
                Check((condition == Cond.Eq ? bits == bound : bits != bound) == (condition == Cond.Eq ? value == actualBound : value != actualBound),
                    "边界、溢出和随机状态的条件结果须保持一致");
            }
        }
        foreach (var condition in new[] { Cond.Slt, Cond.Ule })
        {
            var test = new ComparisonValue(condition, new BinaryValue(BinOp.Add, state, new ConstantValue(1, integer, 32), integer, 32),
                new ConstantValue(0, integer, 32), boolean);
            Check(ReferenceEquals(StateComparisons.Normalize(test, state), test), "范围比较不能按模加法等值规则消去偏移");
        }
        foreach (var term in new ManagedValue[] {
            new ConversionValue(ConvKind.Bitcast, new ConversionValue(ConvKind.Bitcast, state, single, 32), integer, 32),
            new ConversionValue(ConvKind.ZeroExtend, new ConversionValue(ConvKind.Truncate, state, integer, 8), integer, 32),
            new BinaryValue(BinOp.Add, state, new ConstantValue(1, integer, 64), integer, 32),
            new LocalValue(new Variable(Storage.Gpr(1), 1), integer, 32) })
        {
            var test = new ComparisonValue(Cond.Eq, term, new ConstantValue(0, integer, 32), boolean);
            Check(ReferenceEquals(StateComparisons.Normalize(test, state), test), "拒绝浮点、中间截断、不同宽度和其他局部");
        }
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
