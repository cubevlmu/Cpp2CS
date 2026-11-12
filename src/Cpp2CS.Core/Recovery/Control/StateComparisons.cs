using Cpp2CS.Ir;

namespace Cpp2CS.Recovery.Control;

/// <summary>状态局部的模 2^32 等值比较，消去编译器产生的整数偏移和同宽转换。</summary>
internal static class StateComparisons
{
    internal static ManagedValue Normalize(ManagedValue value, LocalValue state)
    {
        if (value is not ComparisonValue { Condition: Cond.Eq or Cond.Ne } comparison || !Integer(state)) return value;
        var (left, right) = comparison.Left is ConstantValue ? (comparison.Right, comparison.Left) : (comparison.Left, comparison.Right);
        if (right is not ConstantValue constant || !Integer(constant) || Offset(left, 0) is not { } offset) return value;
        return comparison with { Left = state, Right = new ConstantValue(unchecked((uint)constant.Bits - offset), state.Type, 32) };

        uint? Offset(ManagedValue term, int depth)
        {
            if (depth > 32 || !Integer(term)) return null;
            if (term is LocalValue local && local.Variable == state.Variable) return 0;
            if (term is ConversionValue { Kind: ConvKind.Bitcast or ConvKind.Truncate or ConvKind.ZeroExtend or ConvKind.SignExtend } conversion)
                return Offset(conversion.Operand, depth + 1);
            if (term is BinaryValue { Op: BinOp.Add or BinOp.Sub, Right: ConstantValue right } binary
                && Integer(right) && Offset(binary.Left, depth + 1) is { } previous)
                return binary.Op == BinOp.Add ? unchecked(previous + (uint)right.Bits) : unchecked(previous - (uint)right.Bits);
            return null;
        }
    }

    private static bool Integer(ManagedValue value) => value.Width == 32 && ManagedTypes.PrimitiveName(value.Type) is "Int32" or "UInt32";
}
