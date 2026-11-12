using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Recovery.Values;

namespace Cpp2CS.Recovery.Shape;

/// <summary>非负或 NaN 的浮点值按等于零、大于零、无序三种关系核对完整条件，保留所有可行路径。</summary>
internal static class FloatRangeBranches
{
    internal static int Run(MachineFunction function, ValueModel values)
    {
        var changed = 0;
        foreach (var block in function.Blocks)
        {
            if (block.Handler is not null || block.IsLandingPad || block.Statements.LastOrDefault() is not Branch branch
                || block.NormalSuccessors.ToArray() is not [var taken, var next]
                || taken.Start != branch.Target || next.Start != branch.Fallthrough || taken == next
                || Constant(values.Operands(branch)[0]) is not { } constant) continue;
            block.Statements[^1] = new Jump(branch.Address, constant ? branch.Target : branch.Fallthrough);
            MachineFunction.RemoveEdgeAt(block, constant ? 1 : 0);
            changed++;
        }
        return changed;
    }

    internal static bool? Constant(Sym condition)
    {
        var pending = new Stack<Sym>();
        var seen = new HashSet<Sym>();
        var candidates = new HashSet<Sym>();
        pending.Push(condition);
        while (pending.TryPop(out var current))
        {
            current = SymTable.Resolve(current);
            if (!seen.Add(current)) continue;
            if (seen.Count > 256) return null;
            switch (current)
            {
                case OpSym { Op.Kind: OperatorKind.Compare, Args: [var left, var right] } comparison
                    when Floating(comparison.Op.Cond):
                    foreach (var value in new[] { left, right }.Select(SymTable.Resolve))
                        if (value is not ConstSym && Nonnegative(value)) candidates.Add(value);
                    break;
                case OpSym op:
                    foreach (var arg in op.Args) pending.Push(arg);
                    break;
                case ConcatSym concat:
                    foreach (var part in concat.Parts) pending.Push(part);
                    break;
            }
        }
        foreach (var candidate in candidates)
        {
            var results = Enumerable.Range(0, 3).Select(relation => Boolean(condition, candidate, relation, 0)).ToArray();
            if (results[0] is { } first && results.All(r => r == first)) return first;
        }
        return null;
    }

    // relation：0 为零，1 为正数（含正无穷），2 为 NaN；不假设 NaN 的载荷与符号。
    private static bool? Boolean(Sym value, Sym candidate, int relation, int depth)
    {
        if (depth > 48) return null;
        value = SymTable.Resolve(value);
        if (SymTable.Bit(value) is { } bit && !ReferenceEquals(bit, value)) return Boolean(bit, candidate, relation, depth + 1);
        bool? Sub(Sym input) => Boolean(input, candidate, relation, depth + 1);
        if (value is ConstSym c) return c.Value != 0;
        if (value is not OpSym op) return null;
        switch (op.Op.Kind)
        {
            case OperatorKind.Not when op.Args is [var operand]: return Sub(operand) is { } v ? !v : null;
            case OperatorKind.And or OperatorKind.Or when op.Args is [var left, var right]:
                return Logical(op.Op.Kind == OperatorKind.And, Sub(left), Sub(right));
            case OperatorKind.Binary when BooleanValue(op) && op.Args is [var left, var right]:
                return op.Op.Binary switch {
                    BinOp.And => Logical(true, Sub(left), Sub(right)),
                    BinOp.Or => Logical(false, Sub(left), Sub(right)),
                    BinOp.Xor => Sub(left) is { } first && Sub(right) is { } second ? first != second : null,
                    _ => null,
                };
            case OperatorKind.Compare when op.Args is [var left, var right]:
                left = SymTable.Resolve(left); right = SymTable.Resolve(right);
                if (Floating(op.Op.Cond))
                {
                    if (left.Width != candidate.Width || right.Width != candidate.Width) return null;
                    // 所有比较必须对应同一值的快照，不能把另一次堆读取视作同一个浮点值。
                    var l = ReferenceEquals(left, candidate); var r = ReferenceEquals(right, candidate);
                    int? order = l && r ? relation == 2 ? 2 : 0
                        : l && Zero(right) ? relation == 2 ? 2 : relation
                        : r && Zero(left) ? relation == 2 ? 2 : -relation
                        : Zero(left) && Zero(right) ? 0 : null;
                    return order is { } o ? Compare(op.Op.Cond, o) : null;
                }
                if (op.Op.Cond is Cond.Eq or Cond.Ne && BooleanValue(left) && BooleanValue(right)
                    && Sub(left) is { } a && Sub(right) is { } b) return (a == b) == (op.Op.Cond == Cond.Eq);
                break;
        }
        return null;
    }

    private static bool BooleanValue(Sym value, int depth = 0) => depth <= 32 && (value is ConstSym { Value: 0 or 1 }
        || SymTable.Bit(value) is not null
        || value is OpSym { Op.Kind: OperatorKind.Binary, Args: [var a, var b] } op
            && op.Op.Binary is BinOp.And or BinOp.Or or BinOp.Xor && BooleanValue(a, depth + 1) && BooleanValue(b, depth + 1));
    private static bool? Logical(bool and, bool? left, bool? right) => and
        ? left == false || right == false ? false : left == true && right == true ? true : null
        : left == true || right == true ? true : left == false && right == false ? false : null;
    private static bool Floating(Cond condition) => condition is >= Cond.FEq and <= Cond.FUne;
    private static bool Zero(Sym value) => value is ConstSym { Width: 32 or 64 } c
        && (c.Value & (c.Width == 32 ? 0x7fffffffUL : 0x7fffffffffffffffUL)) == 0;

    // 2 表示无序，-1/0/1 表示小于/等于/大于。
    private static bool Compare(Cond condition, int order) => condition switch {
        Cond.FEq => order == 0, Cond.FNe => order is -1 or 1,
        Cond.FLt => order == -1, Cond.FLe => order is -1 or 0,
        Cond.FGt => order == 1, Cond.FGe => order is 0 or 1,
        Cond.FUnordered => order == 2, Cond.FOrdered => order != 2,
        Cond.FUlt => order is -1 or 2, Cond.FUle => order is -1 or 0 or 2,
        Cond.FUgt => order is 1 or 2, Cond.FUge => order is 0 or 1 or 2,
        Cond.FUeq => order is 0 or 2, Cond.FUne => order != 0,
        _ => throw new ArgumentOutOfRangeException(nameof(condition)),
    };

    private static bool Nonnegative(Sym value, int depth = 0)
    {
        if (depth > 32) return false;
        value = SymTable.Resolve(value);
        if (value.Width is not (32 or 64)) return false;
        bool Sub(Sym input) => Nonnegative(input, depth + 1);
        return value switch {
            ConstSym c => Zero(c) || c.Value >> (c.Width - 1) == 0
                || (c.Value & (c.Width == 32 ? 0x7fffffffUL : 0x7fffffffffffffffUL)) > (c.Width == 32 ? 0x7f800000UL : 0x7ff0000000000000UL),
            OpSym { Op.Kind: OperatorKind.Binary, Args: [var a, var b] } op when op.Op.Binary == BinOp.FMul
                => a.Width == value.Width && b.Width == value.Width && ReferenceEquals(SymTable.Resolve(a), SymTable.Resolve(b)),
            OpSym { Op.Kind: OperatorKind.Binary, Args: [var a, var b] } op when op.Op.Binary == BinOp.FAdd
                => a.Width == value.Width && b.Width == value.Width && Sub(a) && Sub(b),
            OpSym { Op.Kind: OperatorKind.Unary, Args: [var a] } op when op.Op.Unary is UnOp.FAbs or UnOp.FSqrt => a.Width == value.Width,
            OpSym { Op.Kind: OperatorKind.Convert, Args: [var a] } op when op.Op.Conversion == ConvKind.FloatToFloat => Sub(a),
            OpSym { Op.Kind: OperatorKind.Convert, Args: [{ Width: > 0 and <= 64 }] } op when op.Op.Conversion == ConvKind.UIntToFloat => true,
            OpSym { Op.Kind: OperatorKind.Select, Args: [_, var a, var b] } => Sub(a) && Sub(b),
            _ => false,
        };
    }
}
