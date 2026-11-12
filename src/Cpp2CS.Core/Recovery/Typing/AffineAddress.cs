using Cpp2CS.Ir;
using Cpp2CS.Recovery.Values;

namespace Cpp2CS.Recovery.Typing;

/// <summary>同宽地址代数；扩展、截取、读取和 φ 保持原子身份，避免跨截断改变溢出语义。</summary>
internal sealed record AffineAddress(ulong Offset, IReadOnlyDictionary<Sym, ulong> Terms)
{
    internal static AffineAddress? Normalize(Sym expression)
    {
        const int budget = 512;
        var memo = new Dictionary<Sym, AffineAddress>(ReferenceEqualityComparer.Instance);
        var remaining = budget;
        AffineAddress? Visit(Sym source)
        {
            var value = SymTable.Resolve(source);
            if (value.Width != 64 || --remaining < 0) return null;
            if (memo.TryGetValue(value, out var known)) return known;
            AffineAddress? result;
            if (value is ConstSym constant) result = new(constant.Value, new Dictionary<Sym, ulong>());
            else if (value is OpSym { Op.Kind: OperatorKind.Binary, Args: [var left, var right] } binary
                && left.Width == 64 && right.Width == 64 && binary.Op.Binary is BinOp.Add or BinOp.Sub)
            {
                if (Visit(left) is not { } a || Visit(right) is not { } b) return null;
                var sign = binary.Op.Binary == BinOp.Add ? 1UL : ulong.MaxValue;
                var terms = new Dictionary<Sym, ulong>(a.Terms, ReferenceEqualityComparer.Instance);
                foreach (var (term, coefficient) in b.Terms)
                {
                    var combined = unchecked(terms.GetValueOrDefault(term) + coefficient * sign);
                    if (combined == 0) terms.Remove(term); else terms[term] = combined;
                }
                result = new(unchecked(a.Offset + b.Offset * sign), terms);
            }
            else if (value is OpSym { Op.Kind: OperatorKind.Binary, Args: [var leftFactor, var rightFactor] } multiply
                && multiply.Op.Binary == BinOp.Mul && leftFactor.Width == 64 && rightFactor.Width == 64
                && (leftFactor is ConstSym || rightFactor is ConstSym))
            {
                var factor = (leftFactor as ConstSym ?? (ConstSym)rightFactor).Value;
                if (Visit(leftFactor is ConstSym ? rightFactor : leftFactor) is not { } operand) return null;
                result = new(unchecked(operand.Offset * factor), operand.Terms
                    .Select(p => (p.Key, Value: unchecked(p.Value * factor))).Where(p => p.Value != 0)
                    .ToDictionary(p => p.Key, p => p.Value, (IEqualityComparer<Sym>)ReferenceEqualityComparer.Instance));
            }
            else result = new(0, new Dictionary<Sym, ulong>(ReferenceEqualityComparer.Instance) { [value] = 1 });
            memo[value] = result;
            return result;
        }
        return Visit(expression);
    }

    internal bool Decompose(SymTable syms, Func<Sym, bool> isRoot, out (Sym Root, long Offset, Sym? Index, int Scale) address)
    {
        address = default;
        var roots = Terms.Where(p => isRoot(p.Key)).ToArray();
        if (roots is not [{ Value: 1 } root]) return false;
        var indices = Terms.Where(p => !ReferenceEquals(p.Key, root.Key)).OrderBy(p => p.Key.Id).ToArray();
        if (indices.Length == 0) { address = (root.Key, unchecked((long)Offset), null, 0); return true; }
        if (indices.Any(p => p.Value is 0 or > int.MaxValue)) return false;
        ulong Gcd(ulong a, ulong b) { while (b != 0) (a, b) = (b, a % b); return a; }
        var scale = indices.Select(p => p.Value).Aggregate(Gcd);
        Sym? index = null;
        foreach (var term in indices)
        {
            var coefficient = term.Value / scale;
            var value = coefficient == 1 ? term.Key : syms.Binary(BinOp.Mul, term.Key, syms.Const(coefficient, 64), 64);
            index = index is null ? value : syms.Binary(BinOp.Add, index, value, 64);
        }
        address = (root.Key, unchecked((long)Offset), index, (int)scale);
        return true;
    }
}
