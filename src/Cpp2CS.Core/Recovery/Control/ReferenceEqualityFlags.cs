using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Recovery.Typing;
using Cpp2CS.Recovery.Values;

namespace Cpp2CS.Recovery.Control;

/// <summary>x64 CMP 的差值仅供零判断时，以已确认的托管引用相等性表达 ZF。</summary>
internal static class ReferenceEqualityFlags
{
    internal static bool Run(MachineFunction function, ValueModel values, TypeOracle oracle)
    {
        var statements = function.Blocks.SelectMany(b => b.Statements).ToArray();
        var replacements = new Dictionary<Variable, Define>();
        foreach (var define in statements.OfType<Define>())
        {
            if (define.Value is not Binary { Op: BinOp.Sub, Width: 64, Left.Width: 64, Right.Width: 64 } difference
                || define.Target.Width != 64
                || values.Of(define.Target) is not OpSym { Op.Kind: OperatorKind.Binary, Op.Binary: BinOp.Sub, Args: [var left, var right] }
                || oracle.TypeOf(left) is not { } leftType || !ManagedTypes.IsReferenceType(leftType)
                || oracle.TypeOf(right) is not { } rightType || !ManagedTypes.IsReferenceType(rightType)
                || statements.OfType<Phi>().Any(p => p.Sources.Contains(define.Target))) continue;

            var uses = 0;
            var otherUse = false;
            void Inspect(Expr expression)
            {
                if (ZeroTest(expression, define.Target) is not null) { uses++; return; }
                if (expression is Use use && use.Variable == define.Target) otherUse = true;
                foreach (var child in ExprMap.Children(expression)) Inspect(child);
            }
            foreach (var statement in statements)
                foreach (var operand in ExprMap.Operands(statement)) Inspect(operand);
            if (uses == 0 || otherUse) continue;
            // 保持原定义位置及读取次数；差值为零与全宽引用相等严格等价。
            replacements.Add(define.Target, define with
            {
                Value = new Cpp2CS.Ir.Convert(ConvKind.ZeroExtend, new Compare(Cond.Eq, difference.Left, difference.Right), 64)
            });
        }
        if (replacements.Count == 0) return false;
        Expr Rewrite(Expr expression) => ExprMap.Map(expression, node =>
        {
            if (node is not Compare comparison) return null;
            foreach (var variable in replacements.Keys)
                if (ZeroTest(node, variable) is { } condition)
                    return comparison with { Cond = condition == Cond.Eq ? Cond.Ne : Cond.Eq };
            return null;
        });
        foreach (var block in function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
            {
                var statement = block.Statements[i];
                if (statement is Define define && replacements.TryGetValue(define.Target, out var replacement)) statement = replacement;
                block.Statements[i] = ExprMap.MapOperands(statement, Rewrite);
            }
        return true;
    }

    private static Cond? ZeroTest(Expr expression, Variable variable) => expression switch
    {
        Compare { Cond: Cond.Eq or Cond.Ne, Left: Use { Width: 64 } use, Right: Const { Value: 0, Width: 64 } } comparison
            when use.Variable == variable => comparison.Cond,
        Compare { Cond: Cond.Eq or Cond.Ne, Right: Use { Width: 64 } use, Left: Const { Value: 0, Width: 64 } } comparison
            when use.Variable == variable => comparison.Cond,
        _ => null,
    };
}
