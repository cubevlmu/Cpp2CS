using Cpp2CS.Machine.Flow;
using Cpp2CS.Ir;

namespace Cpp2CS.Machine.Ssa;

using Storage = Cpp2CS.Ir.Storage;

/// <summary>传播条件边确定的完整位型：用于 φ 输入，以及没有其他前驱的目标块。</summary>
public static class EdgeConstants
{
    public static int Run(MachineFunction function)
    {
        var definitions = function.Blocks.SelectMany(b => b.Statements).OfType<Define>().ToDictionary(d => d.Target, d => d.Value);
        var nextTemp = -1;
        Variable Fresh(int width)
        {
            if (nextTemp < 0)
            {
                var statements = function.Blocks.SelectMany(b => b.Statements).ToArray();
                var variables = statements.SelectMany(s => s switch
                {
                    Define d => new[] { d.Target },
                    Phi p => p.Sources.Append(p.Target),
                    Call c => c.Defines.Where(v => v is not null),
                    _ => [],
                }).Concat(statements.SelectMany(ExprMap.Operands).SelectMany(ExprMap.Walk).OfType<Use>().Select(u => u.Variable));
                nextTemp = variables.Where(v => v.Storage.Bank == Bank.Temp).Select(v => v.Storage.Index).DefaultIfEmpty(-1).Max() + 1;
            }
            return new Variable(new Storage(Bank.Temp, nextTemp++, width), 1);
        }

        var replaced = 0;
        foreach (var from in function.Blocks)
        {
            if (from.Statements.LastOrDefault() is not Branch branch || branch.Target == branch.Fallthrough) continue;
            var normal = from.NormalSuccessors.ToArray();
            if (normal.Length != 2 || normal[0].Start != branch.Target || normal[1].Start != branch.Fallthrough) continue;
            var constants = new Dictionary<Const, Variable>();
            for (var side = 0; side < 2; side++)
            {
                var facts = Facts(branch.Condition, side == 0, definitions);
                if (facts.Count == 0) continue;
                var target = normal[side];
                var incoming = target.Predecessors.IndexOf(from);
                if (incoming < 0) throw new InvalidOperationException("CFG 前驱与后继不一致");
                for (var i = 0; i < target.Statements.Count && target.Statements[i] is Phi phi; i++)
                {
                    var source = phi.Sources[incoming];
                    if (!facts.TryGetValue(source, out var constant) || constant.Width != phi.Target.Width) continue;
                    if (!constants.TryGetValue(constant, out var replacement))
                    {
                        constants.Add(constant, replacement = Fresh(constant.Width));
                        from.Statements.Insert(from.Statements.Count - 1, new Define(branch.Address, replacement, constant));
                    }
                    var sources = (Variable[])phi.Sources.Clone();
                    sources[incoming] = replacement;
                    target.Statements[i] = phi with { Sources = sources };
                    replaced++;
                }
                if (target.Predecessors.Count != 1) continue;
                for (var i = 0; i < target.Statements.Count; i++)
                {
                    var statement = target.Statements[i];
                    if (statement is Phi) continue;
                    var rewritten = ExprMap.MapOperands(statement, e =>
                    {
                        var mapped = ExprMap.Map(e, part => part is Use use && facts.TryGetValue(use.Variable, out var value) && use.Width <= value.Width
                            ? Fold.Convert(ConvKind.Truncate, value, use.Width) : null);
                        return ReferenceEquals(mapped, e) ? e : Fold.Simplify(mapped);
                    });
                    if (ReferenceEquals(statement, rewritten)) continue;
                    target.Statements[i] = rewritten;
                    replaced++;
                }
            }
        }
        return replaced;
    }

    /// <summary>仅约束返回常量位宽内的低位，供支配路径上的局部替换使用，不赋予完整寄存器常量。</summary>
    internal static IReadOnlyDictionary<Variable, Const> PartialFacts(Expr condition, bool truth, IReadOnlyDictionary<Variable, Expr> definitions)
        => Facts(condition, truth, definitions, partial: true);

    private static Dictionary<Variable, Const> Facts(Expr condition, bool truth, IReadOnlyDictionary<Variable, Expr> definitions, bool partial = false)
    {
        var result = new Dictionary<Variable, Const>();
        var conflicts = new HashSet<Variable>();
        void Add(Use use, Const constant)
        {
            // 默认约束完整存储位型；部分事实仅以常量位宽约束低位，浮点相等不等于位型相同。
            if (use.Width is not (8 or 16 or 32 or 64) || !partial && use.Width != use.Variable.Width
                || constant.Width != use.Width || conflicts.Contains(use.Variable)) return;
            if (result.TryGetValue(use.Variable, out var previous) && previous != constant)
            {
                result.Remove(use.Variable); conflicts.Add(use.Variable);
            }
            else result[use.Variable] = constant;
        }
        bool Boolean(Expr expression, int depth) => depth <= 32 && expression switch
        {
            Compare or Logical or Not => true,
            Use use when definitions.TryGetValue(use.Variable, out var definition) && use.Width == definition.Width => Boolean(definition, depth + 1),
            Ir.Convert { Kind: ConvKind.ZeroExtend or ConvKind.SignExtend or ConvKind.Truncate } convert => Boolean(convert.Operand, depth + 1),
            _ => false,
        };
        void Equality(Expr expression, Const constant, int depth = 0)
        {
            if (depth > 16 || expression.Width != constant.Width) return;
            if (expression is Use use)
            {
                Add(use, constant);
                if (partial && definitions.TryGetValue(use.Variable, out var definition) && definition.Width == use.Width
                    && definition is Use or Binary { Op: BinOp.Add or BinOp.Sub, Right: Const })
                    Equality(definition, constant, depth + 1);
            }
            else if (partial && expression is Binary { Op: BinOp.Add or BinOp.Sub, Right: Const offset } binary
                && offset.Width == constant.Width && binary.Left.Width == constant.Width)
                Equality(binary.Left, Expr.C(binary.Op == BinOp.Add ? unchecked(constant.Value - offset.Value)
                    : unchecked(constant.Value + offset.Value), constant.Width), depth + 1);
        }
        void Visit(Expr expression, bool value, int depth = 0)
        {
            if (depth > 32) return;
            // 布尔来源继续展开前保留当前 SSA 值为零的事实；后续代码可能直接复用该字节。
            if (partial && !value && expression is Use zero) Add(zero, Expr.C(0, zero.Width));
            switch (expression)
            {
                // P-code 把条件标志存成字节，再与零比较；只穿透已证明的布尔定义，不展开被比较数据的读取。
                case Use use when definitions.TryGetValue(use.Variable, out var definition)
                    && use.Width == definition.Width && Boolean(definition, depth + 1):
                    Visit(definition, value, depth + 1); break;
                case Ir.Convert { Kind: ConvKind.ZeroExtend or ConvKind.SignExtend or ConvKind.Truncate } convert
                    when Boolean(convert.Operand, depth + 1):
                    Visit(convert.Operand, value, depth + 1); break;
                case Compare { Cond: Cond.Eq or Cond.Ne, Left: var tested, Right: Const { Value: 0 } } test
                    when Boolean(tested, depth + 1):
                    Visit(tested, test.Cond == Cond.Ne ? value : !value, depth + 1); break;
                case Compare { Cond: Cond.Eq or Cond.Ne, Left: Const { Value: 0 }, Right: var tested } test
                    when Boolean(tested, depth + 1):
                    Visit(tested, test.Cond == Cond.Ne ? value : !value, depth + 1); break;
                case Not not: Visit(not.Operand, !value, depth + 1); break;
                case Logical logical when logical.IsAnd == value:
                    Visit(logical.Left, value, depth + 1); Visit(logical.Right, value, depth + 1); break;
                case Compare compare when compare.Cond == (value ? Cond.Eq : Cond.Ne):
                    if (compare is { Right: Const right }) Equality(compare.Left, right);
                    else if (compare is { Left: Const left }) Equality(compare.Right, left);
                    break;
            }
        }
        Visit(condition, truth);
        return result;
    }
}
