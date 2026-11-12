using Cpp2CS.Ir;

namespace Cpp2CS.Recovery.Inlining;

internal sealed partial class TemplateRecovery
{
    /// <summary>只读取按值形参并写入 this 的无环构造体。每条分支保留约束，不忽略调用、检查或未用读取。</summary>
    private IReadOnlyList<ValueConstructorEvidence> ValueConstructorPaths(MethodRef method, DefinitionRef structure)
    {
        if (summaries(method) is not { Body: { Regions.Count: 0, Blocks.Count: > 0 } body }) return [];
        var initial = new Walker { Blocks = body.Blocks.ToDictionary(b => b.Address), Caller = false, Block = body.Blocks[0].Address };
        initial.Visited.Add(initial.Block);
        var paths = new List<ValueConstructorEvidence>();
        var pending = new Stack<(Walker State, List<(IReadOnlyList<FieldRef> Path, ManagedValue Value)> Writes,
            List<(ManagedValue Condition, bool Truth)> Conditions)>();
        pending.Push((initial, [], []));
        var steps = 0;
        while (pending.TryPop(out var path))
        {
            var (walker, writes, conditions) = path;
            var finished = false;
            while (!finished)
            {
                if (++steps > 256 || paths.Count + pending.Count > 16) return [];
                ManagedValue? TermOf(ManagedValue value) => Term(walker, value) is { } term ? ConstructorValue(term) : null;
                bool Edge(ManagedEdge edge)
                {
                    if (edge.Copies.Any(c => TermOf(c.Value) is null)) return false;
                    return Follow(walker, edge);
                }
                switch (walker.Current)
                {
                    case ManagedAssignment assignment:
                        if (TermOf(assignment.Value) is not { } value) return [];
                        walker.Env[assignment.Target.Variable] = value;
                        walker.Index++;
                        break;
                    case ManagedJump jump:
                        if (!Edge(jump.Edge)) return [];
                        break;
                    case ManagedBranch branch:
                        if (TermOf(branch.Condition) is not { } test) return [];
                        var other = walker.Clone();
                        if (branch.Fallthrough.Copies.Any(c => Term(other, c.Value) is not { } v || ConstructorValue(v) is null)
                            || !Follow(other, branch.Fallthrough)) return [];
                        pending.Push((other, [.. writes], [.. conditions, (test, false)]));
                        conditions.Add((test, true));
                        if (!Edge(branch.Taken)) return [];
                        break;
                    case ManagedStore store:
                        if (ThisPath(walker, store.Target) is not { Count: > 0 } target || TermOf(store.Value) is not { } stored
                            || writes.Any(w => w.Path.Count < target.Count && FieldPrefix(w.Path, target))) return [];
                        writes.RemoveAll(w => FieldPrefix(target, w.Path));
                        writes.Add((target, stored));
                        walker.Index++;
                        break;
                    case ManagedReturn { Value: null }:
                        if (writes.Count == 0 || !types.Leaves(structure).All(l => writes.Any(w => FieldPrefix(w.Path, l.Path)))) return [];
                        paths.Add(new(method, writes) { Conditions = conditions });
                        finished = true;
                        break;
                    default:
                        return [];
                }
            }
        }
        return paths;
    }

    /// <summary>按值结构体形参的字段是稳定投影；对象、ref 与静态存储的读取不在此证明范围。</summary>
    private ManagedValue? ConstructorValue(ManagedValue value)
    {
        if (value is Observed observed) return ConstructorValue(observed.Read);
        if (value is FieldValue field)
        {
            if (ConstructorValue(field.Receiver) is not { } receiver || types.Kind(receiver.Type) != TypeKind.Struct) return null;
            var projected = field with { Receiver = receiver };
            return ArgumentProjection(projected) is not null ? projected : null;
        }
        if (value is ArgumentValue { Index: >= 0 } or ConstantValue) return value;
        if (value is not (ComposedValue or ComparisonValue or NegatedValue or BooleanValue
            or ConversionValue { Kind: ConvKind.ZeroExtend or ConvKind.Truncate })) return null;
        var valid = true;
        var mapped = ManagedValues.Map(value, child =>
        {
            if (ConstructorValue(child) is { } pure) return pure;
            valid = false;
            return child;
        });
        return valid ? mapped : null;
    }

    private static (ArgumentValue Argument, IReadOnlyList<FieldRef> Path)? ArgumentProjection(ManagedValue value)
    {
        var path = new List<FieldRef>();
        while (value is FieldValue field)
        {
            path.Insert(0, field.Field);
            value = field.Receiver;
        }
        return value is ArgumentValue { Index: >= 0, Type: DefinitionRef { Definition.IsValueType: true } } argument && path.Count > 0
            ? (argument, path) : null;
    }

    private bool BindConstructorPiece(ManagedValue written, ManagedValue desired,
        Dictionary<int, List<(IReadOnlyList<FieldRef> Path, ManagedValue Value)>> pieces)
    {
        if (!written.Type.Equals(desired.Type) || ArgumentProjection(written) is not { } projection) return false;
        if (!pieces.TryGetValue(projection.Argument.Index, out var parts)) pieces[projection.Argument.Index] = parts = [];
        var previous = parts.FirstOrDefault(p => p.Path.SequenceEqual(projection.Path));
        if (previous.Value is not null) return SameTerm(previous.Value, desired);
        if (parts.Any(p => FieldPrefix(p.Path, projection.Path) || FieldPrefix(projection.Path, p.Path))) return false;
        parts.Add((projection.Path, desired));
        return true;
    }

    private bool BindConstructorCondition(ManagedValue condition, bool truth,
        Dictionary<int, List<(IReadOnlyList<FieldRef> Path, ManagedValue Value)>> pieces)
    {
        condition = Fold(condition);
        if (condition is ConstantValue constant) return (constant.Bits != 0) == truth;
        if (condition is NegatedValue negated) return BindConstructorCondition(negated.Operand, !truth, pieces);
        if (condition is ComparisonValue { Condition: Cond.Eq or Cond.Ne, Left: var left, Right: ConstantValue { Bits: <= 1 } bit } comparison
            && types.Kind(left.Type) == TypeKind.Bool)
        {
            var equal = (comparison.Condition == Cond.Eq) == truth;
            return BindConstructorPiece(left, bit with { Bits = equal ? bit.Bits : bit.Bits ^ 1, Type = left.Type, Width = left.Width }, pieces);
        }
        return types.Kind(condition.Type) == TypeKind.Bool
            && BindConstructorPiece(condition, new ConstantValue(truth ? 1UL : 0UL, condition.Type, condition.Width), pieces);
    }

    private ManagedValue? ConstructorArgument(DefinitionRef type, IReadOnlyList<(IReadOnlyList<FieldRef> Path, ManagedValue Value)> parts)
    {
        var leaves = new List<(IReadOnlyList<FieldRef> Path, ManagedValue Value)>();
        foreach (var group in parts.GroupBy(p => p.Path[0]))
        {
            if (group.Count() == 1 && group.First().Path.Count == 1) { leaves.Add(group.First()); continue; }
            var field = group.Key;
            if (field.Field.Type.Substitute(((DefinitionRef)field.DeclaringType).Arguments, []) is not DefinitionRef nested
                || ConstructorArgument(nested, group.Select(p => ((IReadOnlyList<FieldRef>)p.Path.Skip(1).ToArray(), p.Value)).ToArray()) is not { } value) return null;
            leaves.Add(([field], value));
        }
        if (leaves.All(l => (l.Path[0].Field.Attributes & System.Reflection.FieldAttributes.InitOnly) == 0
            && fields.Accessible(l.Path[0], type))) return new ComposedValue(type, leaves);
        return ProveValueConstruction(type, leaves) is { } proof ? new NewObjectValue(proof.Constructor, proof.Arguments) { Transparent = true } : null;
    }
}
