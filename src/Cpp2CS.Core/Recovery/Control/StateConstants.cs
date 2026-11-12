using Cpp2CS.Ir;

namespace Cpp2CS.Recovery.Control;

/// <summary>按实际分派边传播状态局部的常量；合流冲突和局部重写会撤销已知值。</summary>
internal static class StateConstants
{
    internal static void Rewrite(Dictionary<ulong, List<ManagedStatement>> code, ulong entry, LocalValue state)
    {
        if (state.Width != 32 || ManagedTypes.PrimitiveName(state.Type) != "Int32"
            || code.Values.SelectMany(s => s).SelectMany(s => ManagedValues.Of(s).Concat(ManagedValues.CopiedValues(s))).SelectMany(ManagedValues.Walk)
                .OfType<AddressValue>().Any(a => ManagedValues.Walk(a.Target).OfType<LocalValue>().Any(l => l.Variable == state.Variable))) return;
        var incoming = new Dictionary<ulong, int?> { [entry] = null };
        var pending = new Queue<ulong>();
        pending.Enqueue(entry);
        bool IsState(ManagedValue value) => value is LocalValue { Width: 32 } local && local.Variable == state.Variable
            && ManagedTypes.PrimitiveName(local.Type) is "Int32" or "UInt32";
        int? Evaluate(ManagedValue value, int? known)
        {
            if (ManagedValues.Walk(value).Any(v => v is ConversionValue c && (c.Width != 32 || c.Operand.Width != 32)
                || v is BinaryValue { Width: not 32 })) return null;
            return ConstantConditions.Evaluate(value, v => IsState(v) ? known : null) is { } result ? unchecked((int)result) : null;
        }
        int? Written(ManagedStatement statement, int? known) => statement switch
        {
            ManagedAssignment assignment when assignment.Target.Variable == state.Variable => Evaluate(assignment.Value, known),
            ManagedCall { Result: { } result } when result.Variable == state.Variable => null,
            ManagedAwait { Result: { } result } when result.Variable == state.Variable => null,
            _ => known,
        };
        void Follow(ManagedEdge edge, int? known)
        {
            var copies = edge.Copies.Where(c => c.Target.Variable == state.Variable).ToArray();
            if (copies.Length != 0) known = copies is [var copy] ? Evaluate(copy.Value, known) : null;
            if (!incoming.TryGetValue(edge.Target, out var previous))
            {
                incoming.Add(edge.Target, known);
                pending.Enqueue(edge.Target);
            }
            else if (previous is not null && previous != known)
            {
                incoming[edge.Target] = null;
                pending.Enqueue(edge.Target);
            }
        }
        while (pending.TryDequeue(out var at))
        {
            var known = incoming[at];
            foreach (var statement in code[at])
            {
                if (statement is ManagedBranch branch)
                {
                    if (Evaluate(branch.Condition, known) is { } taken)
                        Follow(taken != 0 ? branch.Taken : branch.Fallthrough, known);
                    else if (StateComparisons.Normalize(branch.Condition, state) is ComparisonValue
                        { Condition: Cond.Eq or Cond.Ne, Left: LocalValue local, Right: ConstantValue { Width: 32 } constant } test
                        && IsState(local))
                    {
                        Follow(test.Condition == Cond.Eq ? branch.Taken : branch.Fallthrough, unchecked((int)constant.Bits));
                        Follow(test.Condition == Cond.Eq ? branch.Fallthrough : branch.Taken, known);
                    }
                    else
                    {
                        Follow(branch.Taken, known);
                        Follow(branch.Fallthrough, known);
                    }
                }
                else if (statement is ManagedSwitch choice && Evaluate(choice.Index, known) is { } selected
                    && selected >= 0 && selected < choice.Cases.Count) Follow(choice.Cases[selected], known);
                else foreach (var edge in ManagedValues.Edges(statement)) Follow(edge, known);
                known = Written(statement, known);
            }
        }
        foreach (var (at, initial) in incoming)
        {
            var known = initial;
            code[at] = code[at].Select(statement =>
            {
                ManagedValue Replace(ManagedValue value) => known is { } constant && IsState(value)
                    ? new ConstantValue(unchecked((uint)constant), value.Type, value.Width) : ManagedValues.Map(value, Replace);
                var rewritten = known is not null ? ManagedValues.Map(statement, Replace) : statement;
                // 保留入口分派的比较，反编译器据此识别各个恢复点。
                if (statement is ManagedBranch branch) rewritten = ((ManagedBranch)rewritten) with { Condition = branch.Condition };
                known = Written(statement, known);
                return rewritten;
            }).ToList();
        }
    }
}
