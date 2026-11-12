namespace Cpp2CS.Recovery.Inlining;

internal sealed partial class TemplateRecovery
{
    /// <summary>公共包装被内联后留下的越权调用：以包装方法的完整恢复体证明区域，再换回合法调用。</summary>
    private ManagedBody InlineCalls(ManagedBody body)
    {
        var failed = new HashSet<ManagedStatement>(ReferenceEqualityComparer.Instance);
        while (true)
        {
            var anchors = InaccessibleCalls(body).Where(p => !failed.Contains(p.Call)).Take(1).ToArray();
            if (anchors is not [var anchor]) return body;
            if (InlineCall(body, anchor) is not { } next) { failed.Add(anchor.Call); continue; }
            body = next;
            failed.Clear();
        }
    }

    private IEnumerable<(ulong Block, int Index, ManagedCall Call)> InaccessibleCalls(ManagedBody body)
    {
        foreach (var block in body.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
                if (block.Statements[i] is ManagedCall call && call.Invocation is var invocation
                    && invocation.Method.Method.Name is not (".ctor" or ".cctor")
                    && !ManagedAccess.Method(types, caller.Method.Owner, invocation.Method, invocation.Receiver?.Type))
                    yield return (block.Address, i, call);
    }

    private readonly Dictionary<(MethodRef Method, TypeRef? Receiver), IReadOnlyList<(MethodRef Method, ManagedBody Body)>> callCandidates = [];

    private IReadOnlyList<(MethodRef Method, ManagedBody Body)> CallCandidates(ManagedInvocation anchor)
    {
        var key = (anchor.Method, anchor.Receiver?.Type);
        if (callCandidates.TryGetValue(key, out var known)) return known;
        callCandidates[key] = [];
        var found = new List<(MethodRef Method, ManagedBody Body)>();
        if (anchor.Method.DeclaringType is not DefinitionRef owner) return [];
        var initialized = anchor.Method.Method.IsStatic ? owner : null;
        foreach (var definition in owner.Definition.Methods)
        {
            if (definition.Name is ".ctor" or ".cctor" || definition.GenericParameters.Count != 0) continue;
            var method = new MethodRef(definition, owner.Arguments, []);
            if (method.Equals(anchor.Method) || fields.CallFailure(method, anchor.Receiver?.Type, initialized) is not null) continue;
            if (summaries(method) is not { Body: { } template } || template.Regions.Count != 0 || !Acyclic(template)) continue;
            if (template.Blocks.SelectMany(b => b.Statements).OfType<ManagedCall>().Any(c => c.Invocation.Method.Equals(anchor.Method)))
                found.Add((method, template));
        }
        return callCandidates[key] = found.OrderByDescending(p => p.Body.Blocks.Sum(b => b.Statements.Count)).ToArray();
    }

    private ManagedBody? InlineCall(ManagedBody body, (ulong Block, int Index, ManagedCall Call) anchor)
    {
        var before = InaccessibleCalls(body).Count();
        var blocks = body.Blocks.ToDictionary(b => b.Address);
        var starts = Enumerable.Range(0, anchor.Index + 1).Select(i => (Block: anchor.Block, Index: i)).ToList();
        var visited = new HashSet<ulong> { anchor.Block };
        var current = anchor.Block;
        while (visited.Count < 16)
        {
            if (Predecessors(blocks, current) is not [var predecessor] || !visited.Add(predecessor.Address)) break;
            current = predecessor.Address;
            starts.AddRange(Enumerable.Range(0, predecessor.Statements.Count).Select(i => (current, i)));
            if (predecessor.Statements.Any(s => s is not ManagedJump { Edge.Copies.Count: 0 })) break;
        }
        var (best, covered) = ((ManagedBody?)null, -1);
        foreach (var (method, template) in CallCandidates(anchor.Call.Invocation))
            foreach (var (block, start) in starts)
            {
                if (Match(body, blocks, block, start, template, method.TypeArguments, out _) is not { } match
                    || !match.Covered.Contains((anchor.Block, anchor.Index))
                    || PlanReplacement(body, blocks, block, start, method, match, out _) is not { } replacement) continue;
                var invocation = replacement.Statements.Skip(start).OfType<ManagedCall>().FirstOrDefault(c => c.Inlined && c.Invocation.Method.Equals(method))?.Invocation;
                var initialized = anchor.Call.Invocation.Method.Method.IsStatic ? anchor.Call.Invocation.Method.DeclaringType : null;
                if (invocation is null || fields.CallFailure(method, invocation.Receiver?.Type, initialized) is not null) continue;
                // C# 实例调用增加接收者判空，须在区域入口已有非空依据。
                if (invocation.Receiver is { } receiver && ManagedTypes.IsReferenceType(receiver.Type)
                    && receiver is not ArgumentValue { Index: -1 })
                {
                    var entry = new Walker { Blocks = blocks, Caller = true, Block = block, Index = start };
                    SeedPath(entry);
                    if (!NonNull(entry, receiver)) continue;
                }
                var next = DeadPendingReads(replacement.Apply(body));
                // 严格递减保证终止；失败的原调用交给既有权限检查报告。
                if (InaccessibleCalls(next).Count() >= before) continue;
                if (match.Covered.Count > covered) (best, covered) = (next, match.Covered.Count);
                break;
            }
        return best;
    }
}
