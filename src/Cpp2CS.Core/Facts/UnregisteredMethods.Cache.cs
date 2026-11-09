namespace Cpp2CS.Facts;

public sealed partial class UnregisteredMethods
{
    internal sealed record CachedWitness(ulong Caller, ulong Site, int Method);
    internal sealed record CachedMethod(ulong Address, int Definition, string Abi, CachedWitness[] Witnesses, ulong[] Matches, int[] Adjustors);
    internal sealed record Snapshot(CachedMethod[] Methods, OwnerDecision[] Decisions, FactCheck[] Checks);

    internal Snapshot Capture(BaseFacts facts)
    {
        var specs = new Dictionary<MethodRef, int>();
        for (var i = 0; i < facts.Model.MethodSpecs.Count; i++) specs.TryAdd(facts.Model.MethodSpecs[i], i);
        var entries = new Dictionary<CodeEntry, int>(ReferenceEqualityComparer.Instance);
        for (var i = 0; i < facts.Registrations.Entries.Count; i++) entries.Add(facts.Registrations.Entries[i], i);

        var specsByMethod = facts.Model.MethodSpecs.Select((s, i) => (s, i))
            .GroupBy(p => p.s.Method)
            .ToDictionary(g => g.Key, g => g.Select(p => p.i).ToArray());

        int Token(MethodRef method)
        {
            if (method.TypeArguments.Count == 0 && method.MethodArguments.Count == 0)
                return ~method.Method.Index;
            if (specs.TryGetValue(method, out var idx))
                return idx;
            // 若为分析期间动态实例化的泛型方法（不在元数据 MethodSpecs 表），映射至同定义的已知 Spec 或方法定义 Token
            if (specsByMethod.TryGetValue(method.Method, out var candidateIndices) && candidateIndices.Length > 0)
                return candidateIndices[0];
            return ~method.Method.Index;
        }

        return new(All.Select(m => new CachedMethod(m.Address, m.Definition.Index, Shape(m.Abi),
            m.Witnesses.Select(w => new CachedWitness(w.Caller, w.Site, Token(w.Instance))).ToArray(),
            m.ShapeMatches.ToArray(), m.Adjustors.Select(e => entries[e]).ToArray())).ToArray(),
            decisions.ToArray(), facts.Checks.All.Where(c => c.Name.StartsWith("unregistered.", StringComparison.Ordinal)).ToArray());
    }

    internal static UnregisteredMethods Restore(Snapshot snapshot, BaseFacts facts)
    {
        var result = new UnregisteredMethods();
        var abi = new ManagedAbi(facts.Layouts);
        MethodRef Method(int token) => token < 0 ? new(facts.Model.Methods[~token], [], []) : facts.Model.MethodSpecs[token];
        foreach (var item in snapshot.Methods)
        {
            var definition = facts.Model.Methods[item.Definition];
            var witnesses = item.Witnesses.Select(w => new MethodWitness(w.Caller, w.Site, Method(w.Method))).ToArray();
            // Build 使用第一个完整见证的 ABI；重新分类使类型引用归属本次模型。没有见证的是非泛型方法的副本。
            var signature = (witnesses.Length > 0 ? ClassifyInstance(witnesses[0].Instance, abi) : null)
                ?? ClassifyInstance(new(definition, [], []), abi);

            if (signature is null || Shape(signature) != item.Abi)
            {
                var candidate = facts.Model.MethodSpecs.FirstOrDefault(s => s.Method == definition && ClassifyInstance(s, abi) is { } sig && Shape(sig) == item.Abi);
                if (candidate is not null) signature = ClassifyInstance(candidate, abi);
            }

            if (signature is null || Shape(signature) != item.Abi || witnesses.Any(w => w.Instance.Method != definition))
            {
                // 跳过无法在当前模型还原签名的个别条目，避免阻断全流程
                continue;
            }

            result.accepted.Add(item.Address, new(item.Address, definition, signature, witnesses, item.Matches,
                item.Adjustors.Select(i => facts.Registrations.Entries[i]).ToArray()));
        }
        result.decisions.AddRange(snapshot.Decisions);
        foreach (var check in snapshot.Checks) facts.Checks.Add(check);
        return result;
    }
}
