using Cpp2CS.Facts;
using Cpp2CS.Recovery;
using static Cpp2CS.Pipeline.RecoveryReport;

namespace Cpp2CS.Pipeline;

internal static class SelectionStage
{
    internal sealed record Selection(RecoveryTarget[] Targets, MethodDef[] Methods,
        Dictionary<MethodDef, ulong[]> NativeEntries, MethodDef[] Unselected);

    internal static Selection Select(RecoveryRequest request, ProgramFacts facts, Action<string> Log)
    {
        var namespaces = request.Namespaces;
        var assembliesFilter = request.Assemblies;
        var excludeAssemblies = request.ExcludeAssemblies;
        var types = request.TypeNames();
        var all = request.All || assembliesFilter is not null;
        var list = request.Methods;
        var limit = request.Limit;

        if (assembliesFilter is not null)
        {
            var allAssemblies = facts.Model.Assemblies.Select(a => a.Name).Distinct().ToArray();
            var matchedAssemblies = allAssemblies.Where(a => assembliesFilter.Contains(a, StringComparer.OrdinalIgnoreCase)).ToArray();
            if (matchedAssemblies.Length == 0)
            {
                Log($"[Selection][警告] 未找到匹配的程序集 [{string.Join(", ", assembliesFilter)}]！可用程序集列表: {string.Join(", ", allAssemblies.Take(25))}{(allAssemblies.Length > 25 ? $" 等共 {allAssemblies.Length} 个" : "")}");
            }
            else
            {
                Log($"[Selection] 成功匹配程序集: {string.Join(", ", matchedAssemblies)}");
            }
        }

        if (excludeAssemblies is not null)
        {
            Log($"[Selection] 排除程序集: {string.Join(", ", excludeAssemblies)}");
        }

        RecoveryTarget[] selected;
        if (list is null)
        {
            bool Excluded(MethodDef m) => excludeAssemblies is not null
                && excludeAssemblies.Contains(m.Owner.Assembly, StringComparer.OrdinalIgnoreCase);

            bool Included(MethodDef m) => (all || (types is not null ? types.Contains(Top(m.Owner).FullName) : InNamespaces(m.Owner, namespaces)))
                && (assembliesFilter is null || assembliesFilter.Contains(m.Owner.Assembly, StringComparer.OrdinalIgnoreCase))
                && !Excluded(m);
            var entries = new MethodEntries(facts, new ManagedTypes(facts.Model, facts.Layouts));
            selected = entries.Definitions.Where(e => Included(e.Instance.Method) && facts.Code.RegionOf(e.Address) == CodeRegion.Managed)
                .Select(e => new RecoveryTarget(e.Instance, e.Address)).Take(limit).ToArray();
            var scopeDesc = all
                ? (assembliesFilter is null ? "全程序方法定义" : string.Join(", ", assembliesFilter))
                : (types is not null ? request.Types : string.Join(", ", namespaces));
            if (excludeAssemblies is not null) scopeDesc += $"（排除: {string.Join(", ", excludeAssemblies)}）";
            Log($"[Selection] 筛选命中 {selected.Length} 个方法（{scopeDesc}）");
        }
        else
        {
            selected = File.ReadLines(list).Where(l => l.Length > 0 && !l.StartsWith('#')).Select(l => l.Split('\t'))
                .Select(f => RecoveryTarget.Find(facts, Convert.ToUInt64(f[0], 16), f[1])).ToArray();
            Log($"[Selection] 列表模式命中 {selected.Length} 个方法（{list}）");
        }
        if (selected.GroupBy(t => t.Instance.Method).Any(g => g.Count() > 1))
            throw new InvalidDataException("同一方法定义只能选择一个原生入口，不能以多个实例体覆盖同一 CIL 方法");
        var methods = selected.Select(t => t.Instance.Method).ToArray();
        var selectedDefinitions = methods.ToHashSet();
        var selectedTypes = methods.Select(m => Top(m.Owner)).ToHashSet();
        Log($"[阶段 2/6: Selection] 涉及 {selectedTypes.Count} 个独立类型: {string.Join(", ", selectedTypes.Take(10).Select(t => t.FullName))}{(selectedTypes.Count > 10 ? $" 等共 {selectedTypes.Count} 个" : "")}");
        var nativeEntries = facts.Model.Code.SelectMany(p => p.Value.Select(o => (Method: o.Method.Method, Entry: p.Key)))
            .Where(p => selectedTypes.Contains(Top(p.Method.Owner))).GroupBy(p => p.Method)
            .ToDictionary(g => g.Key, g => g.Select(p => p.Entry).Distinct().Order().ToArray());
        var unselected = facts.Model.Methods.Where(m => selectedTypes.Contains(Top(m.Owner)) && !selectedDefinitions.Contains(m))
            .OrderBy(m => m.Index).ToArray();

        return new(selected, methods, nativeEntries, unselected);
    }
}
