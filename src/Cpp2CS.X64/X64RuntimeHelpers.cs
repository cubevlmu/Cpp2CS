using Cpp2CS.Facts;
using Cpp2CS.Ir;
using System.Buffers.Binary;

namespace Cpp2CS.X64;

/// <summary>导出 API 及仅含直接跳转的别名共享语义；不穿过修改参数的包装。</summary>
public static class X64RuntimeHelpers
{
    private static readonly Dictionary<string, HelperKind> Kinds = new(StringComparer.Ordinal)
    {
        ["il2cpp_object_new"] = HelperKind.ObjectNew,
        ["il2cpp_array_new_specific"] = HelperKind.NewArray,
        ["il2cpp_value_box"] = HelperKind.Box,
        ["il2cpp_runtime_class_init"] = HelperKind.ClassInit,
        ["il2cpp_raise_exception"] = HelperKind.Raise,
        ["il2cpp_class_is_assignable_from"] = HelperKind.IsAssignableFrom,
    };

    public static RuntimeHelper[] Identify(CodeMap map, CodeScan scan, PcodeMachine machine, UsageSlots? usages = null, Cpp2CS.Model.ProgramModel? model = null)
    {
        var candidates = new Dictionary<ulong, List<RuntimeHelper>>();
        var callers = scan.All.Where(r => r.Kind is RefKind.Call or RefKind.TailCall).GroupBy(r => r.Target).ToDictionary(g => g.Key, g => g.Count());
        foreach (var (name, kind) in Kinds)
        {
            if (!map.Image.Exports.TryGetValue(name, out var target)) continue;
            var origin = "PE 名称导出";
            if (kind == HelperKind.ObjectNew)
            {
                var bytes = map.Image.ReadUpTo(target, 18);
                if (bytes.Length == 18 && bytes[..5].SequenceEqual(new byte[] { 0x48, 0x83, 0xec, 0x28, 0xe8 })
                    && bytes[9..].SequenceEqual(new byte[] { 0xeb, 2, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3 }))
                {
                    // 外层可在失败时返回 null，不能把它与抛出异常的内部对象分配整体等同。
                    target = unchecked(target + 9 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(bytes[5..9]));
                    origin = "PE 对象分配导出的正常调用目标；不传播外层失败返回行为";
                }
            }
            var seen = new HashSet<ulong>();
            for (var depth = 0; depth < 8 && machine.Image.IsExecutable(target) && seen.Add(target); depth++)
            {
                if (!candidates.TryGetValue(target, out var list)) candidates[target] = list = [];
                list.Add(new(target, kind, name, depth == 0 ? origin : origin + "的直接跳转链", callers.GetValueOrDefault(target)));
                var statements = new List<Stmt>();
                if (machine.Lift(target, statements) == 0 || statements is not [Jump jump]) break;
                target = jump.Target;
            }
        }
        if (usages is not null)
            foreach (var helper in X64MetadataHelpers.Identify(map, scan, usages))
            {
                if (!candidates.TryGetValue(helper.Address, out var list)) candidates[helper.Address] = list = [];
                list.Add(helper);
            }
        foreach (var helper in X64ExceptionHelpers.Identify(map, scan, machine, model))
        {
            if (!candidates.TryGetValue(helper.Address, out var list)) candidates[helper.Address] = list = [];
            list.Add(helper);
        }
        foreach (var (target, count) in callers)
            if (map.RegionOf(target) != CodeRegion.Managed && Cpp2CS.Image.WindowsCrtFunctionProof.Symbol(map.Image, target) is { } librarySymbol)
            {
                if (!candidates.TryGetValue(target, out var list)) candidates[target] = list = [];
                list.Add(new(target, HelperKind.Import, librarySymbol, "独立 CRT 完整库入口、常量及重定位关系", count));
            }
        if (X64GcHelpers.Identify(map, machine) is { } notification)
            candidates[notification.Address] = [notification with { CallSites = callers.GetValueOrDefault(notification.Address) }];
        foreach (var helper in X64ClassHelpers.Identify(map, scan, machine))
        {
            if (!candidates.TryGetValue(helper.Address, out var list)) candidates[helper.Address] = list = [];
            list.Add(helper);
        }
        foreach (var helper in X64FieldHelpers.Identify(map, scan, machine))
        {
            if (!candidates.TryGetValue(helper.Address, out var list)) candidates[helper.Address] = list = [];
            list.Add(helper);
        }
        var offsets = X64RuntimeOffsets.Identify(machine, candidates.Values.SelectMany(v => v), model?.MetadataVersion);
        if (X64InterfaceHelpers.Identify(map, scan, offsets) is { } interfaceLookup)
        {
            if (!candidates.TryGetValue(interfaceLookup.Address, out var list)) candidates[interfaceLookup.Address] = list = [];
            list.Add(interfaceLookup);
        }
        // 调用方的独立入口也可能仅跳到已识别实现；不要求该入口出现在导出的向前链中。
        foreach (var target in callers.Keys)
        {
            var path = new List<ulong>();
            var current = target;
            for (var depth = 0; depth < 8 && machine.Image.IsExecutable(current)
                && map.RegionOf(current) != CodeRegion.Managed && !path.Contains(current); depth++)
            {
                if (candidates.TryGetValue(current, out var known))
                {
                    if (known.Select(h => (h.Kind, h.Detail)).Distinct().Count() != 1) break;
                    var semantic = known[0];
                    foreach (var alias in path)
                        candidates[alias] = [semantic with { Address = alias, CallSites = callers.GetValueOrDefault(alias),
                            Evidence = "调用入口的纯跳转链 → " + semantic.Evidence }];
                    break;
                }
                path.Add(current);
                var statements = new List<Stmt>();
                if (machine.Lift(current, statements) == 0 || statements is not [Jump jump]) break;
                current = jump.Target;
            }
        }
        return candidates.Values.Where(list => list.Select(h => (h.Kind, h.Detail)).Distinct().Count() == 1)
            .Select(list => list[0]).OrderBy(h => h.Address).ToArray();
    }
}
