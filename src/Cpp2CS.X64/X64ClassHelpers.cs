using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.X64;

/// <summary>以布局访问器、初始化标志和异常导出锚定返回类指针的初始化包装。</summary>
internal static class X64ClassHelpers
{
    internal static IEnumerable<RuntimeHelper> Identify(CodeMap map, CodeScan scan, PcodeMachine machine)
    {
        var image = map.Image;
        var size = Export("il2cpp_class_instance_size");
        var monoSize = Export("mono_class_instance_size");
        var initialized = Export("il2cpp_class_is_inited");
        var handle = Export("il2cpp_gchandle_get_target");
        var raiseExport = Export("il2cpp_raise_exception");
        if (size == 0 || handle == 0
            || !Match(monoSize, "40 53 48 83 ec 20 48 8b d9 e8 ?? ?? ?? ?? 48 8b cb 48 83 c4 20 5b e9 ?? ?? ?? ??")
            || Terminal(Relative(monoSize + 23)) != size
            || !Match(initialized, "0f b6 81 ?? ?? ?? ?? d0 e8 24 01 c3")
            || !Match(raiseExport, "48 83 ec 28 33 d2 e8 ?? ?? ?? ?? cc")) yield break;
        var init = Terminal(Relative(monoSize + 10));
        var raise = Terminal(Relative(raiseExport + 7));
        // Class::Init 的快速路径检查 initialized 位；偏移由导出读取器交叉核对。
        if (!Match(init, "48 89 5c 24 10 48 89 6c 24 18 48 89 74 24 20 57 48 83 ec 20 48 8b f9 f6 81 ?? ?? ?? ?? 02 0f 85 ?? ?? ?? ??")
            || !image.ReadUpTo(init + 25, 4).SequenceEqual(image.ReadUpTo(initialized + 3, 4))
            || raise == 0 || !new NoReturnOracle(machine, map).IsNoReturn(raise)) yield break;
        foreach (var group in scan.All.Where(r => r.Kind is RefKind.Call or RefKind.TailCall).GroupBy(r => r.Target))
        {
            var entry = group.Key;
            if (map.RegionOf(entry) == CodeRegion.Managed || map.At(entry)?.HasUnmodeledExceptions == true) continue;
            if (!Match(entry, "40 53 48 83 ec 20 48 8b d9 e8 ?? ?? ?? ?? 48 83 bb ?? ?? ?? ?? 00 75 09 48 8b c3 48 83 c4 20 5b c3 48 8b 8b ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b c8 33 d2 e8 ?? ?? ?? ?? cc")) continue;
            if (Terminal(Relative(entry + 10)) != init || Terminal(Relative(entry + 41)) != handle
                || Terminal(Relative(entry + 51)) != raise
                || !image.ReadUpTo(entry + 17, 4).SequenceEqual(image.ReadUpTo(entry + 36, 4))) continue;
            yield return new(entry, HelperKind.InitializedTypeInfo, null,
                "布局访问器的初始化目标及 initialized 位与导出一致；成功返回输入类，失败经 GCHandle 导出取异常并进入已证明不返回的抛出目标", group.Count());
        }

        ulong Export(string name) => image.Exports.TryGetValue(name, out var entry) ? Terminal(entry) : 0;
        ulong Terminal(ulong address)
        {
            var seen = new HashSet<ulong>();
            for (var i = 0; i < 8 && image.IsExecutable(address) && map.RegionOf(address) != CodeRegion.Managed && seen.Add(address); i++)
            {
                if (!Match(address, "e9 ?? ?? ?? ??")) return address;
                address = Relative(address + 1);
            }
            return 0;
        }
        ulong Relative(ulong address) => unchecked(address + 4 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(image.ReadUpTo(address, 4)));
        bool Match(ulong address, string pattern)
        {
            if (!image.IsExecutable(address)) return false;
            var parts = pattern.Split(' ');
            var bytes = image.ReadUpTo(address, parts.Length);
            if (bytes.Length != parts.Length) return false;
            for (var i = 0; i < parts.Length; i++)
                if (parts[i] != "??" && bytes[i] != System.Convert.ToByte(parts[i], 16)) return false;
            return true;
        }
    }
}
