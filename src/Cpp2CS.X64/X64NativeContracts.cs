using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Ir;

namespace Cpp2CS.X64;

/// <summary>从导出原型及完整参数转发包装提取机器输入；不将布局初始化当作托管类型初始化。</summary>
public static class X64NativeContracts
{
    public static IReadOnlyDictionary<ulong, NativeInputContract> Identify(CodeMap map)
    {
        var result = new Dictionary<ulong, NativeInputContract>();
        var image = map.Image;
        if (image.Architecture != Cpp2CS.Model.Architecture.X64) return result;
        var mono = Export("mono_class_instance_size"); var size = Export("il2cpp_class_instance_size"); var initialized = Export("il2cpp_class_is_inited");
        if (mono == 0 || size == 0 || initialized == 0
            || !Matches(mono, "40 53 48 83 ec 20 48 8b d9 e8 ?? ?? ?? ?? 48 8b cb 48 83 c4 20 5b e9 ?? ?? ?? ??")
            || Terminal(Relative(mono + 23)) != size
            || !Matches(size, "8b 81 ?? ?? ?? ?? c3")
            || !Matches(initialized, "0f b6 81 ?? ?? ?? ?? d0 e8 24 01 c3")) return result;
        var init = Terminal(Relative(mono + 10));
        if (init == 0 || map.RegionOf(init) == CodeRegion.Managed
            || !Matches(init, "48 89 5c 24 10 48 89 6c 24 18 48 89 74 24 20 57 48 83 ec 20 48 8b f9 f6 81 ?? ?? ?? ?? 02 0f 85 ?? ?? ?? ??")
            || !image.ReadUpTo(init + 25, 4).SequenceEqual(image.ReadUpTo(initialized + 3, 4))) return result;
        result[init] = new([Storage.Gpr(1)], "mono_class_instance_size 导出完整转发、大小访问器和初始化位共同锚定 Class::Init 输入原型；返回及内存效果未知");
        return result;

        ulong Export(string name) => image.Exports.TryGetValue(name, out var entry) ? Terminal(entry) : 0;
        ulong Terminal(ulong address)
        {
            var seen = new HashSet<ulong>();
            for (var depth = 0; depth < 8 && image.IsExecutable(address) && seen.Add(address); depth++)
            {
                if (!Matches(address, "e9 ?? ?? ?? ??")) return address;
                address = Relative(address + 1);
            }
            return 0;
        }
        ulong Relative(ulong field) => unchecked(field + 4 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(image.ReadUpTo(field, 4)));
        bool Matches(ulong address, string pattern)
        {
            if (!image.IsExecutable(address)) return false;
            var parts = pattern.Split(' '); var bytes = image.ReadUpTo(address, parts.Length);
            if (bytes.Length != parts.Length) return false;
            for (var i = 0; i < parts.Length; i++) if (parts[i] != "??" && bytes[i] != System.Convert.ToByte(parts[i], 16)) return false;
            return true;
        }
    }
}
