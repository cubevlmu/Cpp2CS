using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Image;

namespace Cpp2CS.X64;

/// <summary>从虚方法查找导出中的接口偏移扫描与参数转发核实接口慢路径。</summary>
internal static class X64InterfaceHelpers
{
    internal static RuntimeHelper? Identify(CodeMap map, CodeScan scan, RuntimeOffsets offsets)
    {
        if (offsets.ClassVtable != 0x138 || offsets.MethodClass != 0x20
            || !map.Image.Exports.TryGetValue("il2cpp_object_get_virtual_method", out var entry)) return null;
        var image = map.Image;
        var seen = new HashSet<ulong>();
        for (var depth = 0; depth < 8 && seen.Add(entry); depth++)
        {
            var jump = image.ReadUpTo(entry, 5);
            if (jump is not [0xe9, ..]) break;
            entry = Relative(entry + 1);
        }
        if (map.At(entry) is not { HasUnmodeledExceptions: false } range || range.Start != entry || range.Size < 0xe3) return null;
        // RCX 保存到 R11；RDX 为 MethodInfo，取其声明类和槽号。扫描 (接口类, offset) 对，失败后转发对象、接口类和 ushort 槽。
        const string pattern = "40 53 48 83 ec 20 f6 42 4c 20 48 8b da 4c 8b d9 0f 85 ?? ?? ?? ?? f6 42 4c 40 0f 84 ?? ?? ?? ?? 48 8b 52 20 48 89 7c 24 30 f6 82 18 01 00 00 20 75 20 80 7a 2a 13 74 1a 80 7a 2a 1e 74 14 0f b7 4b 50 49 8b 03 48 83 c1 14 48 03 c9 48 8b 3c c8 eb 43 4c 8b 11 33 c9 0f b7 7b 50 45 0f b7 82 2e 01 00 00 66 41 3b c8 73 1c 4d 8b 8a b0 00 00 00 0f b7 c1 48 03 c0 49 39 14 c1 74 3a 66 ff c1 66 41 3b c8 72 eb 44 0f b7 c7 49 8b cb e8 ?? ?? ?? ?? 48 8b 78 08";
        var parts = pattern.Split(' ');
        var bytes = image.ReadUpTo(entry, parts.Length);
        if (bytes.Length != parts.Length) return null;
        for (var i = 0; i < parts.Length; i++)
            if (parts[i] != "??" && bytes[i] != System.Convert.ToByte(parts[i], 16)) return null;
        if (Relative(entry + 18) != entry + 0xe2 || Relative(entry + 28) != entry + 0xe2) return null;
        var target = Relative(entry + 0x8d);
        if (!image.IsExecutable(target) || map.RegionOf(target) == CodeRegion.Managed
            || map.At(target) is not { HasUnmodeledExceptions: false } function || function.Start != target) return null;
        return new(target, HelperKind.InterfaceLookup, null,
            "虚方法查找导出：接口计数、16 字节偏移表扫描、MethodInfo 声明类与槽、失败时对象/接口/槽转发以及返回的 VirtualInvokeData.method 读取均匹配受限 MSVC 形态",
            scan.All.Count(r => r.Target == target && r.Kind is RefKind.Call or RefKind.TailCall));

        ulong Relative(ulong at) => unchecked(at + 4 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(image.ReadUpTo(at, 4)));
    }
}
