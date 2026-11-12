using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace Cpp2CS.Facts.Derived;

/// <summary>MSVC 零参数接口调用桩：核对完整扫描、已知慢路径及两臂的动态尾调用。</summary>
internal sealed class NativeInterfaceInvokeProof(ProgramFacts facts)
{
    private readonly ConcurrentDictionary<ulong, Lazy<bool>> bodies = new();

    internal bool Matches(ulong entry) => bodies.GetOrAdd(entry, address => new(() => Prove(address))).Value;

    private bool Prove(ulong entry)
    {
        if (facts.Model.Image.Architecture != Architecture.X64 || facts.Base.RuntimeOffsets is not { ClassVtable: 0x138, MethodClass: 0x20 }
            || facts.Registrations.At(entry).Length != 0
            || facts.Code.At(entry) is not { Start: var start, HasUnmodeledExceptions: false, Size: >= 0x8e and <= 0xa0 } range || start != entry) return false;
        const string pattern = "40 53 48 83 ec 20 49 8b d8 33 c0 44 0f b7 c1 4c 8b 1b 45 0f b7 8b 2e 01 00 00 66 41 3b c1 73 25 4d 8b 93 b0 00 00 00 66 0f 1f 84 00 00 00 00 00 0f b7 c8 48 03 c9 49 39 14 ca 74 23 66 ff c0 66 41 3b c1 72 eb 48 8b cb e8 ?? ?? ?? ?? 48 8b cb 4c 8b 00 48 8b 50 08 48 83 c4 20 5b 49 ff e0 0f b7 d0 48 8b cb 48 03 d2 41 8b 44 d2 08 41 03 c0 48 98 48 c1 e0 04 48 05 38 01 00 00 49 03 c3 4c 8b 00 48 8b 50 08 48 83 c4 20 5b 49 ff e0";
        var parts = pattern.Split(' ');
        var bytes = facts.Model.Image.ReadUpTo(entry, checked((int)range.Size));
        if (parts.Length != 0x8e || bytes.Length != (int)range.Size) return false;
        for (var i = 0; i < parts.Length; i++)
            if (parts[i] != "??" && bytes[i] != System.Convert.ToByte(parts[i], 16)) return false;
        foreach (var padding in bytes[parts.Length..])
            if (padding != 0xcc) return false;
        var slow = unchecked(entry + 0x4d + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(bytes[0x49..0x4d]));
        // 慢路径身份由虚方法查找导出的独立证据确定，不能凭本桩的偏移自证布局。
        return facts.Helpers.At(slow)?.Kind == HelperKind.InterfaceLookup;
    }
}
