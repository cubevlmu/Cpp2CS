using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace Cpp2CS.Image;

/// <summary>无析构、无复制回调的单指针 IL2CPP 异常包装，与已核对的 MSVC throw 入口绑定。</summary>
public static class WindowsExceptionObjectProof
{
    private static readonly ConditionalWeakTable<ImageDocument, ConcurrentDictionary<ulong, byte>> Wrappers = new();
    public static bool IsKnownWrapperDescriptor(ImageDocument image, ulong descriptor) =>
        Wrappers.TryGetValue(image, out var known) && known.ContainsKey(descriptor);
    public static bool IsRethrow(ImageDocument image, ulong entry)
    {
        var bytes = image.ReadUpTo(entry, 35);
        if (bytes.Length != 35 || !bytes[..13].SequenceEqual(System.Convert.FromHexString("4883EC28488BD1488D4C2438E8"))
            || !bytes.Slice(17, 3).SequenceEqual(System.Convert.FromHexString("488D15"))
            || !bytes.Slice(24, 6).SequenceEqual(System.Convert.FromHexString("488D4C2438E8")) || bytes[34] != 0xcc) return false;
        var construct = Relative(entry + 13, bytes[13..17]);
        if (!image.ReadUpTo(construct, 7).SequenceEqual(System.Convert.FromHexString("488911488BC1C3"))) return false;
        var type = Relative(entry + 20, bytes[20..24]);
        var throwing = Relative(entry + 30, bytes[30..34]);
        if (!WindowsFh4RuntimeProof.MatchesThrow(image, throwing) || !IsWrapperType(image, type)) return false;
        var array = image.PreferredBase + image.ReadU32(type + 12);
        var catchable = image.PreferredBase + image.ReadU32(array + 4);
        var descriptor = image.PreferredBase + image.ReadU32(catchable + 4);
        Wrappers.GetOrCreateValue(image).TryAdd(descriptor, 0);
        return true;
    }

    public static ulong? ThrowTarget(ImageDocument image, ulong rethrow) => IsRethrow(image, rethrow)
        ? Relative(rethrow + 30, image.ReadUpTo(rethrow + 30, 4)) : null;

    public static bool IsWrapperType(ImageDocument image, ulong type)
    {
        if (!WindowsEhReader.Readable(image, type, 16)) return false;
        var info = image.ReadUpTo(type, 16);
        if (info[..12].IndexOfAnyExcept((byte)0) >= 0) return false;
        var array = image.PreferredBase + BinaryPrimitives.ReadUInt32LittleEndian(info[12..]);
        if (!WindowsEhReader.Readable(image, array, 8) || image.ReadU32(array) != 1) return false;
        var catchable = image.PreferredBase + image.ReadU32(array + 4);
        if (!WindowsEhReader.Readable(image, catchable, 28)) return false;
        var data = image.ReadUpTo(catchable, 28);
        var descriptor = image.PreferredBase + BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
        var proven = (BinaryPrimitives.ReadUInt32LittleEndian(data) & ~1U) == 0
            && BinaryPrimitives.ReadUInt32LittleEndian(data[8..]) == 0
            && BinaryPrimitives.ReadInt32LittleEndian(data[12..]) == -1
            && BinaryPrimitives.ReadUInt32LittleEndian(data[16..]) == 0
            && BinaryPrimitives.ReadUInt32LittleEndian(data[20..]) == 8
            && BinaryPrimitives.ReadUInt32LittleEndian(data[24..]) == 0
            && WindowsEhReader.TypeDescriptorName(image, descriptor)
                == ".?AUIl2CppExceptionWrapper@@";
        return proven;
    }

    private static ulong Relative(ulong field, ReadOnlySpan<byte> displacement) =>
        unchecked(field + 4 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(displacement));
}
