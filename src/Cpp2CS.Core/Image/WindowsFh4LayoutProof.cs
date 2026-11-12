using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Cpp2CS.Image;

/// <summary>MSVC 已知完整处理器及无调用解码器的原生格式见证；不证明外部处理逻辑或托管异常投影。</summary>
internal static class WindowsFh4LayoutProof
{
    // 来自 MSVC 14.44 x64 libvcruntime 的完整 COFF COMDAT；只归零已列明的重定位字段。
    private const string HandlerHash = "B068507C5A60121447C4E982F23524470E287E29F49507E64BD110D82DB461E2";
    private const string DecoderHash = "0E9C1A708E8C7E8E16369652B7E6AFBAA2185978615C73CFF1A5B3367D4BE54D";
    private const string WrapperHash = "1DA1F663044FFD41D13FC0C0F3F3AF030395D7FDCCF56530E71263C70BD8E33F";

    internal static bool Matches(ImageDocument image, ulong handler)
    {
        if (!Fingerprint(image, handler, 200, [65, 78, 87, 123, 174], HandlerHash)) return false;
        var ptd = Relative(image, handler + 65);
        if (!image.IsExecutable(ptd) || Relative(image, handler + 78) != ptd || Relative(image, handler + 87) != ptd) return false;
        var decoder = Relative(image, handler + 123);
        if (!Fingerprint(image, decoder, 300, [33, 63, 70, 160, 167, 249, 256], DecoderHash)
            || Relative(image, decoder + 33) != image.PreferredBase) return false;
        var wrapper = Relative(image, handler + 174);
        if (!Fingerprint(image, wrapper, 75, [49, 56], WrapperHash)
            || !image.IsExecutable(Relative(image, wrapper + 49)) || !image.IsExecutable(Relative(image, wrapper + 56))) return false;
        var lengths = image.PreferredBase + image.ReadU32(decoder + 63);
        var shifts = image.PreferredBase + image.ReadU32(decoder + 70);
        // ADDR32NB 表引用必须绑定同一只读常量；不忽略重定位后实际使用的数据。
        return image.PreferredBase + image.ReadU32(decoder + 160) == lengths
            && image.PreferredBase + image.ReadU32(decoder + 249) == lengths
            && image.PreferredBase + image.ReadU32(decoder + 167) == shifts
            && image.PreferredBase + image.ReadU32(decoder + 256) == shifts
            && WindowsEhReader.Readable(image, lengths, 16) && WindowsEhReader.Readable(image, shifts, 16)
            && image.ReadUpTo(lengths, 16).SequenceEqual(System.Convert.FromHexString("FFFEFFFDFFFEFFFCFFFEFFFDFFFEFFFB"))
            && image.ReadUpTo(shifts, 16).SequenceEqual(System.Convert.FromHexString("1912190B191219041912190B19121900"));
    }

    private static bool Fingerprint(ImageDocument image, ulong entry, int length, int[] relocations, string expected)
    {
        if (image.SectionAt(entry) is not { Executable: true } section || entry < section.Address
            || (ulong)length > section.Size - (entry - section.Address)) return false;
        var bytes = image.ReadUpTo(entry, length).ToArray();
        if (bytes.Length != length) return false;
        foreach (var offset in relocations) bytes.AsSpan(offset, 4).Clear();
        return System.Convert.ToHexString(SHA256.HashData(bytes)) == expected;
    }

    private static ulong Relative(ImageDocument image, ulong field) =>
        unchecked(field + 4 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(image.ReadUpTo(field, 4)));
}
