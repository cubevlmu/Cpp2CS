using System.Buffers.Binary;

namespace Cpp2CS.Image;

/// <summary>PE 只读数据的文件初值；排除加载器写入、可写节、代码和未映射尾部。</summary>
internal sealed class PeConstants(ImageDocument image)
{
    private readonly (ulong Address, ulong End)[] writes = Merge(image.LoaderWrites);

    private static (ulong Address, ulong End)[] Merge(IReadOnlyList<(ulong Address, ulong Size)> ranges)
    {
        var result = new List<(ulong Address, ulong End)>();
        foreach (var (address, size) in ranges.OrderBy(r => r.Address))
        {
            var end = checked(address + size);
            if (size == 0) continue;
            if (result.Count > 0 && address <= result[^1].End)
                result[^1] = (result[^1].Address, Math.Max(result[^1].End, end));
            else result.Add((address, end));
        }
        return result.ToArray();
    }

    internal ulong? Read(ulong address, int width)
    {
        if (image.Architecture != Cpp2CS.Model.Architecture.X64 || image.HasUnmodeledLoaderWrites || width is not (8 or 16 or 32 or 64)) return null;
        var size = (ulong)(width / 8);
        if (address > ulong.MaxValue - size || image.SectionAt(address) is not { Executable: false } section || (section.Flags & 1) != 0
            || size > section.Size - (address - section.Address)) return null;
        var lo = 0;
        var hi = writes.Length;
        while (lo < hi)
        {
            var mid = lo + (hi - lo) / 2;
            if (writes[mid].End <= address) lo = mid + 1;
            else hi = mid;
        }
        if (lo < writes.Length && writes[lo].Address < address + size) return null;
        var bytes = image.ReadUpTo(address, (int)size);
        if ((ulong)bytes.Length != size) return null;
        return width switch { 8 => bytes[0], 16 => BinaryPrimitives.ReadUInt16LittleEndian(bytes), 32 => BinaryPrimitives.ReadUInt32LittleEndian(bytes), _ => BinaryPrimitives.ReadUInt64LittleEndian(bytes) };
    }
}
