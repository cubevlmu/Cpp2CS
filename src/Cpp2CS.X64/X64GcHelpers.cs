using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Ir;

namespace Cpp2CS.X64;

/// <summary>从导出字段写入定位 GC 通知，验证完整位图标记循环。</summary>
internal static class X64GcHelpers
{
    internal static RuntimeHelper? Identify(CodeMap map, PcodeMachine machine)
    {
        if (!map.Image.Exports.TryGetValue("il2cpp_gc_wbarrier_set_field", out var entry)) return null;
        var wrapper = map.Image.ReadUpTo(entry, 11);
        // (obj, location, value) 转发为 (location, value)。
        if (wrapper.Length != 11 || !wrapper[..7].SequenceEqual(System.Convert.FromHexString("488BCA498BD0E9"))) return null;
        var store = Terminal(Relative(entry + 11, wrapper[7..]));
        var body = map.Image.ReadUpTo(store, 8);
        if (body.Length != 8 || !body[..4].SequenceEqual(System.Convert.FromHexString("488911E9"))) return null;
        var notify = Terminal(Relative(store + 8, body[4..]));
        if (notify == 0 || map.RegionOf(notify) == CodeRegion.Managed || map.At(notify)?.HasUnmodeledExceptions == true) return null;
        var bytes = map.Image.ReadUpTo(notify, 66);
        if (!CardMarkingBody(bytes)) return null;
        var flag = Relative(notify + 7, bytes.Slice(2, 4));
        var bitmap = Relative(notify + 23, bytes.Slice(19, 4));
        if (map.Image.SectionAt(flag) is not { Executable: false } flagSection || (flagSection.Flags & 1) == 0
            || map.Image.SectionAt(bitmap) is not { Executable: false } bitmapSection || (bitmapSection.Flags & 1) == 0) return null;
        return new(notify, HelperKind.GcNotification, null,
            "导出字段写入之后的单参数通知：开关、页号位图、LOCK CMPXCHG 重试；不解引用输入地址", 0);

        ulong Terminal(ulong address)
        {
            var seen = new HashSet<ulong>();
            for (var i = 0; i < 8 && map.Image.IsExecutable(address)
                && map.RegionOf(address) != CodeRegion.Managed && seen.Add(address); i++)
            {
                var statements = new List<Stmt>();
                if (machine.Lift(address, statements) == 0) return 0;
                if (statements is not [Jump jump]) return address;
                address = jump.Target;
            }
            return 0;
        }
    }

    // RIP 位移独立解析；其余指令、分支落点和原子更新必须完整匹配。
    internal static bool CardMarkingBody(ReadOnlySpan<byte> bytes) => bytes.Length == 66
        && bytes[..2].SequenceEqual(System.Convert.FromHexString("833D"))
        && bytes.Slice(6, 13).SequenceEqual(System.Convert.FromHexString("004C8BC1743549C1E80C488D0D"))
        && bytes[23..].SequenceEqual(System.Convert.FromHexString("4181E0FFFF1F00418BC048C1E8064183E03F488D14C10F0D0A488B02488BC84C0FABC1F0480FB10A75EFC3"));

    private static ulong Relative(ulong next, ReadOnlySpan<byte> displacement) =>
        unchecked(next + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(displacement));
}
