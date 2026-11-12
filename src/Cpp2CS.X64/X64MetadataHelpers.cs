using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Image;

namespace Cpp2CS.X64;

/// <summary>MSVC 元数据令牌解析器的结构推断；只接受已核对的原子读取、解码、分派和存回形态。</summary>
internal static class X64MetadataHelpers
{
    internal static IEnumerable<RuntimeHelper> Identify(CodeMap map, CodeScan scan, UsageSlots usages)
    {
        var calls = scan.All.Where(r => r.Kind == RefKind.Call).GroupBy(r => r.Target);
        foreach (var group in calls)
        {
            var entry = group.Key;
            var count = group.Count();
            // 调用点证据只是筛选条件，不能单凭槽位地址推断函数语义。
            var slots = usages.SlotAddressBeforeCall.GetValueOrDefault(entry);
            if (slots < 2 || slots * 2 <= count || map.At(entry) is not { HasUnmodeledExceptions: false }) continue;
            var image = map.Image;
            // 初始化调用之后是栈上零 OR 的完整屏障；调用参数和返回寄存器保持不变。
            if (!Match(image, entry, "48 83 ec 28 e8 ?? ?? ?? ?? f0 83 0c 24 00 48 83 c4 28 c3")) continue;
            var wrapper = Relative(image, entry + 5);
            if (!Match(image, wrapper, "b2 01 e9 ?? ?? ?? ??")) continue;
            var core = Relative(image, wrapper + 3);
            if (!Resolver(image, map, core)) continue;
            yield return new(entry, HelperKind.InitMetadata, null,
                $"结构推断：MSVC 原子槽位读取、低位标记、29/1 位令牌解码、七类分派与条件存回；{slots}/{count} 调用点引用已解码槽位；包装保持参数并执行锁定屏障", count);
            // 内层固定 initialize=true，使用相同槽位解析器；不把外层附加屏障归到内层。
            if (map.RegionOf(wrapper) != CodeRegion.Managed)
                yield return new(wrapper, HelperKind.InitMetadata, null,
                    "结构推断：已核对解析器的 initialize=true 单参数入口；不包含外层锁定屏障",
                    scan.All.Count(r => r.Target == wrapper && r.Kind is RefKind.Call or RefKind.TailCall));
        }
    }

    private static bool Resolver(ImageDocument image, CodeMap map, ulong core)
    {
        if (map.At(core) is not { HasUnmodeledExceptions: false } range || range.Start != core || range.Size > 2048) return false;
        // RCX 是槽位指针，R14 保存它；零增量 XADD 取得唯一快照，偶数指针直接返回。
        if (!Match(image, core, "48 89 5c 24 18 41 56 48 83 ec 40 33 db 4c 8b f1 8b cb 44 0f b6 c2 f0 49 0f c1 0e f6 c1 01 75 0f 48 8b c1 48 8b 5c 24 60 48 83 c4 40 41 5e c3 48 89 7c 24 58 8b c1 c1 e8 1d 8b f9 d1 ef 81 e7 ff ff ff 0f ff c8 83 f8 06 0f 87 ?? ?? ?? ?? 4c 8d 0d ?? ?? ?? ?? 48 98 41 8b 94 81 ?? ?? ?? ?? 49 03 d1 ff e2")) return false;
        var exit = Relative(image, core + 0x4a);
        var basis = Relative(image, core + 0x51);
        var table = basis + U32(image, core + 0x5b);
        if (basis != image.PreferredBase || exit < core + 0x64 || exit + 20 > range.End || table < exit + 20
            || table + 28 > range.End || image.ReadUpTo(table, 28).Length != 28
            || image.SectionAt(table) is not { } tableSection || (tableSection.Flags & 1) != 0) return false;
        // 所有正常慢路径在非空时向同一个槽位写入结果；恢复非易失寄存器后返回该结果。
        var join = exit - 9;
        if (!Match(image, join, "48 85 db 74 04 90 49 89 1e 48 8b 7c 24 58 48 8b c3 48 8b 5c 24 60 48 83 c4 40 41 5e c3")) return false;
        var targets = Enumerable.Range(0, 7).Select(i => basis + U32(image, table + (ulong)i * 4)).ToArray();
        if (targets.Any(t => t < core + 0x64 || t >= join) || targets.Distinct().Count() != 6 || targets[2] != targets[5]) return false;
        // 类型信息、Il2CppType、方法、字段的实参及返回结果有各自的固定形态。
        if (!Match(image, targets[0], "41 0f b6 d0 8b cf e8 ?? ?? ?? ?? 48 8b d8 e9 ?? ?? ?? ??")
            || Relative(image, targets[0] + 15) != join || !image.IsExecutable(Relative(image, targets[0] + 7))) return false;
        if (!Match(image, targets[1], "48 8b 05 ?? ?? ?? ?? 48 8b 48 38 48 8b 1c f9 e9 ?? ?? ?? ??")
            || Relative(image, targets[1] + 16) != join) return false;
        if (!Match(image, targets[2], "e8 ?? ?? ?? ?? 48 8b d8 e9 ?? ?? ?? ??")
            || Relative(image, targets[2] + 9) != join || !image.IsExecutable(Relative(image, targets[2] + 1))) return false;
        if (!Match(image, targets[3], "8b cf e8 ?? ?? ?? ?? 48 8b d8 e9 ?? ?? ?? ??")
            || Relative(image, targets[3] + 11) != join || !image.IsExecutable(Relative(image, targets[3] + 3))) return false;
        // 字符串有缓存读取和原子发布，字段 RVA 分支重新取得 FieldInfo。
        if (!Match(image, targets[4], "48 8b 1d ?? ?? ?? ?? 8b d7 48 c1 e2 03 48 83 3c fb 00 74 09 48 8b 1c 1a e9 ?? ?? ?? ??")
            || Relative(image, targets[4] + 25) != join
            || !Match(image, targets[6], "8b cf 48 89 74 24 50 e8 ?? ?? ?? ?? 48 8b f0")
            || Relative(image, targets[6] + 8) != Relative(image, targets[3] + 3)) return false;
        return true;
    }

    private static uint U32(ImageDocument image, ulong address) => BinaryPrimitives.ReadUInt32LittleEndian(image.ReadUpTo(address, 4));
    private static ulong Relative(ImageDocument image, ulong displacement) => unchecked(displacement + 4 + (ulong)(long)(int)U32(image, displacement));

    private static bool Match(ImageDocument image, ulong address, string pattern)
    {
        var parts = pattern.Split(' ');
        var bytes = image.ReadUpTo(address, parts.Length);
        if (bytes.Length != parts.Length) return false;
        for (var i = 0; i < parts.Length; i++)
            if (parts[i] != "??" && bytes[i] != System.Convert.ToByte(parts[i], 16)) return false;
        return true;
    }
}
