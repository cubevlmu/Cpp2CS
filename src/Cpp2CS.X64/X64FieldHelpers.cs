using Cpp2CS.Facts;
using Cpp2CS.Ir;

namespace Cpp2CS.X64;

/// <summary>由三个导出访问器核对字段布局，再识别完整的实例字段地址计算体。</summary>
internal static class X64FieldHelpers
{
    internal static IEnumerable<RuntimeHelper> Identify(CodeMap map, CodeScan scan, PcodeMachine machine)
    {
        ulong Terminal(ulong entry)
        {
            var seen = new HashSet<ulong>();
            for (var i = 0; i < 8 && machine.Image.IsExecutable(entry) && seen.Add(entry); i++)
            {
                if (map.At(entry)?.HasUnmodeledExceptions == true) return 0;
                var statements = new List<Stmt>();
                if (machine.Lift(entry, statements) <= 0) return 0;
                if (statements is not [Jump jump]) return entry;
                entry = jump.Target;
            }
            return 0;
        }
        byte[] Export(string name, int length) => machine.Image.Exports.TryGetValue(name, out var entry) && Terminal(entry) is var target && target != 0
            ? machine.Image.ReadUpTo(target, length).ToArray() : [];
        var parent = Export("il2cpp_field_get_parent", 5);
        var offset = Export("il2cpp_field_get_offset", 5);
        var valueType = Export("il2cpp_class_is_valuetype", 7);
        if (parent.Length != 5 || !parent.AsSpan(0, 3).SequenceEqual(new byte[] { 0x48, 0x8b, 0x41 }) || parent[4] != 0xc3
            || offset.Length != 5 || !offset.AsSpan(0, 3).SequenceEqual(new byte[] { 0x48, 0x63, 0x41 }) || offset[4] != 0xc3
            || valueType.Length != 7 || !valueType.AsSpan(0, 2).SequenceEqual(new byte[] { 0x8b, 0x41 })
            || !valueType.AsSpan(3).SequenceEqual(new byte[] { 0xc1, 0xe8, 0x1f, 0xc3 })
            || parent[3] >= 128 || offset[3] >= 128 || valueType[2] >= 128 || parent[3] == offset[3]) yield break;
        // CMP x,0 不会溢出；随后 LEA 不改标志，因此 CMOVNS 与 CMOVGE 在此完整体中等价。
        var expected = System.Convert.FromHexString("488B42004C6342004C03C183780000498D48F0490F49C8488BC1C3");
        expected[3] = parent[3]; expected[7] = offset[3]; expected[13] = valueType[2];
        var emitted = new HashSet<ulong>();
        foreach (var group in scan.All.Where(r => r.Kind is RefKind.Call or RefKind.TailCall).GroupBy(r => r.Target))
        {
            var entry = Terminal(group.Key);
            if (entry == 0 || map.RegionOf(entry) == CodeRegion.Managed) continue;
            var body = machine.Image.ReadUpTo(entry, expected.Length);
            if (body.Length != expected.Length || body[21] is not (0x49 or 0x4d)) continue;
            expected[21] = body[21];
            if (!body.SequenceEqual(expected)) continue;
            foreach (var target in new[] { entry, group.Key })
                if (emitted.Add(target))
                    yield return new(target, HelperKind.FieldAddress, null,
                        "PE 字段父类／有符号偏移／值类型位访问器与完整地址计算体；值类型扣除对象头", group.Count());
        }
    }
}
