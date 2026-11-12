using System.Buffers.Binary;
using System.Text;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.X64;

/// <summary>核对空消息、导出构造链与不返回抛出链；不根据邻近字符串猜测异常类型。</summary>
internal static class X64ExceptionHelpers
{
    internal static IEnumerable<RuntimeHelper> Identify(CodeMap map, CodeScan scan, PcodeMachine machine, Cpp2CS.Model.ProgramModel? model = null)
    {
        var image = map.Image;
        var corlib = Export("il2cpp_get_corlib");
        var findClass = Export("il2cpp_class_from_name");
        var initialize = Export("il2cpp_runtime_object_init");
        var allocate = Export("il2cpp_object_new");
        var raise = Export("il2cpp_raise_exception");
        // object_new 导出在异常路径返回 null；这里仅以正常路径的目标锚定分配器。
        if (allocate == 0 || !Match(allocate, "48 83 ec 28 e8 ?? ?? ?? ?? eb 02 33 c0 48 83 c4 28 c3")
            || raise == 0 || !Match(raise, "48 83 ec 28 33 d2 e8 ?? ?? ?? ?? cc")
            || corlib == 0 || findClass == 0 || initialize == 0) yield break;
        allocate = Terminal(Relative(allocate + 5));
        raise = Terminal(Relative(raise + 7));
        if (allocate == 0 || raise == 0) yield break;
        var noReturn = new NoReturnOracle(machine, map);
        foreach (var calls in scan.All.Where(r => r.Kind is RefKind.Call or RefKind.TailCall).GroupBy(r => r.Target))
        {
            var entry = calls.Key;
            if (map.RegionOf(entry) == CodeRegion.Managed || map.At(entry) is not { HasUnmodeledExceptions: false }) continue;
            var rethrow = WindowsExceptionObjectProof.IsRethrow(image, entry) ? entry
                : Match(entry, "48 83 ec 28 e8 ?? ?? ?? ?? cc") && WindowsExceptionObjectProof.IsRethrow(image, Relative(entry + 5)) ? Relative(entry + 5) : 0;
            if (rethrow != 0)
            {
                yield return new(entry, HelperKind.Rethrow, null,
                    "完整的单指针异常包装、无析构复制回调的类型记录及 MSVC throw 契约；保留原异常堆栈", calls.Count());
                if (entry != rethrow) yield return new(rethrow, HelperKind.Rethrow, null, "已核对重抛包装的直接实现", 0);
                yield return new(WindowsExceptionObjectProof.ThrowTarget(image, rethrow)!.Value, HelperKind.Import, "_CxxThrowException",
                    "独立 MSVC COFF 的完整 throw 入口；托管语义另按调用点的异常类型记录证明", 0);
                continue;
            }
            // codegen throw 重置异常堆栈；只允许匹配元数据中的两个堆栈字段，不能吞掉任意对象写入。
            if (model is not null && Match(entry, "48 89 5c 24 08 57 48 83 ec 20 48 8b f9 48 8b da 48 83 c1 ?? e8 ?? ?? ?? ?? 48 8d 4f ?? e8 ?? ?? ?? ?? 48 8b d3 48 8b cf e8 ?? ?? ?? ?? cc")
                && StackField("_stackTrace", image.ReadUpTo(entry + 19, 1)[0])
                && StackField("_stackTraceString", image.ReadUpTo(entry + 28, 1)[0])
                && Match(Relative(entry + 21), "48 c7 01 00 00 00 00 c3")
                && Match(Relative(entry + 30), "48 c7 01 00 00 00 00 c3")
                && Terminal(Relative(entry + 41)) == raise && noReturn.IsNoReturn(entry))
            {
                yield return new(entry, HelperKind.CodegenRaise, null,
                    "匹配核心库 Exception 的堆栈字段清零、原异常与帧参数转发、导出抛出目标及不返回链", calls.Count());
                continue;
            }
            var outer = entry;
            var seen = new HashSet<ulong>();
            for (var depth = 0; depth < 4 && seen.Add(outer) && Match(outer, "48 83 ec 28 e8 ?? ?? ?? ?? cc"); depth++)
                outer = Relative(outer + 5);
            // 无参工厂将空 StringView 直接存入栈槽；槽位地址未传给任何调用。
            if (Match(outer, "48 83 ec 28 e8 ?? ?? ?? ?? 48 8b c8 33 d2 e8 ?? ?? ?? ?? cc")
                && Terminal(Relative(outer + 15)) == raise)
            {
                var directFactory = Relative(outer + 5);
                if (Match(directFactory, "40 53 48 83 ec 30 33 c0 48 89 44 24 20 48 89 44 24 28 e8 ?? ?? ?? ?? 4c 8d 05 ?? ?? ?? ?? 48 8b c8 48 8d 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 48 8b c8 48 8b d8 e8 ?? ?? ?? ?? 48 83 7c 24 28 00 76 ??")
                    && Terminal(Relative(directFactory + 19)) == corlib
                    && Terminal(Relative(directFactory + 41)) == findClass
                    && Terminal(Relative(directFactory + 49)) == allocate
                    && Terminal(Relative(directFactory + 60)) == initialize
                    && Match(directFactory + 72 + image.ReadUpTo(directFactory + 71, 1)[0], "48 8b c3 48 83 c4 30 5b c3")
                    && CString(Relative(directFactory + 36)) == "System"
                    && CString(Relative(directFactory + 26)) is "IndexOutOfRangeException" or "NullReferenceException" or "DivideByZeroException"
                    && noReturn.IsNoReturn(entry))
                    yield return new(entry, HelperKind.Throw, "System." + CString(Relative(directFactory + 26)),
                        "栈内空消息；类型查找、分配、默认构造与抛出由 PE 导出锚定，空槽地址不逃逸；无正常返回", calls.Count());
                continue;
            }
            if (!Match(outer, "48 83 ec 38 48 8d 4c 24 20 e8 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? cc")) continue;
            var empty = Relative(outer + 10);
            if (!Match(empty, "33 c0 48 89 01 48 89 41 08 48 8b c1 c3")) continue;
            var throwing = Relative(outer + 18);
            if (!Match(throwing, "48 83 ec 28 e8 ?? ?? ?? ?? 48 8b c8 33 d2 e8 ?? ?? ?? ?? cc")
                || Terminal(Relative(throwing + 15)) != raise) continue;
            var factory = Relative(throwing + 5);
            // RCX 保存空 StringView；其长度为零，跳过消息赋值分支。四个调用均由导出身份锚定。
            if (!Match(factory, "48 89 5c 24 08 57 48 83 ec 20 48 8b f9 e8 ?? ?? ?? ?? 4c 8d 05 ?? ?? ?? ?? 48 8b c8 48 8d 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 48 8b c8 48 8b d8 e8 ?? ?? ?? ?? 48 83 7f 08 00 76 ??")) continue;
            if (Terminal(Relative(factory + 14)) != corlib || Terminal(Relative(factory + 36)) != findClass
                || Terminal(Relative(factory + 44)) != allocate || Terminal(Relative(factory + 55)) != initialize) continue;
            var tail = factory + 66 + image.ReadUpTo(factory + 65, 1)[0];
            if (!Match(tail, "48 8b c3 48 8b 5c 24 30 48 83 c4 20 5f c3")) continue;
            var space = CString(Relative(factory + 31));
            var name = CString(Relative(factory + 21));
            if (space != "System" || name is not ("NullReferenceException" or "IndexOutOfRangeException" or "DivideByZeroException")) continue;
            if (!noReturn.IsNoReturn(entry)) continue;
            yield return new(entry, HelperKind.Throw, space + "." + name,
                "空消息包装；类型查找、对象分配、默认构造和抛出均与 PE 导出调用链对应；正常返回路径不存在", calls.Count());
        }

        ulong Export(string name)
        {
            if (!image.Exports.TryGetValue(name, out var target)) return 0;
            return Terminal(target);
        }
        bool StackField(string name, byte offset) => offset < 128 && model!.Fields.Count(f => !f.IsStatic
            && f.Owner.Assembly == "mscorlib.dll" && f.Owner.FullName == "System.Exception" && f.Name == name && f.Offset == offset) == 1;
        ulong Terminal(ulong target)
        {
            var seen = new HashSet<ulong>();
            for (var i = 0; i < 8 && seen.Add(target); i++)
            {
                if (!Match(target, "e9 ?? ?? ?? ??")) return image.IsExecutable(target) ? target : 0;
                target = Relative(target + 1);
            }
            return 0;
        }
        ulong Relative(ulong at) => unchecked(at + 4 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(image.ReadUpTo(at, 4)));
        bool Match(ulong at, string pattern)
        {
            if (!image.IsExecutable(at)) return false;
            var parts = pattern.Split(' ');
            var bytes = image.ReadUpTo(at, parts.Length);
            if (bytes.Length != parts.Length) return false;
            for (var i = 0; i < parts.Length; i++)
                if (parts[i] != "??" && bytes[i] != System.Convert.ToByte(parts[i], 16)) return false;
            return true;
        }
        string? CString(ulong at)
        {
            if (image.SectionAt(at) is not { Executable: false } section || (section.Flags & 1) != 0) return null;
            var bytes = image.ReadUpTo(at, 64);
            var end = bytes.IndexOf((byte)0);
            return end is > 0 and < 64 && bytes[..end].ToArray().All(b => b is >= 32 and < 127)
                ? Encoding.ASCII.GetString(bytes[..end]) : null;
        }
    }
}
