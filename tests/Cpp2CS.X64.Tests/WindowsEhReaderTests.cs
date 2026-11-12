using System.Buffers.Binary;
using System.Text;
using Cpp2CS.Image;

namespace Cpp2CS.X64.Tests;

internal static class WindowsEhReaderTests
{
    internal static void Run(byte[] original)
    {
        foreach (var variant in new[] { "filter", "cleanup", "unknown", "count", "crossing", "cxx4", "cxx4-unwind", "cxx4-reserved", "cxx4-backlink",
            "cxx3", "cxx3-count", "cxx3-cycle", "cxx3-magic" })
        {
            var bytes = original.ToArray();
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            var cxx4 = variant.StartsWith("cxx4", StringComparison.Ordinal);
            var cxx3 = variant.StartsWith("cxx3", StringComparison.Ordinal);
            Encoding.ASCII.GetBytes(cxx4 ? "vcruntime140_1.dll\0" : cxx3 ? "vcruntime140.dll\0" : "ntdll.dll\0").CopyTo(bytes, 0x650);
            Encoding.ASCII.GetBytes((variant == "unknown" ? "UnknownHandler" : cxx4 ? "__CxxFrameHandler4" : cxx3 ? "__CxxFrameHandler3" : "__C_specific_handler") + "\0").CopyTo(bytes, 0x6b2);
            U32(0x124, 12); U32(0x700, 0x1000); U32(0x704, 0x1020); U32(0x708, 0x3140);
            bytes[0x740] = 9; bytes[0x741] = 4; U32(0x744, 0x1080);
            Convert.FromHexString("FF250A200000").CopyTo(bytes, 0x280); bytes[0x290] = 0xc3;
            U32(0x748, variant == "count" ? 4097U : variant == "crossing" ? 2U : 1U);
            U32(0x74c, 0x1000); U32(0x750, variant == "crossing" ? 0x1018U : 0x1010U);
            U32(0x754, variant == "cleanup" ? 0x1090U : 1U); U32(0x758, variant == "cleanup" ? 0U : 0x1010U);
            if (variant == "crossing") { U32(0x75c, 0x1008); U32(0x760, 0x1020); U32(0x764, 1); U32(0x768, 0x1010); }
            if (cxx4)
            {
                U32(0x748, 0x3180);
                bytes[0x780] = variant == "cxx4-reserved" ? (byte)128 : variant == "cxx4" ? (byte)0 : (byte)8;
                if (variant is "cxx4-unwind" or "cxx4-backlink") { U32(0x781, 0x31a0); U32(0x785, 0x3190); }
                else U32(0x781, 0x3190);
                bytes[0x790] = 2; bytes[0x791] = 16; bytes[0x792] = 0;
                bytes[0x7a0] = 2; bytes[0x7a1] = variant == "cxx4-backlink" ? (byte)0 : (byte)8;
            }
            if (cxx3)
            {
                U32(0x748, 0x3180); U32(0x780, variant == "cxx3-magic" ? 0x19930521U : 0x19930522U);
                U32(0x784, variant == "cxx3-count" ? 1025U : 1U); U32(0x788, 0x31b0);
                U32(0x78c, 0); U32(0x790, 0); U32(0x794, 1); U32(0x798, 0x31c0);
                U32(0x79c, unchecked((uint)-32)); U32(0x7a0, 0); U32(0x7a4, 1);
                U32(0x7b0, variant == "cxx3-cycle" ? 0 : uint.MaxValue); U32(0x7b4, 0x1090);
                U32(0x7c0, 0x1008); U32(0x7c4, 0);
            }
            var image = ImageDocument.Parse(bytes); var range = FunctionTable.Build(image).Ranges.Single();
            Check(range.WindowsUnwind is { Version: 1, Flags: 1, PrologLength: 4, Codes.Length: 0 }, "展开记录保留真实头部和编码");
            var parsed = WindowsEhReader.Read(image, range);
            Check(parsed.ManagedProjection == "not-proven", "读表不能冒充托管 EH 恢复完成");
            if (variant is "filter" or "cleanup")
                Check(parsed.HandlerKind == WindowsHandlerKind.Seh && parsed.MetadataStatus == "parsed"
                    && parsed.Scopes.Single().Kind == variant, "只有已锚定处理器才读取对应 scope schema");
            else if (variant == "unknown") Check(parsed.HandlerKind == WindowsHandlerKind.Unknown && parsed.Scopes.Count == 0, "未知处理器不得根据表头猜测 schema");
            else if (variant == "cxx3") Check(parsed.HandlerKind == WindowsHandlerKind.Cxx3 && parsed.MetadataStatus == "parsed"
                && parsed.UnwindActions is [{ State: 0, NextState: -1, Action: 0x180001090 }] && parsed.UnwindHelpOffset == -32,
                "FH3 使用固定相对表及有符号展开帧偏移");
            else if (variant == "cxx3-magic") Check(parsed.MetadataStatus == "unsupported-schema", "不按 FH3 布局猜测旧版本 FuncInfo");
            else if (variant is "cxx4" or "cxx4-unwind") Check(parsed.HandlerKind == WindowsHandlerKind.Cxx4 && parsed.MetadataStatus == "parsed"
                && parsed.IpStates is [{ Address: 0x180001008, State: -1 }] && parsed.UnwindActions.Count == (variant == "cxx4" ? 0 : 1),
                "FH4 按压缩整数和相对状态表读取，不得误用 SEH scope 偏移");
            else Check(parsed.MetadataStatus == "malformed", "表越界或交叉区域必须明确拒绝");
        }
        // 预期字节来自 Fixtures/Fh4Encoding.cpp 调用 MSVC 官方编码器的输出。
        foreach (var (value, encoded) in new (uint, string)[] { (0, "00"), (1, "02"), (127, "FE"),
            (128, "0102"), (16383, "FDFF"), (16384, "030002"), (2097151, "FBFFFF"),
            (2097152, "07000002"), (268435455, "F7FFFFFF"), (268435456, "0F00000010"), (uint.MaxValue, "0FFFFFFFFF") })
        {
            var bytes = original.ToArray();
            void U32(int at, uint data) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), data);
            Encoding.ASCII.GetBytes("vcruntime140_1.dll\0").CopyTo(bytes, 0x650);
            Encoding.ASCII.GetBytes("__CxxFrameHandler4\0").CopyTo(bytes, 0x6b2);
            U32(0x124, 12); U32(0x700, 0x1000); U32(0x704, 0x1020); U32(0x708, 0x3140);
            bytes[0x740] = 9; U32(0x744, 0x1080); U32(0x748, 0x3180);
            Convert.FromHexString("FF250A200000").CopyTo(bytes, 0x280);
            bytes[0x780] = 4;
            var data = Convert.FromHexString(encoded); data.CopyTo(bytes, 0x781);
            U32(0x781 + data.Length, 0x3190);
            bytes[0x790] = 2; bytes[0x791] = 16; bytes[0x792] = 0;
            var image = ImageDocument.Parse(bytes);
            var result = WindowsEhReader.Read(image, FunctionTable.Build(image).Ranges.Single());
            Check(result.MetadataStatus == "parsed" && result.BbtFlags == value, "FH4 压缩整数边界必须与工具链编码器一致");
        }
        Console.WriteLine("Windows EH 读取检查通过：处理器导入身份、SEH scope、清理／过滤、计数越界、交叉区域及FH4隔离");
    }

    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
