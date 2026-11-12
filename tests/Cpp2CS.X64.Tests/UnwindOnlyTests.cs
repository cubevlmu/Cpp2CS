using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class UnwindOnlyTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        // 调用不可继续的系统异常；随后的 RET 不可达。处理器本身有 RET，不能与主体返回混淆。
        foreach (var flags in new byte[] { 0, 1, 2, 3, 10 })
        foreach (var returns in new[] { false, true })
        {
            var bytes = original.ToArray();
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x700, 0x1030); U32(0x704, 0x103c); U32(0x708, 0x3140);
            bytes[0x740] = (byte)(1 | flags << 3);
            U32(0x744, 0x1010);
            bytes[0x231] = returns ? (byte)0 : (byte)1;
            var image = ImageDocument.Parse(bytes);
            var range = FunctionTable.Build(image).At(basis + 0x1030)!;
            var map = CodeMap.BuildPe(image, [basis + 0x1060]);
            var function = map.At(basis + 0x1030)!;
            Check(range.UnwindFlags == flags, "原始展开标志必须保留");
            Check(function.HasUnwindOnlyHandler == (flags == 2), "只有明确的 UHANDLER 可作清理依据");
            Check(function.HasUnmodeledExceptions == ((flags & 3) != 0), "不能删除未建模的处理器");
            var cfg = new CfgBuilder(new PcodeMachine(image, decoder), map);
            var expected = !returns && flags == 0;
            Check(cfg.NoReturn.IsNoReturn(basis + 0x1030) == expected, "未知清理可能离开函数，不能只依据 UHANDLER 证明不返回");
            Check(cfg.NoReturn.IsNoReturn(basis + 0x1060) == expected, "不返回证据沿直接调用传播");
            if (expected)
                Check(cfg.Build(basis + 0x1060).Blocks.SelectMany(b => b.Statements).All(s => s is not Opaque),
                    "只在已证明不返回之后停止，不解码调用方 INT3");
        }
        Console.WriteLine("展开清理与异常捕获区分通过：10 组 PE 标志及返回路径变异");
    }

    private static void Check(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }
}
