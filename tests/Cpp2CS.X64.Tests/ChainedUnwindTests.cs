using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class ChainedUnwindTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        var bytes = original.ToArray();
        const ulong basis = 0x180000000;
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        U32(0x124, 36);
        U32(0x700, 0x1000); U32(0x704, 0x1005); U32(0x708, 0x3140);
        U32(0x70c, 0x1005); U32(0x710, 0x100b); U32(0x714, 0x3150);
        U32(0x718, 0x100b); U32(0x71c, 0x100c); U32(0x720, 0x3170);
        bytes[0x740] = 1;
        bytes[0x750] = 0x21;
        bytes.AsSpan(0x700, 12).CopyTo(bytes.AsSpan(0x754));
        bytes[0x770] = 0x21;
        bytes.AsSpan(0x70c, 12).CopyTo(bytes.AsSpan(0x774));
        System.Convert.FromHexString("E900000000B82A000000C3C3").CopyTo(bytes, 0x200);
        var image = ImageDocument.Parse(bytes);
        var table = FunctionTable.Build(image);
        var root = table.At(basis + 0x1008)!;
        Check(root.Start == basis + 0x1000 && root.ContiguousEnd == basis + 0x100c && root.Fragments.Length == 2
            && !root.HasSeparatedFragments, "连续多级展开链属于同一函数且保留片段证据");
        Check(root.Fragments.All(f => f.WindowsUnwind is { Flags: 4, ChainedParent: not null })
            && root.WindowsUnwind is { Flags: 0 }, "各片段必须保留自身展开记录，不能只剩主范围状态");
        var map = CodeMap.BuildPe(image, [basis + 0x1000, basis + 0x1005]);
        Check(map.At(basis + 0x1005) is { HasUnmodeledExceptions: false } range && range.Start == basis + 0x1000,
            "片段内部的候选入口不得遮盖主函数");
        var function = new CfgBuilder(new PcodeMachine(image, decoder), map).Build(basis + 0x1000);
        Check(function.Problems.Count == 0 && function.Blocks.SelectMany(b => b.Statements).Any(s => s is Return)
            && function.Blocks.SelectMany(b => b.Statements).All(s => s is not Call), "跨展开片段的跳转仍是函数内控制流");
        // 空隙不按相邻地址猜测为函数内容。
        U32(0x70c, 0x1010); U32(0x710, 0x1016);
        U32(0x718, 0x1016); U32(0x71c, 0x1017);
        bytes.AsSpan(0x70c, 12).CopyTo(bytes.AsSpan(0x774));
        var separated = FunctionTable.Build(ImageDocument.Parse(bytes)).At(basis + 0x1000)!;
        Check(separated.HasSeparatedFragments && separated.ContiguousEnd == basis + 0x1005, "分离片段继续保留缺口");
        Check(CodeMap.BuildPe(ImageDocument.Parse(bytes), [basis + 0x1010]).At(basis + 0x1010) is null,
            "分离片段不得按缺少展开表的元数据入口重新放行");
        bytes[0x740] = 9; U32(0x744, 0x1000);
        Check(CodeMap.BuildPe(ImageDocument.Parse(bytes), []).At(basis + 0x1000)!.HasUnmodeledExceptions,
            "主展开信息有处理器时不得删除异常边界");
        bytes[0x740] = 17;
        Check(CodeMap.BuildPe(ImageDocument.Parse(bytes), []).At(basis + 0x1000) is
            { HasUnmodeledExceptions: true, HasUnwindOnlyHandler: false },
            "仅清理处理器不能覆盖分离代码片段的未知路径");
        bytes[0x750] = 0x29;
        var rejected = false;
        try { _ = FunctionTable.Build(ImageDocument.Parse(bytes)); }
        catch (InvalidDataException) { rejected = true; }
        Check(rejected, "CHAININFO 与 EHANDLER 同时置位必须拒绝");
        Console.WriteLine("连续展开链、分离范围和异常处理边界测试通过");
    }

    private static void Check(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }
}
