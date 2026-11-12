using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class ReferenceTests
{
    public static void Run(SleighDecoder decoder)
    {
        // 独立构造三个 PE 节，不依赖业务二进制或元数据。
        var bytes = new byte[0x800];
        void U16(int at, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(at), value);
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        U16(0, 0x5a4d); U32(60, 0x80); U32(0x80, 0x4550);
        U16(0x84, 0x8664); U16(0x86, 3); U16(0x94, 144);
        U16(0x98, 0x20b);
        const ulong imageBase = 0x180000000;
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0xb0), imageBase);
        U32(0xb8, 0x1000); U32(0xbc, 0x200); U32(0xd0, 0x4000); U32(0xd4, 0x200);
        U32(0x104, 4); U32(0x120, 0x3100); U32(0x124, 12);
        U32(0x700, 0x1000); U32(0x704, 0x100a); U32(0x708, 0x3110);
        bytes[0x710] = 1;
        U32(0x110, 0x3020); U32(0x114, 40);
        U32(0x620, 0x3070); U32(0x62c, 0x3050); U32(0x630, 0x3090);
        System.Text.Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(bytes, 0x650);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x670), 0x30b0);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x678), 0x800000000000002a);
        System.Text.Encoding.ASCII.GetBytes("RaiseException\0").CopyTo(bytes, 0x6b2);
        for (var i = 0; i < 3; i++)
        {
            var at = 0x128 + i * 40;
            System.Text.Encoding.ASCII.GetBytes(new[] { ".text", ".data", ".rdata" }[i]).CopyTo(bytes, at);
            U32(at + 8, 0x200); U32(at + 12, (uint)(i + 1) * 0x1000);
            U32(at + 16, 0x200); U32(at + 20, (uint)(i + 1) * 0x200);
            U32(at + 36, new uint[] { 0x60000020, 0xc0000040, 0x40000040 }[i]);
        }
        System.Convert.FromHexString("488B05F90F0000C20000").CopyTo(bytes, 0x200);
        System.Convert.FromHexString("488D0DE91F0000C3").CopyTo(bytes, 0x210);
        System.Convert.FromHexString("C20800CC").CopyTo(bytes, 0x220);
        System.Convert.FromHexString("BA01000000FF1555200000C3").CopyTo(bytes, 0x230);
        System.Convert.FromHexString("BA00000000FF1545200000C3").CopyTo(bytes, 0x240);
        System.Convert.FromHexString("FF153A200000C3").CopyTo(bytes, 0x250);
        System.Convert.FromHexString("E8CBFFFFFFCC").CopyTo(bytes, 0x260);
        System.Convert.FromHexString("85C97407BA01000000EB05BA00000000FF15FA1F0000C3").CopyTo(bytes, 0x280);
        System.Convert.FromHexString("E89BFFFFFF").CopyTo(bytes, 0x2a0);
        System.Convert.FromHexString("C3").CopyTo(bytes, 0x2a5);
        System.Convert.FromHexString("BA01000000E886FFFFFFFF15CA1F0000C3").CopyTo(bytes, 0x2b0);
        var image = ImageDocument.Parse(bytes);
        NativeCopyTests.Run(bytes, decoder);
        GuardedCopyTests.Run(bytes, decoder);
        NativeLeafTests.Run(bytes, decoder);
        NativeBodyTests.Run(bytes, decoder);
        ObservedReadTests.Run(bytes, decoder);
        InvokerTests.Run(bytes, decoder);
        FieldHelperTests.Run(bytes, decoder);
        RuntimeForwardingTests.Run(bytes, decoder);
        BaseConstructorTests.Run(bytes, decoder);
        SkippedBaseThunkTests.Run(bytes, decoder);
        ConstructorPrefixTests.Run(bytes, decoder);
        ResultBufferTests.Run(bytes, decoder);
        StructGetterEmissionTests.Run(bytes);
        ReadonlyConstructionTests.Run(bytes, decoder);
        GenericScopeTests.Run(bytes, decoder);
        SharedDelegateConstructionTests.Run(bytes, decoder);
        ReferenceWrapperTests.Run(bytes, decoder);
        StackCopyTests.Run(bytes, decoder);
        StackReferenceTests.Run(bytes, decoder);
        AffineAddressTests.Run();
        PlatformDescriptorTests.Run(bytes);
        ConstructorShapeTests.Run();
        HierarchyTypeTests.Run(bytes, decoder);
        CallWrapperTests.Run(bytes, decoder);
        FloatCompositeTests.Run(bytes, decoder);
        ExceptionHelperTests.Run(bytes, decoder);
        VectorConstantTests.Run(bytes, decoder);
        Check(image.Section(".data")!.Flags == 3 && image.Section(".rdata")!.Flags == 2 && image.Section(".text")!.Flags == 6, "PE 节权限");
        Check(image.Imports[imageBase + 0x3090] == "RaiseException" && image.Imports[imageBase + 0x3098] == "KERNEL32.dll!#42", "PE 名称与序号导入");
        Check(image.ReadPointer(imageBase + 0x3090) is null, "IAT 不作为静态指针读取");
        ulong[] entries = [.. new ulong[] { 0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050, 0x1060, 0x1080, 0x10a0, 0x10a5, 0x10b0 }.Select(a => a + imageBase)];
        var map = CodeMap.BuildPe(image, entries);
        var machine = new PcodeMachine(image, decoder);
        var scan = X64References.Scan(map, machine, entries);
        Check(scan.All.Contains(new(entries[0], imageBase + 0x2000, RefKind.Load, 8)), "RIP 相对读取引用");
        Check(scan.All.Contains(new(entries[1], imageBase + 0x3000, RefKind.Address, 0)), "RIP 相对地址引用");
        var cfg = new CfgBuilder(machine, map);
        Check(cfg.Build(entries[0]).Problems.Count == 0, "RET 0 不进入填充区");
        var unknown = cfg.Build(entries[2]);
        Check(unknown.Blocks.SelectMany(b => b.Statements).OfType<Opaque>().Count() == 1 && unknown.Blocks.Single().End == entries[2] + 3, "未知返回保持诊断并停止探索");
        var oracle = cfg.NoReturn;
        var breakpoint = new List<Stmt>();
        PcodeLowerer.Lower(decoder.Decode(imageBase + 0x1000, [0xcc]), breakpoint);
        Check(breakpoint is [Trap { Kind: "breakpoint" }], "INT3 必须准确识别并保留为陷阱");
        var trapBytes = bytes.ToArray(); trapBytes[0x220] = 0xcc;
        var trapImage = ImageDocument.Parse(trapBytes);
        Check(!new NoReturnOracle(new PcodeMachine(trapImage, decoder), CodeMap.BuildPe(trapImage, entries))
            .IsNoReturn(imageBase + 0x1020), "可恢复的断点陷阱不能独立证明函数不返回");
        Check(oracle.IsNoReturn(imageBase + 0x1030), "不可继续异常没有正常返回边");
        Check(!oracle.IsNoReturn(imageBase + 0x1040) && !oracle.IsNoReturn(imageBase + 0x1050), "可继续或未知 flags 不构成不返回证据");
        Check(oracle.IsNoReturn(imageBase + 0x1060) && cfg.Build(imageBase + 0x1060).Blocks.SelectMany(b => b.Statements).All(s => s is not Opaque), "抛异常链不探索 INT3 填充");
        Check(!oracle.IsNoReturn(imageBase + 0x1080), "汇合存在可继续路径时保守返回");
        Check(!oracle.IsNoReturn(imageBase + 0x10a0) && !oracle.IsNoReturn(entries[2]), "边界或未知语义不是不返回证明");
        Check(!oracle.IsNoReturn(imageBase + 0x10b0), "普通调用使易失参数常量失效");
        Check(oracle.Returns(imageBase + 0x1030, map.At(imageBase + 0x1030)! with { HasUnmodeledExceptions = true }), "未恢复异常处理可能返回");
        var otherModule = bytes.ToArray();
        System.Text.Encoding.ASCII.GetBytes("example.dll\0\0").CopyTo(otherModule, 0x650);
        var otherImage = ImageDocument.Parse(otherModule);
        var otherMap = CodeMap.BuildPe(otherImage, entries);
        Check(!new NoReturnOracle(new PcodeMachine(otherImage, decoder), otherMap).IsNoReturn(imageBase + 0x1030), "同名自定义导入不能套用系统异常语义");
        var fallback = bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(fallback.AsSpan(0x620), 0);
        bytes.AsSpan(0x670, 24).CopyTo(fallback.AsSpan(0x690));
        Check(ImageDocument.Parse(fallback).Imports.Count == 2, "未绑定映像允许缺少 ILT");
        BinaryPrimitives.WriteUInt32LittleEndian(fallback.AsSpan(0x624), 1);
        Check(ImageDocument.Parse(fallback).Imports.Count == 0, "绑定 IAT 不解读为名称");
        var malformed = bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(malformed.AsSpan(0x114), 20);
        Reject(malformed, "导入描述符必须终止");
        malformed = bytes.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(malformed.AsSpan(0x678), 0x800000000001002a);
        Reject(malformed, "序号保留位必须为零");
        malformed = bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(malformed.AsSpan(0x630), 0x31fc);
        Reject(malformed, "IAT 必须完整映射");
        Console.WriteLine("PE 节属性、直接引用与返回 CFG 测试通过");
        RuntimeFactTests.Run(bytes, decoder);
        ChainedUnwindTests.Run(bytes, decoder);
        UnwindOnlyTests.Run(bytes, decoder);
        WindowsEhReaderTests.Run(bytes);
    }

    private static void Reject(byte[] bytes, string reason)
    {
        try { _ = ImageDocument.Parse(bytes); }
        catch (InvalidDataException) { return; }
        throw new InvalidOperationException(reason);
    }

    private static void Check(bool value, string reason)
    {
        if (!value) throw new InvalidOperationException(reason);
    }
}
