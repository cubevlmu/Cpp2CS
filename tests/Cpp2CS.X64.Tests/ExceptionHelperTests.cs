using System.Buffers.Binary;
using System.Text;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class ExceptionHelperTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        var bytes = original.ToArray();
        const ulong basis = 0x180000000;
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        void Code(int at, string hex) => System.Convert.FromHexString(hex).CopyTo(bytes, at - 0xe00);
        void Rel(int at, int target) => BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(at - 0xe00), target - at - 4);
        Array.Clear(bytes, 0x200, 0x400);
        U32(0x108, 0x2000); U32(0x10c, 0x200);
        U32(0x414, 5); U32(0x418, 5); U32(0x41c, 0x2040); U32(0x420, 0x2060); U32(0x424, 0x2080);
        (string Name, uint Address)[] exports = [("il2cpp_get_corlib", 0x10b9), ("il2cpp_class_from_name", 0x10ba),
            ("il2cpp_runtime_object_init", 0x10bb), ("il2cpp_object_new", 0x10a0), ("il2cpp_raise_exception", 0x10c0)];
        var nameAt = 0x490;
        for (var i = 0; i < exports.Length; i++)
        {
            U32(0x440 + i * 4, exports[i].Address); U32(0x460 + i * 4, (uint)(nameAt + 0x1c00));
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x480 + i * 2), (ushort)i);
            nameAt += Encoding.ASCII.GetBytes(exports[i].Name + "\0", bytes.AsSpan(nameAt));
        }
        Code(0x1000, "4883EC28E800000000CC"); Rel(0x1005, 0x1010);
        Code(0x1010, "4883EC28E800000000488BC833D2E800000000CC"); Rel(0x1015, 0x1030); Rel(0x101f, 0x10d0);
        // 空消息的长度槽未逃逸；不可达消息设置区可改变而不影响此路径。
        Code(0x1030, "40534883EC3033C048894424204889442428E8000000004C8D0500000000488BC8488D1500000000E800000000488BC8E800000000488BC8488BD8E80000000048837C24280076089090909090909090488BC34883C4305BC3");
        Rel(0x1043, 0x10b9); Rel(0x104a, 0x3180); Rel(0x1054, 0x31a0);
        Rel(0x1059, 0x10ba); Rel(0x1061, 0x10b8); Rel(0x106c, 0x10bb);
        Code(0x10a0, "4883EC28E800000000EB0233C04883C428C3"); Rel(0x10a5, 0x10b8);
        Code(0x10b8, "C3C3C3C3");
        Code(0x10c0, "4883EC2833D2E800000000CC"); Rel(0x10c7, 0x10d0);
        Code(0x10d0, "BA01000000FF1500000000CC"); Rel(0x10d7, 0x3090);
        Code(0x1100, "48895C2408574883EC20488BF9488BDA4883C158E800000000488D4F60E800000000488BD3488BCFE800000000CC");
        Rel(0x1115, 0x1130); Rel(0x111e, 0x1130); Rel(0x1129, 0x10d0);
        Code(0x1130, "48C70100000000C3");
        Encoding.ASCII.GetBytes("IndexOutOfRangeException\0").CopyTo(bytes, 0x780);
        Encoding.ASCII.GetBytes("System\0").CopyTo(bytes, 0x7a0);
        Array.Clear(bytes, 0x700, 0x60);
        (uint Start, uint End)[] ranges = [(0x1000, 0x100a), (0x1010, 0x1024), (0x1030, 0x1089), (0x10d0, 0x10dc), (0x1100, 0x112e)];
        U32(0x124, (uint)ranges.Length * 12);
        for (var i = 0; i < ranges.Length; i++) { U32(0x700 + i * 12, ranges[i].Start); U32(0x704 + i * 12, ranges[i].End); U32(0x708 + i * 12, 0x3140); }
        bytes[0x740] = 1;
        RuntimeHelper[] Identify(byte[] data, bool metadata = true, int offset = 0x58, ulong imageBase = basis)
        {
            var image = ImageDocument.Parse(data);
            var owner = new TypeDef { Index = 0, Assembly = "mscorlib.dll", Namespace = "System", Name = "Exception", Token = 0x02000001,
                Attributes = System.Reflection.TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 128 };
            var fields = new[] { new FieldDef { Index = 0, Owner = owner, Name = "_stackTrace", Type = new DefinitionRef(owner, []), Attributes = 0, Offset = offset },
                new FieldDef { Index = 1, Owner = owner, Name = "_stackTraceString", Type = new DefinitionRef(owner, []), Attributes = 0, Offset = 0x60 } };
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [owner], Fields = fields,
                Methods = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var map = CodeMap.BuildPe(image, []);
            var scan = CodeScan.FromReferences(map, new Dictionary<ulong, CodeRef[]> { [imageBase + 0x1000] = [
                new(imageBase + 0x1000, imageBase + 0x1000, RefKind.Call, 0), new(imageBase + 0x1000, imageBase + 0x1100, RefKind.Call, 0)] });
            return X64RuntimeHelpers.Identify(map, scan, new PcodeMachine(image, decoder), model: metadata ? model : null);
        }
        Check(Identify(bytes).Any(h => h.Address == basis + 0x1000 && h.Kind == HelperKind.Throw && h.Detail == "System.IndexOutOfRangeException"), "栈内空消息默认异常构造");
        Check(Identify(bytes).Any(h => h.Kind == HelperKind.CodegenRaise), "按元数据偏移核实堆栈重置并抛出");
        foreach (var at in new[] { 0x236, 0x240, 0x243, 0x259, 0x261, 0x26c, 0x277, 0x281, 0x780, 0x2d1 })
        {
            var changed = bytes.ToArray(); changed[at] ^= 1;
            Check(Identify(changed).All(h => h.Address != basis + 0x1000), "非空消息、分支、构造链、返回或不返回证据变化必须拒绝");
        }
        foreach (var at in new[] { 0x313, 0x31c, 0x315, 0x31e, 0x329, 0x333, 0x2d1 })
        {
            var changed = bytes.ToArray(); changed[at] ^= 1;
            Check(Identify(changed).All(h => h.Kind != HelperKind.CodegenRaise), "非堆栈写入、非清零操作或错误抛出目标必须拒绝");
        }
        Check(Identify(bytes, false).All(h => h.Kind != HelperKind.CodegenRaise) && Identify(bytes, offset: 0x50).All(h => h.Kind != HelperKind.CodegenRaise), "缺少或不匹配的元数据不得猜测字段");
        var moved = bytes.ToArray(); BinaryPrimitives.WriteUInt64LittleEndian(moved.AsSpan(0xb0), basis + 0x10000000);
        Check(Identify(moved, imageBase: basis + 0x10000000).Count(h => h.Kind is HelperKind.Throw or HelperKind.CodegenRaise) == 2, "异常辅助函数不依赖固定基址");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
