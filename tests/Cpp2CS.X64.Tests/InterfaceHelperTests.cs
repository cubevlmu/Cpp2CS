using System.Buffers.Binary;
using System.Text;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Idioms;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class InterfaceHelperTests
{
    internal static void Run(byte[] original, BaseFacts basisFacts)
    {
        var bytes = original.ToArray();
        const ulong basis = 0x180000000;
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        void Relative(int at, int target) => BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(at), target - (at + 0xe00) - 4);
        Array.Clear(bytes, 0x200, 0x400);
        U32(0x108, 0x2000); U32(0x10c, 0x200);
        U32(0x414, 1); U32(0x418, 1); U32(0x41c, 0x2040); U32(0x420, 0x2044); U32(0x424, 0x2048);
        U32(0x440, 0x1000); U32(0x444, 0x2060);
        Encoding.ASCII.GetBytes("il2cpp_object_get_virtual_method\0").CopyTo(bytes, 0x460);
        System.Convert.FromHexString("40534883EC20F6424C20488BDA4C8BD90F85CC000000F6424C400F84C2000000488B522048897C2430F68218010000207520807A2A13741A807A2A1E74140FB74B50498B034883C1144803C9488B3CC8EB434C8B1133C90FB77B50450FB7822E01000066413BC8731C4D8B8AB00000000FB7C14803C0493914C1743A66FFC166413BC872EB440FB7C7498BCBE800000000488B7808").CopyTo(bytes, 0x200);
        Relative(0x28d, 0x1100); bytes[0x2e2] = 0xc3; bytes[0x300] = 0xc3;
        U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, 0x10e3); U32(0x708, 0x3140);
        U32(0x70c, 0x1100); U32(0x710, 0x1101); U32(0x714, 0x3140); bytes[0x740] = 1; U32(0x744, 0x1100);
        RuntimeHelper? Identify(byte[] data, int? vtable = 0x138)
        {
            var image = ImageDocument.Parse(data);
            var map = CodeMap.BuildPe(image, []);
            return X64InterfaceHelpers.Identify(map, CodeScan.Unscanned(map), new(null, null, "测试布局") { MethodClass = 0x20, ClassVtable = vtable });
        }
        Check(Identify(bytes) is { Kind: HelperKind.InterfaceLookup, Address: basis + 0x1100 }, "接口慢路径由虚方法查找导出的扫描和参数转发指名");
        foreach (var at in new[] { 0x223, 0x25a, 0x25f, 0x26c, 0x276, 0x27c, 0x285, 0x28a, 0x28d, 0x293, 0x212, 0x21c, 0x740 })
        {
            var changed = bytes.ToArray(); changed[at] ^= (byte)(at == 0x740 ? 8 : 1);
            Check(Identify(changed) is null, "声明类/槽、计数/偏移表、循环、参数、返回用法、控制流或异常边变化时拒绝");
        }
        Check(Identify(bytes, null) is null && Identify(bytes, 0x180) is null, "未知或不匹配的运行时布局不识别");
        var moved = bytes.ToArray(); BinaryPrimitives.WriteUInt64LittleEndian(moved.AsSpan(0xb0), basis + 0x10000000);
        Check(Identify(moved)?.Address == basis + 0x10001100, "识别不依赖固定映像基址");
        RewriteChecks(basisFacts, basis);
    }

    private static void RewriteChecks(BaseFacts basisFacts, ulong basis)
    {
        var type = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Interface", Token = 0x02000001,
            Attributes = System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Interface, IsValueType = false, IsEnum = false, Size = 16 };
        var facts = basisFacts with { Helpers = RuntimeHelpers.FromEvidence(basisFacts.Code, basisFacts.Scan,
            [new(basis + 0x1010, HelperKind.InterfaceLookup, null, "独立测试契约", 1)]) };
        foreach (var used in new[] { false, true })
        foreach (var upperUnknown in new[] { false, true })
        {
            var result = new Variable(Storage.Gpr(0), 1);
            var block = new Block(basis + 0x1000) { End = basis + 0x1008 };
            block.Statements.Add(new Call(block.Start, CallKind.Direct, Expr.C(basis + 0x1010, 64)) {
                Arguments = [Expr.C(1, 64), new Symbol(SymbolKind.Class, new DefinitionRef(type, [])),
                    upperUnknown ? new Insert(new Unknown("未设置的槽参数高位", 64), Expr.C(0, 16), 0) : Expr.C(0, 32)],
                Sources = [Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8)], Results = [Storage.Gpr(0)], Defines = [result] });
            if (used) block.Statements.Add(new Call(block.Start + 1, CallKind.Indirect, new Load(new Use(result, 64), 64)));
            block.Statements.Add(new Return(block.Start + 2));
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            function.Renumber();
            new IdiomRewriter(facts).Run(function);
            Check(block.Statements.OfType<Call>().First().Op?.Kind == (used ? OpKind.InterfaceInvokeData : null),
                "只有分派使用中的接口查找归一；未使用结果的调用保留原有效果");
        }
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
