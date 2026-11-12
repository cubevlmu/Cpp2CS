using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class VectorConstantTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000, low = 0x0123456789abcdef, high = 0xfedcba9876543210;
        foreach (var address in new[] { 0x31c0, 0x3088, 0x31f8, 0x2000, 0x1100 })
        {
            var bytes = original.ToArray();
            System.Convert.FromHexString("0F100500000000C3").CopyTo(bytes, 0x200);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x203), address - 0x1007);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x7c0), low);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x7c8), high);
            var image = ImageDocument.Parse(bytes);
            var map = CodeMap.BuildPe(image, []);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [], Fields = [], Methods = [],
                RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var facts = new BaseFacts { Model = model, Code = map, Scan = CodeScan.Unscanned(map), Layouts = new FieldLayouts(model),
                MachineFactory = () => new PcodeMachine(image, decoder) };
            var lifted = new FunctionLifter(facts).Lift(basis + 0x1000, new Read(new Storage(Bank.Vec, 0), 128));
            Check(lifted.Errors.Count == 0, "向量常量提升保持 SSA");
            var nodes = lifted.Function.Blocks.SelectMany(b => b.Statements).SelectMany(ExprMap.Operands).SelectMany(ExprMap.Walk).ToArray();
            if (address == 0x31c0)
                Check(!nodes.OfType<Load>().Any() && nodes.OfType<Const>().Any(c => c.Value == low)
                    && nodes.OfType<Const>().Any(c => c.Value == high), "128 位读取保留两个不同的完整 64 位分量");
            else Check(nodes.OfType<Load>().Any(), "IAT 重叠、跨节、可写或代码位置不得折叠向量读取");
        }
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}
