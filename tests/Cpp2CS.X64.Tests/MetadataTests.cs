using Cpp2CS.Facts;
using Cpp2CS.Idioms;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Model;

namespace Cpp2CS.X64.Tests;

internal static class MetadataTests
{
    public static void Run()
    {
        var usages = new UsageSlots
        {
            Slots = new Dictionary<ulong, UsageSlot> { [0x2000] = new(0x2000, new(UsageKind.StringLiteral, 0, "sample"), 1, 0) },
            UnreferencedDecodable = new Dictionary<ulong, Usage>(), SlotAddressBeforeCall = new Dictionary<ulong, int>(),
        };
        var block = new Block(0x1000) { End = 0x1010 };
        block.Statements.AddRange([
            new Call(0x1000, CallKind.Direct, Expr.C(0x3000, 64)),
            new Store(0x1005, Expr.C(0x2100, 64), Expr.C(1, 8)),
            new Return(0x100f) { Pieces = [new(0, new Load(Expr.C(0x2000, 64), 64)),
                new(8, new Load(Expr.C(0x2000, 64), 32)), new(16, new Load(Expr.C(0x2200, 64), 64))] },
        ]);
        var function = new MachineFunction { Entry = 0x1000, Range = new(0x1000, 0x1010, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
        var result = MetadataLoadsPass.Run(function, usages);
        if (result.ReadSlots.Count != 1 || block.Statements[^1] is not Return { Pieces: [
                { Value: Symbol { Kind: SymbolKind.String, Value: "sample" } },
                { Value: Load { Width: 32 } }, { Value: Load }] }
            || !block.Statements.OfType<Call>().Any() || !block.Statements.OfType<Store>().Any())
            throw new InvalidOperationException("元数据槽位改写不得删除初始化副作用或猜测未知读取");
        Console.WriteLine("元数据槽位改写测试通过");
    }
}
