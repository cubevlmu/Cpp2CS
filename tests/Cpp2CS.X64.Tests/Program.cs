using Cpp2CS.Ir;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class Program
{
    private static PcodeVarnode Reg(string name, int size, ulong offset = 0) => new("register", 0, offset, size, name);
    private static PcodeVarnode Const(ulong value, int size = 8) => new("const", 0, value, size, null);
    private static PcodeVarnode Ram(ulong value) => new("ram", 0, value, 8, null);

    private static List<Stmt> Run(params PcodeOperation[] ops)
    {
        var statements = new List<Stmt>();
        PcodeLowerer.Lower(new LiftedInstruction(0x1000, 5, ops), statements);
        return statements;
    }

    private static void Check(bool valid, string reason)
    {
        if (!valid) throw new Exception(reason);
    }

    private static int Main(string[] args)
    {
        if (args is ["windows-eh-image", var image, var schema]) { WindowsEhNativeTests.Run(image, schema); return 0; }
        if (args is ["decoder-concurrency", var specification]) { DecoderConcurrencyTests.Run(specification); return 0; }
        if (args is ["decompile-image", var managedImage, var output])
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(managedImage))!;
            Cpp2CS.Output.SourceProject.Write(managedImage, directory, Path.Combine(output, "src"), _ => true);
            return 0;
        }
        if (args is ["check-source", var sourceOutput, var assemblyName]) { SourceCompilation.Check(sourceOutput, assemblyName); return 0; }
        // 全宽及 32 位写入与 8/16 位部分插入的语义不同。
        var eax = Run(new PcodeOperation(0, 1, "COPY", Reg("EAX", 4), [Const(42, 4)]));
        Check(eax is [Assign { Target: { Bank: Bank.Gpr, Index: 0 }, Value: Cpp2CS.Ir.Const { Value: 42, Width: 32 } }], "EAX write");

        var al = Run(new PcodeOperation(0, 1, "COPY", Reg("AL", 1), [Const(4, 1)]));
        Check(al is [Assign { Target: { Bank: Bank.Gpr, Index: 0 }, Value: Insert { Low: 0 } }], "AL insert");

        var ah = Run(new PcodeOperation(0, 1, "COPY", Reg("AH", 1), [Const(4, 1)]));
        Check(ah is [Assign { Target: { Bank: Bank.Gpr, Index: 0 }, Value: Insert { Low: 8 } }], "AH insert");

        var call = Run(new PcodeOperation(0, 1, "CALL", null, [Ram(0x1234)]));
        Check(call is [Call { Kind: CallKind.Direct, Target: Cpp2CS.Ir.Const { Value: 0x1234 } }], "Direct CALL");

        var store = Run(new PcodeOperation(0, 1, "STORE", null, [Const(1) with { ReferencedSpace = "ram" }, Reg("RSP", 8), Const(0x7F, 1)]));
        Check(store is [Store { Value: Cpp2CS.Ir.Const { Value: 0x7F } }], "STORE has no output");

        var unhandled = Run(new PcodeOperation(0, 1, "CALLOTHER", null, [Const(9)]));
        Check(unhandled is [Opaque], "Unhandled op must be Opaque");

        var internalBranch = Run(new PcodeOperation(0, 1, "BRANCH", null, [Const(2)]));
        Check(internalBranch is [Opaque], "P-code internal branch must not become native jump");

        var rejected = Run(new(0, 1, "COPY", Reg("RAX", 8), [Const(1)]), new(1, 9, "CALLOTHER", null, [Const(9)]));
        Check(rejected is [Opaque], "失败指令不保留部分写入");
        var shift = Run(new PcodeOperation(0, 29, "INT_LEFT", Reg("RAX", 8), [Const(1), Const(64)]));
        var evaluated = new Evaluator();
        evaluated.Run(shift, 0x1000, 0x1005);
        Check(evaluated.Failure is null && evaluated.Get(Storage.Gpr(0)) == 0, "P-code 超宽移位不取模");

        Console.WriteLine("PcodeLowerer smoke tests passed");
        AbiTests.Run();
        MetadataTests.Run();
        SourceIteratorTests.Run();
        if (args is [var sla]) { DecoderConcurrencyTests.Run(sla); NativeTests.Run(sla); HardwareTests.Run(sla); }
        return 0;
    }
}
