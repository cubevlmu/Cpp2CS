using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Machine.Lifting;

using Storage = Cpp2CS.Ir.Storage;

/// <summary>运行时短跳板保留实际寄存器转换，再调用已有独立契约的目标；不把转换包装标成同 ABI 别名。</summary>
internal sealed class RuntimeForwarding(ProgramFacts facts, IMachine machine)
{
    private sealed record Forwarded(Stmt[] Prefix, ulong Target);
    private readonly Dictionary<ulong, Forwarded?> bodies = [];

    internal int Run(MachineFunction function)
    {
        var count = 0;
        foreach (var block in function.Blocks)
        {
            if (block.Handler is not null || block.IsLandingPad) continue;
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Call { Kind: CallKind.Direct, Op: null, Arguments.Length: 0, Results.Length: 0, Target: Const target } call
                    || target.Value == function.Entry) continue;
                if (facts.NativeRuntimeAliases.At(target.Value) is { } runtime)
                {
                    block.Statements[i] = call with { Target = Expr.C(runtime.Method.Address, 64), Resolved = runtime };
                    function.NativeExpansions.Add(new(function.Entry, call.Address, target.Value, "native-runtime-tail-alias"));
                    count++;
                    continue;
                }
                if (Body(target.Value) is not { } forwarded) continue;
                block.Statements[i] = call with { Target = Expr.C(forwarded.Target, 64) };
                block.Statements.InsertRange(i, forwarded.Prefix);
                i += forwarded.Prefix.Length;
                count++;
            }
        }
        return count;
    }

    private Forwarded? Body(ulong entry)
    {
        if (bodies.TryGetValue(entry, out var known)) return known;
        bodies[entry] = null;
        if (facts.Code.RegionOf(entry) == CodeRegion.Managed || facts.Code.At(entry) is { HasUnmodeledExceptions: true }
            || facts.Helpers.At(entry) is { Kind: not HelperKind.Unknown }) return null;
        var prefix = new List<Stmt>();
        var section = machine.Image.SectionAt(entry);
        if (section is not { Executable: true }) return null;
        var end = Math.Min(entry + 48, section.Address + section.Size);
        if (facts.Code.At(entry) is { } range) end = Math.Min(end, range.End);
        for (var pc = entry; pc < end;)
        {
            var statements = new List<Stmt>();
            var length = machine.Lift(pc, statements);
            if (length <= 0 || (ulong)length > end - pc) return null;
            pc += (ulong)length;
            foreach (var statement in statements)
            {
                if (statement is Jump jump && statements[^1] == statement && jump.Target != entry
                    && facts.Helpers.At(jump.Target) is { Kind: not HelperKind.Unknown })
                    return bodies[entry] = new(prefix.ToArray(), jump.Target);
                // 整数参数的截断/扩展只改写实际易失 GPR，不引入临时变量或内存效果。
                if (statement is not Assign { Target.Bank: Bank.Gpr } assign || !machine.Convention.Clobbered.Contains(assign.Target)
                    || !Conversion(assign.Value)) return null;
                prefix.Add(assign);
            }
        }
        return null;
    }

    private static bool Conversion(Expr value) => value switch {
        Const => true,
        Read { Storage.Bank: Bank.Gpr, Storage.Index: not 4 } => true,
        Cpp2CS.Ir.Convert { Kind: ConvKind.ZeroExtend or ConvKind.SignExtend or ConvKind.Truncate } c => Conversion(c.Operand),
        Extract x => Conversion(x.Operand),
        _ => false,
    };
}
