using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Machine.Lifting;

using Storage = Cpp2CS.Ir.Storage;

/// <summary>无托管身份的短原生体展开后交给公共恢复层；保留实际栈、寄存器及内存效果。</summary>
internal sealed class NativeBodyInlining(ProgramFacts facts, CfgBuilder cfg, FactsCallModel calls)
{
    private readonly Dictionary<ulong, bool> bodies = [];

    internal void Run(MachineFunction function)
    {
        var convention = cfg.Machine.Convention;
        new ClosureInlining(cfg, _ => false, Body, convention.IntegerArguments[0], convention.StackPointer,
            Storage.Gpr(5), new HashSet<Storage>(), nativeCallStack: true, maxDepth: 1, maxBlocks: 128).Run(function);
    }

    private bool Body(ulong entry)
    {
        if (bodies.TryGetValue(entry, out var known)) return known;
        bodies[entry] = false;
        if (facts.Registrations.At(entry).Length != 0 || facts.Helpers.At(entry) is { Kind: not HelperKind.Unknown }
            || facts.NativeInterfaceInvokes.Matches(entry)
            || facts.Code.At(entry) is not { Start: var start, Size: > 0 and <= 512, HasUnmodeledExceptions: false,
                ExceptionRegions.Length: 0 } || start != entry
            || calls.Signature(entry) is { Source: not "proven-native-straight-line" }) return false;
        var function = cfg.Build(entry);
        if (function.Problems.Count != 0 || function.Blocks.Count > 32
            || function.Blocks.Any(b => b.Handler is not null || b.IsLandingPad)
            || function.Blocks.SelectMany(b => b.Statements).Any(s => s is Opaque or IndirectJump or Trap
                || s is Call c && (c.Kind is not (CallKind.Direct or CallKind.Tail or CallKind.TailIndirect)
                    || c.Kind != CallKind.TailIndirect && (c.Target is not Const target || target.Value == entry)))) return false;
        return bodies[entry] = BalancedStack(function);
    }

    // 各块入口必须有唯一的固定 SP 偏移，正常返回时回到原生入口 SP；动态栈及冲突合流保留调用。
    private bool BalancedStack(MachineFunction function)
    {
        var stack = cfg.Machine.Convention.StackPointer;
        var offsets = new Dictionary<Block, long> { [function.EntryBlock] = 0 };
        var work = new Queue<Block>();
        work.Enqueue(function.EntryBlock);
        var returned = false;
        while (work.TryDequeue(out var block))
        {
            var offset = offsets[block];
            foreach (var statement in block.Statements)
            {
                if (statement is Assign a && a.Target == stack)
                {
                    if (a.Value is not Binary { Width: 64, Op: BinOp.Add or BinOp.Sub, Left: Read read, Right: Const value } binary
                        || read.Storage != stack || read.Width != 64 || value.Width != 64) return false;
                    var delta = unchecked((long)value.Value);
                    if (delta is < -65536 or > 65536) return false;
                    offset += binary.Op == BinOp.Add ? delta : -delta;
                    if (offset is < -65536 or > 0) return false;
                }
                if (statement is Return or Call { Kind: CallKind.Tail or CallKind.TailIndirect })
                {
                    if (offset != 0) return false;
                    returned = true;
                }
            }
            foreach (var successor in block.NormalSuccessors)
            {
                if (offsets.TryGetValue(successor, out var prior))
                {
                    if (prior != offset) return false;
                }
                else { offsets.Add(successor, offset); work.Enqueue(successor); }
            }
        }
        return returned;
    }
}
