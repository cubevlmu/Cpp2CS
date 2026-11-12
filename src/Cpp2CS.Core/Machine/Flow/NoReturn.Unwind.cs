using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;

namespace Cpp2CS.Machine.Flow;

using Storage = Cpp2CS.Ir.Storage;

public sealed partial class NoReturnOracle
{
    private enum CleanupControl { Unknown, ReturnsToDispatcher, Terminates }
    private readonly Dictionary<ulong, bool> unwindControl = [];
    private readonly Dictionary<ulong, CleanupControl> cleanupControl = [];
    private readonly HashSet<ulong> activeUnwind = [];
    private readonly HashSet<ulong> activeCleanup = [];

    private bool UnwindCannotResume(CodeFunction range)
    {
        if (unwindControl.TryGetValue(range.Start, out var known)) return known;
        if (activeUnwind.Count >= MaxDepth || !activeUnwind.Add(range.Start)) return false;
        var proven = Check();
        activeUnwind.Remove(range.Start);
        // 递归产生的失败不缓存，避免把临时假设传播给其他入口。
        if (proven) unwindControl[range.Start] = true;
        return proven;

        bool Check()
        {
            if (range.WindowsRange is not { HasSeparatedFragments: false, Handler: not null } native) return false;
            var analysis = WindowsEhReader.Read(machine.Image, native);
            if (analysis is not { MetadataStatus: "parsed", RuntimeContract: "msvc-fh4-runtime-contract",
                CxxHeader: 40 or 104, CatchRegions.Count: 0, Scopes.Count: 0 }) return false;
            foreach (var action in analysis.UnwindActions)
            {
                if (action.NextState >= action.State) return false;
                if (action.Kind == 0) continue;
                if (action.Kind is not (1 or 3) || action.Action is not { } target
                    || CleanupCannotEscape(target) == CleanupControl.Unknown) return false;
            }
            return true;
        }
    }

    // Return 只表示回到调用清理体的分派器；longjmp、回调、未知间接转移和可达陷阱均不能证明。
    private CleanupControl CleanupCannotEscape(ulong entry)
    {
        if (cleanupControl.TryGetValue(entry, out var known)) return known;
        if (activeCleanup.Count >= MaxDepth || !activeCleanup.Add(entry)) return CleanupControl.Unknown;
        var control = Check();
        activeCleanup.Remove(entry);
        if (control != CleanupControl.Unknown) cleanupControl[entry] = control;
        return control;

        CleanupControl Check()
        {
            if (WindowsFh4RuntimeProof.CleanupBoundary(machine.Image, entry, out var returns))
                return returns ? CleanupControl.ReturnsToDispatcher : CleanupControl.Terminates;
            if (functions.At(entry) is not { } range || range.Start != entry || range.Size > 4096
                || range.HasUnmodeledExceptions && !UnwindCannotResume(range)) return CleanupControl.Unknown;
            var visited = new Dictionary<ulong, long>();
            var pending = new Stack<(ulong Address, long Stack)>(); pending.Push((entry, 0));
            var hasReturn = false;
            while (pending.TryPop(out var work))
            {
                var address = work.Address; var stackOffset = work.Stack;
                if (!range.Contains(address) || visited.Count >= 4096) return CleanupControl.Unknown;
                if (visited.TryGetValue(address, out var prior))
                { if (prior != stackOffset) return CleanupControl.Unknown; continue; }
                visited.Add(address, stackOffset);
                var statements = new List<Stmt>();
                var size = machine.Lift(address, statements);
                if (size <= 0 || (ulong)size > range.End - address || statements.Any(s => s is Opaque or Trap))
                    return CleanupControl.Unknown;
                // 清理体的 ret 必须回到自己的调用记录；禁止动态换栈及覆盖返回地址。
                var local = new Dictionary<Storage, Expr> { [machine.Convention.StackPointer] = new FrameAddress(stackOffset) };
                Expr Resolve(Expr expression) => Fold.Simplify(ExprMap.Map(expression,
                    node => node is Read read && local.TryGetValue(read.Storage, out var value) ? value : null));
                foreach (var statement in statements)
                {
                    if (statement is Assign assign)
                    {
                        var value = Resolve(assign.Value);
                        local[assign.Target] = value;
                        if (assign.Target != machine.Convention.StackPointer) continue;
                        if (value is not FrameAddress frame) return CleanupControl.Unknown;
                        stackOffset = frame.Offset;
                    }
                    else if (statement is Store store && Resolve(store.Target) is FrameAddress slot
                        && slot.Offset < 8 && slot.Offset + (store.Value.Width + 7) / 8 > 0) return CleanupControl.Unknown;
                }
                var next = address + (ulong)size;
                void Push(ulong target) => pending.Push((target, stackOffset));
                switch (statements.LastOrDefault())
                {
                    case Return:
                        if (stackOffset != 0) return CleanupControl.Unknown;
                        hasReturn = true; break;
                    case Jump jump when range.Contains(jump.Target): Push(jump.Target); break;
                    case Jump jump:
                        if (stackOffset != 0) return CleanupControl.Unknown;
                        var tail = CleanupCannotEscape(jump.Target);
                        if (tail == CleanupControl.Unknown) return tail;
                        hasReturn |= tail == CleanupControl.ReturnsToDispatcher;
                        break;
                    case Branch branch:
                        if (!range.Contains(branch.Target)) return CleanupControl.Unknown;
                        Push(branch.Target); Push(next); break;
                    case IndirectJump: return CleanupControl.Unknown;
                    case Call call:
                        if (call.Op?.Kind == OpKind.MemoryBarrier) { Push(next); break; }
                        if (call is not { Target: Const target, Kind: CallKind.Direct or CallKind.Tail }) return CleanupControl.Unknown;
                        var called = CleanupCannotEscape(target.Value);
                        if (called == CleanupControl.Unknown) return called;
                        if (call.Kind == CallKind.Tail)
                        {
                            if (stackOffset != 0) return CleanupControl.Unknown;
                            hasReturn |= called == CleanupControl.ReturnsToDispatcher;
                        }
                        else if (called != CleanupControl.Terminates) Push(next);
                        break;
                    default: Push(next); break;
                }
            }
            return hasReturn ? CleanupControl.ReturnsToDispatcher : CleanupControl.Terminates;
        }
    }
}
