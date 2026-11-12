using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;

namespace Cpp2CS.Machine.Flow;

using Storage = Cpp2CS.Ir.Storage;

/// <summary>FH4 的状态、包装捕获和原生清理先归一化为公共异常边，再进入 SSA。</summary>
internal sealed class WindowsEhPlan
{
    private const ulong Synthetic = 1UL << 61;
    internal sealed record Pad(ulong Address, int State, WindowsCatchRegion? Catch,
        WindowsCatchHandler? Handler, IReadOnlyList<Store> Transfers, IReadOnlyList<WindowsUnwindAction> Cleanup,
        bool NativeFunclet = false, ulong ExceptionalDestination = 0, bool Terminates = false);
    internal required CodeFunction Range { get; init; }
    internal required WindowsEhAnalysis Analysis { get; init; }
    internal required long Frame { get; init; }
    internal required IReadOnlyList<Pad> Pads { get; init; }
    internal IReadOnlyList<ulong> Roots => Pads.Where(p => p.Handler is not null).Select(p => p.Handler!.Continuations[0]).Distinct().ToArray();
    internal IReadOnlySet<ulong> CleanupTargets => Pads.SelectMany(p => p.Cleanup).Where(a => a.Kind == 1).Select(a => a.Action!.Value).ToHashSet();
    internal IReadOnlySet<ulong> FuncletTargets => Pads.Where(p => p.NativeFunclet).Select(p => p.Handler!.Entry).ToHashSet();

    internal static WindowsEhPlan? Create(CfgBuilder cfg, CodeFunction range, out string reason)
    {
        var machine = cfg.Machine; var code = cfg.Functions;
        reason = "fh4-owner-layout-unsupported";
        if (range.WindowsRange is not { Handler: { } handler, HasSeparatedFragments: false,
            WindowsUnwind: { Version: 1, FrameRegister: 0 } unwind } native) return null;
        var analysis = WindowsEhReader.Read(machine.Image, native);
        if (analysis is not { HandlerKind: WindowsHandlerKind.Cxx4, MetadataStatus: "parsed", CxxHeader: 40 or 56 or 96 or 104 }) return null;
        var noExcept = (analysis.CxxHeader.Value & 64) != 0;
        if (!WindowsFh4RuntimeProof.Matches(machine.Image, handler, out reason)) return null;
        if (!FrameSize(machine, range, unwind, out var frame)) { reason = "fh4-parent-frame-not-proven"; return null; }
        var pads = new List<Pad>();
        var catches = new Dictionary<WindowsCatchRegion, (WindowsCatchHandler Handler, IReadOnlyList<Store> Transfers, bool Native)>();
        foreach (var region in analysis.CatchRegions)
        {
            reason = "fh4-catch-wrapper-or-continuation-unsupported";
            if (region.Handlers is not [var caught] || caught.NativeTypeName != ".?AUIl2CppExceptionWrapper@@"
                || caught.Adjectives != 8 || caught.Continuations is not [var continuation]
                || !range.Contains(continuation) || caught.ObjectOffset is not { } objectOffset || caught.FrameOffset is not null) return null;
            if (caught.TypeDescriptor is not { } descriptor || !WindowsExceptionObjectProof.IsKnownWrapperDescriptor(machine.Image, descriptor))
            { reason = "fh4-wrapper-type-binding-not-proven"; return null; }
            var simple = Transfers(machine, code, caught.Entry, frame, objectOffset, out var transfers);
            if (!simple && !Funclet(cfg, caught)) { reason = "fh4-funclet-control-or-entry-not-proven"; return null; }
            catches.Add(region, (caught, simple ? transfers : [], !simple));
        }
        var actions = analysis.UnwindActions.ToDictionary(a => a.State);
        var byState = new Dictionary<int, Pad>();
        var active = new HashSet<int>();
        Pad? Destination(int state)
        {
            if (byState.TryGetValue(state, out var known)) return known;
            if (!active.Add(state)) return null;
            var catcher = analysis.CatchRegions.Where(c => state >= c.Low && state <= c.High)
                .OrderBy(c => c.High - c.Low).FirstOrDefault();
            var targetState = catcher is null ? -1 : (int)catcher.Low;
            var cleanups = new List<WindowsUnwindAction>();
            var seen = new HashSet<int>();
            for (var current = state; current > targetState;)
            {
                if (!seen.Add(current) || !actions.TryGetValue(current, out var action)) return null;
                if (action.Kind != 0)
                {
                    if (action.Action is not { } entry) return null;
                    if (action.Kind == 3)
                    {
                        if (!WindowsFh4RuntimeProof.CleanupBoundary(machine.Image, entry, out var returns) || returns) return null;
                    }
                    else if (action.Kind != 1 || action.ObjectOffset is null
                        || code.At(entry) is not { Start: var start } cleanup || start != entry
                        || cleanup.HasUnmodeledExceptions && cfg.WindowsExceptionProblem(entry) is not null) return null;
                    cleanups.Add(action);
                }
                if (action.NextState >= current) return null;
                current = action.NextState;
                if (current < targetState) return null;
            }
            if (catcher is null && cleanups.Count == 0 && !noExcept)
            {
                active.Remove(state);
                return byState[state] = new(0, state, null, null, [], []);
            }
            var binding = catcher is null ? default : catches[catcher];
            var exceptionDestination = 0UL;
            if (binding.Native)
            {
                if (Destination((int)catcher!.CatchHigh) is not { } destination) return null;
                exceptionDestination = destination.Address;
            }
            var address = Synthetic | ((ulong)pads.Count << 40) | range.Start;
            var pad = new Pad(address, state, catcher, binding.Handler, binding.Transfers ?? [], cleanups, binding.Native, exceptionDestination,
                Terminates: catcher is null && noExcept);
            pads.Add(pad);
            active.Remove(state); byState[state] = pad;
            return pad;
        }
        var regions = new List<ExceptionRegion>();
        var ips = analysis.IpStates.OrderBy(p => p.Address).ToArray();
        foreach (var (ip, i) in ips.Select((p, i) => (p, i)))
        {
            if (ip.State < 0 && !noExcept || ip.Address >= range.End) continue;
            if (!byState.TryGetValue(ip.State, out var pad))
            {
                if (Destination(ip.State) is not { } destination) { reason = "fh4-unwind-state-chain-unsupported"; return null; }
                byState[ip.State] = pad = destination;
            }
            var end = i + 1 < ips.Length ? Math.Min(ips[i + 1].Address, range.End) : range.End;
            if (pad.Address != 0 && ip.Address < end) regions.Add(new(ip.Address, end, pad.Address));
        }
        reason = "fh4-wrapper-catch-cleanup-and-parent-frame";
        return new() { Range = range with { ExceptionRegions = regions.ToArray(), HasUnmodeledExceptions = false }, Analysis = analysis,
            Frame = frame, Pads = pads };
    }

    internal void Attach(MachineFunction function, CfgBuilder cfg)
    {
        var blocks = function.Blocks.ToDictionary(b => b.Start);
        var temporary = 30000;
        var auxiliary = 0UL;
        Block Auxiliary(bool landing = false)
        {
            var address = Synthetic | (1UL << 59) | (auxiliary++ << 40) | function.Entry;
            var block = new Block(address) { End = address + 1, IsLandingPad = landing };
            function.Blocks.Add(block); blocks.Add(address, block); return block;
        }
        Block? termination = null;
        foreach (var plan in Pads)
        {
            var pad = new Block(plan.Address) { End = plan.Address + 1, IsLandingPad = true };
            function.Blocks.Add(pad); blocks.Add(pad.Start, pad);
            var current = pad;
            var terminated = false;
            // 展开后的栈与普通返回后的调用结果不同；父帧位置由 UNWIND_INFO 和真实 prolog 共同核对。
            pad.Statements.Add(new Assign(pad.Start, cfg.Machine.Convention.StackPointer,
                new StackAllocation(pad.Start, new PrimitiveRef("byte"))));
            foreach (var action in plan.Cleanup)
            {
                if (action.Kind == 3)
                {
                    // 独立 CRT 已证明的终止动作没有续接；不把它当作对象析构调用。
                    current.Statements.Add(new Call(current.Start, CallKind.Direct, Expr.C(action.Action!.Value, 64))
                    { Op = new(OpKind.Terminate, null), DoesNotReturn = true });
                    terminated = true;
                    break;
                }
                current.Statements.Add(new Assign(current.Start, Storage.Gpr(1), new FrameAddress(Frame + action.ObjectOffset!.Value)));
                current.Statements.Add(new Call(current.Start, CallKind.Direct, Expr.C(action.Action!.Value, 64)));
                if (termination is null)
                {
                    termination = Auxiliary(landing: true);
                    termination.Statements.Add(new Call(termination.Start, CallKind.Direct, Expr.C(0, 64)) { Op = new(OpKind.Terminate, null) });
                }
                var next = Auxiliary(); MachineFunction.AddEdge(current, next);
                // MSVC 的展开过滤器终止再次抛出的 C++ 异常；后续沿用公共管线对这类运行时落地块的归一策略。
                current.Handler = termination; current.Successors.Add(termination); termination.Predecessors.Add(current);
                current = next;
            }
            if (!terminated && plan.Terminates)
            {
                // noexcept 的无状态区间也会终止；有展开动作时先保留其真实清理顺序。
                current.Statements.Add(new Call(current.Start, CallKind.Direct, Expr.C(0, 64))
                { Op = new(OpKind.Terminate, null), DoesNotReturn = true });
                terminated = true;
            }
            if (!terminated && plan.Handler is { } handler)
            {
                var result = Storage.Temp(temporary++);
                current.Statements.Add(new Call(current.Start, CallKind.Direct, Expr.C(0, 64))
                { Op = new(OpKind.BeginCatch, null), Arguments = [new Intrinsic("eh_exception", [], 64)], Results = [result] });
                if (plan.NativeFunclet)
                {
                    current.Statements.Add(new Store(current.Start, new FrameAddress(Frame + handler.ObjectOffset!.Value), new Read(result, 64)));
                    current.Statements.Add(new Assign(current.Start, Storage.Gpr(2), new FrameAddress(Frame)));
                    current.Statements.Add(new Call(current.Start, CallKind.Direct, Expr.C(handler.Entry, 64)));
                    var next = Auxiliary(); MachineFunction.AddEdge(current, next);
                    if (plan.ExceptionalDestination != 0)
                    {
                        var escaped = blocks[plan.ExceptionalDestination];
                        current.Handler = escaped; current.Successors.Add(escaped); escaped.Predecessors.Add(current);
                    }
                    current = next;
                    foreach (var storage in cfg.Machine.Convention.Clobbered.Where(s => s.Bank is Bank.Gpr or Bank.Vec))
                        current.Statements.Add(new Assign(current.Start, storage, new Unknown("fh4-continuation-register", storage.Width)));
                }
                foreach (var transfer in plan.Transfers)
                    current.Statements.Add(transfer with { Value = ExprMap.Map(transfer.Value, e =>
                        e is Intrinsic { Name: "fh4_caught_object" } ? new Load(new Read(result, 64), 64) : null) });
                // 续接代码在原函数执行，恢复父帧 SP；保留异常边上的未定义易失寄存器。
                current.Statements.Add(new Assign(current.Start, cfg.Machine.Convention.StackPointer, new FrameAddress(Frame)));
                var continuation = blocks[handler.Continuations[0]];
                current.Statements.Add(new Jump(current.Start, continuation.Start));
                MachineFunction.AddEdge(current, continuation);
            }
            else if (!terminated) current.Statements.Add(new Call(current.Start, CallKind.Direct, Expr.C(0, 64))
                { Op = new(OpKind.ResumeUnwind, null), Arguments = [new Intrinsic("eh_exception", [], 64)] });
            function.NativeExpansions.Add(new(function.Entry, plan.Address,
                plan.Handler?.Entry ?? plan.Cleanup.FirstOrDefault()?.Action ?? Range.WindowsRange!.Handler!.Value, "win64-fh4-state"));
        }
        foreach (var block in function.Blocks.ToArray())
        {
            if (block.IsLandingPad || block.Statements.LastOrDefault() is not Call call) continue;
            var region = Range.ExceptionRegions.FirstOrDefault(r => call.Address >= r.Start && call.Address < r.End);
            if (region is null || !blocks.TryGetValue(region.LandingPad, out var pad)) continue;
            block.Handler = pad; block.Successors.Add(pad); pad.Predecessors.Add(block);
        }
        // 清理体具有已核对的 EH 归属；展开为普通原生语句，真实调用和写入继续接受公共恢复检查。
        var preserved = new HashSet<Storage>(new[] { 3, 5, 6, 7, 12, 13, 14, 15 }.Select(Storage.Gpr)
            .Concat(Enumerable.Range(6, 10).Select(Storage.Vec)));
        new ClosureInlining(cfg, _ => false, entry => CleanupTargets.Contains(entry) || FuncletTargets.Contains(entry), Storage.Gpr(1),
            cfg.Machine.Convention.StackPointer, Storage.Gpr(5), preserved, maxDepth: 1).Run(function);
        function.Renumber();
    }

    private static bool Funclet(CfgBuilder cfg, WindowsCatchHandler handler)
    {
        if (cfg.Functions.At(handler.Entry) is not { Start: var start, HasUnmodeledExceptions: false, Size: > 0 and <= 1024 }
            || start != handler.Entry) return false;
        var function = cfg.Build(handler.Entry);
        if (function.Problems.Count != 0 || function.Blocks.Count > 64 || function.Blocks.SelectMany(b => b.Statements)
            .Any(s => s is Opaque or IndirectJump or Trap || s is Call { Kind: CallKind.Tail or CallKind.TailIndirect })) return false;
        bool ValidReturn(Block block, int before, HashSet<Block> path)
        {
            if (!path.Add(block)) return false;
            for (var i = before - 1; i >= 0; i--)
            {
                if (block.Statements[i] is Assign { Target: var target } assign && target == Storage.Gpr(0))
                    return Fold.Simplify(assign.Value) is Const value && (value.Value == 0 || value.Value == handler.Continuations[0]);
                if (block.Statements[i] is Call) return false;
            }
            return block.Predecessors.Count > 0 && block.Predecessors.All(p => ValidReturn(p, p.Statements.Count, new(path)));
        }
        var returns = function.Blocks.Where(b => b.Statements.LastOrDefault() is Return).ToArray();
        return returns.Length > 0 && returns.All(b => ValidReturn(b, b.Statements.Count - 1, []));
    }

    private static bool FrameSize(IMachine machine, CodeFunction range, WindowsUnwindRecord unwind, out long frame)
    {
        frame = 0;
        var values = new Dictionary<Storage, Expr> { [machine.Convention.StackPointer] = new FrameAddress(0) };
        for (var pc = range.Start; pc < range.Start + unwind.PrologLength;)
        {
            var statements = new List<Stmt>(); var size = machine.Lift(pc, statements);
            if (size <= 0 || pc + (ulong)size > range.Start + unwind.PrologLength) return false;
            foreach (var statement in statements)
            {
                if (statement is Assign assign) values[assign.Target] = Expand(assign.Value, values);
                else if (statement is not Store) return false;
            }
            pc += (ulong)size;
        }
        if (values.GetValueOrDefault(machine.Convention.StackPointer) is not FrameAddress stack) return false;
        long allocated = 0;
        var codes = unwind.Codes;
        for (var i = 0; i < codes.Length; i += 2)
        {
            if (i + 1 >= codes.Length) return false;
            var op = codes[i + 1] & 15; var info = codes[i + 1] >> 4;
            switch (op)
            {
                case 0: allocated += 8; break;
                case 1 when info == 0 && i + 3 < codes.Length: allocated += System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(codes.AsSpan(i + 2)) * 8L; i += 2; break;
                case 1 when info == 1 && i + 5 < codes.Length: allocated += System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(codes.AsSpan(i + 2)); i += 4; break;
                case 2: allocated += info * 8 + 8; break;
                case 4 or 8: i += 2; if (i >= codes.Length) return false; break;
                case 5 or 9: i += 4; if (i >= codes.Length) return false; break;
                default: return false;
            }
        }
        frame = stack.Offset;
        return frame == -allocated;
    }

    private static bool Transfers(IMachine machine, CodeMap code, ulong entry, long frame, long objectOffset, out IReadOnlyList<Store> transfers)
    {
        var output = new List<Store>(); transfers = output;
        if (code.At(entry) is not { Start: var start, Size: > 0 and <= 256 } range || start != entry) return false;
        var values = new Dictionary<Storage, Expr> { [Storage.Gpr(2)] = new FrameAddress(frame),
            [machine.Convention.StackPointer] = new Intrinsic("fh4_funclet_stack", [], 64) };
        for (var pc = entry; pc < range.End;)
        {
            var statements = new List<Stmt>(); var size = machine.Lift(pc, statements);
            if (size <= 0 || pc + (ulong)size > range.End) return false;
            foreach (var statement in statements)
            {
                switch (statement)
                {
                    case Assign assign:
                        var value = Expand(assign.Value, values);
                        value = ExprMap.Map(value, e => e is Load { Width: 64, Address: FrameAddress slot } && slot.Offset == frame + objectOffset
                            ? new Intrinsic("fh4_wrapper", [], 64) : e is Load { Width: 64, Address: Intrinsic { Name: "fh4_wrapper" } }
                                ? new Intrinsic("fh4_caught_object", [], 64) : null);
                        values[assign.Target] = Fold.Simplify(value); break;
                    case Store store:
                        var target = Expand(store.Target, values); var stored = Expand(store.Value, values);
                        if (ExprMap.Walk(target).Any(e => e is Intrinsic { Name: "fh4_funclet_stack" })) break;
                        if (target is not FrameAddress location || location.Offset < frame || location.Offset + 8 > 8
                            || stored is not Intrinsic { Name: "fh4_caught_object" }) return false;
                        output.Add(store with { Target = target, Value = stored }); break;
                    case Return:
                        return values.GetValueOrDefault(Storage.Gpr(0)) is Const { Value: 0 } && output.Count > 0;
                    default: return false;
                }
            }
            pc += (ulong)size;
        }
        return false;
    }

    private static Expr Expand(Expr value, Dictionary<Storage, Expr> values)
    {
        var expanded = Fold.Simplify(ExprMap.Map(value, e => e is Read read && values.TryGetValue(read.Storage, out var definition)
            ? definition.Width == read.Width ? definition : Fold.Convert(ConvKind.Truncate, definition, read.Width) : null));
        return ExprMap.Map(expanded, e => e is Binary { Op: BinOp.Add or BinOp.Sub, Left: FrameAddress frame, Right: Const offset } binary
            ? new FrameAddress(unchecked(frame.Offset + (binary.Op == BinOp.Add ? (long)offset.Value : -(long)offset.Value))) : null);
    }
}
