using Cpp2CS.Ir;

namespace Cpp2CS.Machine.Flow;

using Storage = Cpp2CS.Ir.Storage;

/// <summary>
/// IL2CPP 把 finally 写成按引用捕获局部的 lambda（<c>il2cpp::utils::Finally([&amp;]{...})</c>）。clang 不内联时，闭包留在调用方的栈上，
/// 其中存着被捕获局部的地址，lambda 成为一个没有元数据的函数。这些局部因此看起来地址逃逸，方法里对它们的读写都无法恢复。
/// 这里在 SSA 之前把这种调用展开回调用方：机器语义不变，SP 相对的访问落到调用方的帧下方，闭包内容经帧转发回到被捕获的局部。
/// 被调函数里的调用抛出异常时，在它自己的 try 内进入它的落地块（finally 体里的 catch），其余进入调用点的落地块。
/// 展开器在异常离开被调函数时恢复 SP 和被调用者保存的寄存器，正常返回时被调函数自己恢复它们，
/// 所以调用方在任何出口看到的都是调用前的值：副本里写这些寄存器的地方改用专属的临时存储，调用方的寄存器不变。
/// codegen 头文件里的内联成员函数（Array::SetAt、ArrayElementTypeCheck）clang 不内联时同样成为没有元数据的函数，
/// 展开方式相同；展开之后与内联的形式一致，由 L2 按运行时操作恢复。
/// </summary>
internal sealed class ClosureInlining(CfgBuilder cfg, Func<ulong, bool> isClosure, Func<ulong, bool> isOutlined, Storage firstArgument, Storage stackPointer, Storage framePointer, IReadOnlySet<Storage> preserved,
    bool nativeCallStack = false, int maxDepth = 3, int maxBlocks = 4096)
{
    /// <summary>展开产生的块用这个标记位的合成地址，不与代码地址和路径复制的合成地址相交。</summary>
    private const ulong Synthetic = 1UL << 62;

    /// <summary>提升器只用低编号的临时存储，且只在单条指令内部使用。</summary>
    private const int FirstTemporary = 1024;

    private ulong next;
    private int temporaries = FirstTemporary;

    public void Run(MachineFunction function)
    {
        temporaries = Math.Max(FirstTemporary, function.Blocks.SelectMany(b => b.Statements).OfType<Assign>()
            .Where(a => a.Target.Bank == Bank.Temp).Select(a => a.Target.Index + 1).DefaultIfEmpty(0).Max());
        next = Math.Max(next, function.Blocks.Where(b => b.Start >> 62 == 1).Select(b => (b.Start ^ Synthetic) + 1).DefaultIfEmpty(0UL).Max());
        var depth = new Dictionary<Block, int>();
        var added = 0;
        var changed = false;
        var work = new Stack<Block>(function.Blocks);
        while (work.TryPop(out var block))
        {
            var level = depth.GetValueOrDefault(block);
            if (level >= maxDepth || added >= maxBlocks || nativeCallStack && (block.Handler is not null || block.IsLandingPad)) continue;
            bool Candidate(Stmt statement) => statement is Call { Kind: CallKind.Direct, DoesNotReturn: false, Target: Const target }
                && target.Value != function.Entry && (isOutlined(target.Value) || isClosure(target.Value));
            var index = block.Statements.FindIndex(Candidate);
            while (index >= 0 && !isOutlined(((Const)((Call)block.Statements[index]).Target).Value) && !StackAddressInFirstArgument(block, index))
                index = block.Statements.FindIndex(index + 1, Candidate);
            if (index < 0) continue;
            var call = (Call)block.Statements[index];
            var callee = cfg.Build(((Const)call.Target).Value);
            if (callee.Problems.Count > 0 || nativeCallStack && added + callee.Blocks.Count + 1 > maxBlocks) continue;
            var returnAddress = 0UL;
            if (nativeCallStack)
            {
                var decoded = new List<Stmt>();
                var size = cfg.Machine.Lift(call.Address, decoded);
                if (size <= 0 || decoded.LastOrDefault() is not Call { Kind: CallKind.Direct } original || original.Target != call.Target) continue;
                returnAddress = call.Address + (ulong)size;
            }
            var (blocks, continuation) = Inline(block, index, callee, returnAddress);
            function.NativeExpansions.Add(new(cfg.Functions.At(call.Address)?.Start ?? function.Entry, call.Address, callee.Entry,
                nativeCallStack ? "native-body" : "closure-or-outlined"));
            added += blocks.Count + (nativeCallStack ? 1 : 0);
            changed = true;
            function.Blocks.AddRange(blocks);
            function.Blocks.Add(continuation);
            depth[continuation] = level;
            foreach (var clone in blocks) depth[clone] = level + 1;
            work.Push(continuation);
            foreach (var clone in blocks) work.Push(clone);
        }
        if (changed) function.Renumber();
    }

    /// <summary>调用时第一个实参是栈地址：调用之前最近一次写入它的是 SP 或帧指针加常量（可经同块的另一个寄存器）。沿唯一前驱回溯，遇到调用为止。</summary>
    private bool StackAddressInFirstArgument(Block block, int call)
    {
        var at = block;
        var end = call;
        for (var steps = 0; steps < 4; steps++)
        {
            for (var i = end - 1; i >= 0; i--)
            {
                if (at.Statements[i] is Call) return false;
                if (at.Statements[i] is Assign assign && assign.Target == firstArgument) return IsStackAddress(assign.Value, at, i);
            }
            if (at.Predecessors is not [var predecessor]) return false;
            at = predecessor;
            end = at.Statements.Count;
        }
        return false;
    }

    private bool IsStackAddress(Expr value, Block block, int before) => value switch
    {
        Read { Storage: var storage } when storage == stackPointer || storage == framePointer => true,
        Read { Storage: var storage } => Definition(storage, block, before) is var (source, at) && IsStackAddress(source, block, at),
        Binary { Op: BinOp.Add or BinOp.Sub, Right: Const } binary => IsStackAddress(binary.Left, block, before),
        _ => false,
    };

    /// <summary>同块内 before 之前对存储的最近一次写入；其间有调用时不成立。</summary>
    private static (Expr Value, int Index)? Definition(Storage storage, Block block, int before)
    {
        for (var i = before - 1; i >= 0; i--)
        {
            if (block.Statements[i] is Call) return null;
            if (block.Statements[i] is Assign assign && assign.Target == storage) return (assign.Value, i);
        }
        return null;
    }

    /// <summary>把 block 中 index 处的调用换成 callee 的一份副本。返回新块与调用之后的续接块。</summary>
    private (List<Block> Blocks, Block Continuation) Inline(Block block, int index, MachineFunction callee, ulong returnAddress)
    {
        var call = (Call)block.Statements[index];
        var handler = block.Handler;
        var continuation = Fresh(block.End);
        continuation.Statements = [.. block.Statements.Skip(index + 1)];

        // 调用之后的语句和原有的正常后继归续接块；异常边属于这次调用，由副本里的调用继承。
        var normal = block.NormalSuccessors.ToArray();
        if (handler is not null) MachineFunction.RemoveEdgeAt(block, block.Successors.Count - 1);
        foreach (var successor in normal)
        {
            successor.Predecessors[successor.Predecessors.IndexOf(block)] = continuation;
            continuation.Successors.Add(successor);
        }
        block.Successors.Clear();
        block.Statements.RemoveRange(index, block.Statements.Count - index);

        // x64 保留真实寄存器及保存/恢复访存，补回 Call 抽象省去的返回地址入栈。
        // ARM64 闭包沿用专属 SP/非易失寄存器，以处理异常离开时的恢复。
        var renamed = callee.Blocks.SelectMany(b => b.Statements).OfType<Assign>().Select(a => a.Target)
            .Where(t => nativeCallStack ? t.Bank == Bank.Temp && t.Index >= 1000 : t == stackPointer || preserved.Contains(t))
            .Distinct().ToDictionary(t => t, t => new Storage(Bank.Temp, temporaries++, t.Width));
        if (nativeCallStack)
        {
            block.Statements.Add(new Assign(call.Address, stackPointer, new Binary(BinOp.Sub, new Read(stackPointer, 64), Expr.C(8, 64), 64)));
            block.Statements.Add(new Store(call.Address, new Read(stackPointer, 64), Expr.C(returnAddress, 64)));
        }
        else foreach (var (register, temporary) in renamed)
            block.Statements.Add(new Assign(call.Address, temporary, new Read(register, register.Width)));
        var movesStack = renamed.TryGetValue(stackPointer, out var stack);
        Stmt Rename(Stmt statement)
        {
            var mapped = renamed.Count == 0 ? statement : ExprMap.MapOperands(statement, e => ExprMap.Map(e, v => v is Read read && renamed.TryGetValue(read.Storage, out var temporary) ? new Read(temporary, read.Width) : null));
            if (mapped is not Assign assign) return mapped with { };
            return assign with { Target = renamed.GetValueOrDefault(assign.Target, assign.Target),
                PreserveRead = assign.PreserveRead || nativeCallStack && ExprMap.Walk(assign.Value).Any(e => e is Load) };
        }
        Call Copied(Call original)
        {
            var copy = ((Call)Rename(original)).Duplicate();
            return movesStack ? copy with { StackPointer = new Read(stack, stack.Width) } : copy;
        }
        var clones = callee.Blocks.ToDictionary(b => b, b =>
        {
            var clone = Fresh(b.End);
            clone.IsLandingPad = b.IsLandingPad;
            return clone;
        });
        var starts = callee.Blocks.ToDictionary(b => b.Start, b => clones[b].Start);
        var created = new List<Block>();
        foreach (var original in callee.Blocks)
        {
            var current = clones[original];
            created.Add(current);
            var thrown = original.Handler is { } own ? clones[own] : handler;
            var statements = original.Statements.ToList();
            for (var i = 0; i < statements.Count; i++)
            {
                switch (statements[i])
                {
                    // selector 的取值由 LSDA 决定，副本的落地块不在调用方的异常表里：这里按被调函数的表定下。
                    case Assign { Value: Intrinsic { Name: "eh_selector" } } selector:
                        var filter = callee.Range.ExceptionRegions.Where(r => r.LandingPad == original.Start).SelectMany(r => r.Actions)
                            .FirstOrDefault(a => a.Kind == "typed-catch")?.Filter ?? 0;
                        current.Statements.Add(Rename(selector with { Value = Expr.C(unchecked((ulong)filter), selector.Value.Width) }));
                        break;
                    case Return returned:
                        if (nativeCallStack) current.Statements.Add(new Assign(returned.Address, stackPointer,
                            new Binary(BinOp.Add, new Read(stackPointer, 64), Expr.C(8, 64), 64)));
                        Link(current, continuation);
                        break;
                    case Call { Kind: CallKind.Tail or CallKind.TailIndirect } tail:
                        // 尾调用返回到被调函数的调用者，也就是这里的续接点。
                        // x64 的普通 Call 抽象以入栈前 SP 寻址实参，先越过原有返回地址。
                        if (nativeCallStack) current.Statements.Add(new Assign(tail.Address, stackPointer,
                            new Binary(BinOp.Add, new Read(stackPointer, 64), Expr.C(8, 64), 64)));
                        current = Called(current, Copied(tail) with { Kind = tail.Kind == CallKind.Tail ? CallKind.Direct : CallKind.Indirect }, thrown, created);
                        Link(current, continuation);
                        break;
                    case Call inner:
                        // 落地块只接在块末尾的调用上：调用点在 try 内时，副本里的每个调用各自结束一个块。
                        current = i == statements.Count - 1 && inner.DoesNotReturn
                            ? Terminal(current, Copied(inner), thrown)
                            : thrown is null ? Append(current, Copied(inner)) : Called(current, Copied(inner), thrown, created);
                        break;
                    case Jump jump:
                        current.Statements.Add(jump with { Target = starts[jump.Target] });
                        break;
                    case Branch branch:
                        current.Statements.Add((Branch)Rename(branch) with { Target = starts[branch.Target], Fallthrough = starts[branch.Fallthrough] });
                        break;
                    case IndirectJump table:
                        current.Statements.Add((IndirectJump)Rename(table) with { Targets = table.Targets.Select(t => starts[t]).ToArray() });
                        break;
                    default:
                        current.Statements.Add(Rename(statements[i]));
                        break;
                }
            }
            foreach (var successor in original.NormalSuccessors)
                Link(current, clones[successor]);
        }

        Link(block, clones[callee.EntryBlock]);
        return (created, continuation);
    }

    private static Block Append(Block block, Call call)
    {
        block.Statements.Add(call);
        return block;
    }

    private static Block Terminal(Block block, Call call, Block? handler)
    {
        block.Statements.Add(call);
        if (handler is not null) AttachHandler(block, handler);
        return block;
    }

    /// <summary>调用结束当前块，异常边接到调用点的落地块，返回接续的新块。</summary>
    private Block Called(Block block, Call call, Block? handler, List<Block> created)
    {
        block.Statements.Add(call);
        var following = Fresh(block.End);
        created.Add(following);
        Link(block, following);
        if (handler is not null) AttachHandler(block, handler);
        return following;
    }

    private static void AttachHandler(Block block, Block handler)
    {
        block.Handler = handler;
        Link(block, handler);
    }

    private static void Link(Block from, Block to)
    {
        from.Successors.Add(to);
        to.Predecessors.Add(from);
    }

    private Block Fresh(ulong end) => new(Synthetic | next++) { End = end };
}
