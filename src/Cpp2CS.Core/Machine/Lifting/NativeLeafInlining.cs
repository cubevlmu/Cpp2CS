using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Machine.Lifting;

using Storage = Cpp2CS.Ir.Storage;

/// <summary>已证直线体保留机器效果；类型求解前保留单身份托管调用。</summary>
internal sealed class NativeLeafInlining(ProgramFacts facts, IMachine machine)
{
    private readonly Dictionary<(ulong Entry, bool AllowPure), Stmt[]?> bodies = [];

    internal int Run(MachineFunction function)
    {
        var next = function.Blocks.SelectMany(b => b.Statements).OfType<Assign>().Select(a => a.Target)
            .Where(s => s.Bank == Bank.Temp).Select(s => s.Index).DefaultIfEmpty(999).Max() + 1;
        var count = 0;
        foreach (var block in function.Blocks)
        {
            if (block.Handler is not null || block.IsLandingPad) continue;
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Call { Kind: CallKind.Direct, Op: null, DoesNotReturn: false, Target: Const target } call
                    || facts.EntriesAt(target.Value).Where(e => e.Kind is EntryKind.Method or EntryKind.GenericMethod)
                        .Select(e => e.Method).Distinct().Take(2).Count() == 1
                    || target.Value == function.Entry || Body(target.Value) is not { } body || !body.OfType<Store>().Any()) continue;
                // SLEIGH 的 unique 空间只在一条指令内有效；副本不得覆盖调用方的临时存储。
                var temporaries = body.OfType<Assign>().Select(a => a.Target).Where(s => s.Bank == Bank.Temp)
                    .Distinct().ToDictionary(s => s, s => new Storage(Bank.Temp, next++, s.Width));
                var copy = body.Select(s =>
                {
                    var mapped = ExprMap.MapOperands(s, e => ExprMap.Map(e, v => v is Read r && temporaries.TryGetValue(r.Storage, out var t)
                        ? new Read(t, r.Width) : null));
                    return mapped is Assign a ? a with { Target = temporaries.GetValueOrDefault(a.Target, a.Target),
                        PreserveRead = a.PreserveRead || ExprMap.Walk(a.Value).Any(e => e is Load) } : mapped;
                }).ToArray();
                block.Statements.RemoveAt(i);
                block.Statements.InsertRange(i, copy);
                function.NativeExpansions.Add(new(facts.Code.At(call.Address)?.Start ?? function.Entry, call.Address, target.Value, "native-straight-line"));
                i += copy.Length - 1;
                count++;
            }
        }
        return count;
    }

    /// <summary>SSA 类型与分派求解之后，只展开仍无签名的只读入口，优先保留已有托管调用。</summary>
    internal int RunReads(MachineFunction function, Func<Call, bool> unresolved)
    {
        var next = function.Blocks.SelectMany(b => b.Statements).SelectMany(s => s switch {
            Define d => new[] { d.Target }, Phi p => [p.Target], Call c => c.Defines, _ => [],
        }).Concat(function.Dead.Select(d => d.Define.Target)).Where(v => v.Storage.Bank == Bank.Temp)
            .Select(v => v.Storage.Index + 1).DefaultIfEmpty(1000).Max();
        var count = 0;
        foreach (var block in function.Blocks)
        {
            if (block.Handler is not null || block.IsLandingPad) continue;
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Call { Kind: CallKind.Direct, Op: null, DoesNotReturn: false, Resolved: null, Target: Const target } call
                    || target.Value == function.Entry || call.Defines.Length != call.Results.Length || !unresolved(call)
                    || call.Results.Any(s => s.Bank is not (Bank.Gpr or Bank.Vec))
                    || Body(target.Value, allowPure: true) is not { } body || body.OfType<Store>().Any()) continue;
                var inputs = call.ArgumentsBySource();
                var state = new Dictionary<Storage, Expr>();
                var statements = new List<Stmt>();
                foreach (var statement in body)
                {
                    if (statement is not Assign assign) { statements.Add(statement); continue; }
                    var expression = Fold.Simplify(ExprMap.Map(assign.Value, node => node is Read read
                        ? Fold.Convert(ConvKind.Truncate, state.GetValueOrDefault(read.Storage, inputs.GetValueOrDefault(read.Storage,
                            new Unknown("共享只读体的入口寄存器未知", read.Storage.Width))), read.Width) : null));
                    if (expression.Width < assign.Target.Width) expression = Fold.Convert(ConvKind.ZeroExtend, expression, assign.Target.Width);
                    var variable = new Variable(new Storage(Bank.Temp, next++, assign.Target.Width), 1);
                    statements.Add(new Define(assign.Address, variable, expression) { PreserveRead = ExprMap.Walk(assign.Value).Any(e => e is Load) });
                    state[assign.Target] = new Use(variable, variable.Width);
                }
                for (var result = 0; result < call.Defines.Length; result++)
                    statements.Add(new Define(call.Address, call.Defines[result], state.GetValueOrDefault(call.Results[result],
                        inputs.GetValueOrDefault(call.Results[result], new Unknown("共享只读体没有该输出", call.Results[result].Width)))));
                Cpp2CS.Machine.Ssa.ReadEffects.PreserveInputs(function, call.Arguments);
                block.Statements.RemoveAt(i);
                block.Statements.InsertRange(i, statements);
                function.NativeExpansions.Add(new(facts.Code.At(call.Address)?.Start ?? function.Entry, call.Address, target.Value, "native-straight-line-ssa"));
                i += statements.Count - 1;
                count++;
            }
        }
        return count;
    }

    private Stmt[]? Body(ulong target, bool allowPure = false)
    {
        var key = (target, allowPure);
        if (bodies.TryGetValue(key, out var cached)) return cached;
        bodies[key] = null;
        if (machine.Architecture != Architecture.X64 || facts.EntriesAt(target).Any(e => e.Method?.Method.Name is ".ctor" or ".cctor")
            || facts.NativeCalls.At(target) is not { } summary) return null;
        // 已登记的纯寄存器体仍先由托管消歧证明处理；不凭机器别名选择某个重载。
        if (!allowPure && facts.EntriesAt(target).Length > 0 && !summary.WritesMemory
            && !summary.Body.SelectMany(ExprMap.Operands).SelectMany(ExprMap.Walk).OfType<Load>().Any()
            && !ConstantReturn(target, summary.Returns)) return null;
        return bodies[key] = summary.Body.ToArray();
    }

    private bool ConstantReturn(ulong entry, IReadOnlyDictionary<Storage, Expr> returned)
    {
        var signatures = facts.EntriesAt(entry).Select(e => e.Method).OfType<MethodRef>()
            .Select(m => facts.CreateAbi().Machine(m, out _)).ToArray();
        if (signatures.Length == 0 || signatures.Any(s => s?.Return is not { Transfer: Transfer.Value, Pieces.Length: 1, Size: > 0 and <= 8 })) return false;
        return signatures.Select(s => s!.Return!.Pieces[0]).Distinct().ToArray() is [var piece]
            && returned.TryGetValue(piece.Register, out var result) && Fold.Convert(ConvKind.Truncate, result, piece.Width) is Const;
    }

}
