using Cpp2CS.Facts;
using Cpp2CS.Ir;

namespace Cpp2CS.Machine.Flow;

using Storage = Cpp2CS.Ir.Storage;
using Convert = Cpp2CS.Ir.Convert;

public sealed partial class NoReturnOracle
{
    // 只传播常量及本条指令的 IAT 读取，不推测普通内存内容。
    private bool ReturnsX64(ulong entry, CodeFunction range)
    {
        // 无 catch 的 FH4 仍须逐项排除清理中的非局部控制转移，不能只依赖 UHANDLER。
        if (range.HasUnmodeledExceptions && !UnwindCannotResume(range)) return true;
        var inputs = new Dictionary<ulong, Dictionary<Storage, Expr>>();
        var ready = new Stack<(ulong Address, Dictionary<Storage, Expr> Values)>();
        var deferred = new Queue<(ulong? After, ulong Target, Dictionary<Storage, Expr> Values)>();
        ready.Push((entry, new()));
        var steps = 0;
        while (true)
        {
            while (ready.TryPop(out var work))
            {
                if (++steps > 20000 || !range.Contains(work.Address)) return true;
                var values = work.Values;
                if (inputs.TryGetValue(work.Address, out var old))
                {
                    // 汇合只保留每条进入路径都相同的值；信息变弱时重新检查后继。
                    var merged = old.Where(p => values.TryGetValue(p.Key, out var value) && p.Value == value).ToDictionary();
                    if (merged.Count == old.Count) continue;
                    values = merged;
                }
                inputs[work.Address] = new(values);
                var statements = new List<Stmt>();
                var size = machine.Lift(work.Address, statements);
                if (size == 0 || (ulong)size > range.End - work.Address || statements.Any(s => s is Opaque)) return true;
                var next = work.Address + (ulong)size;
                var terminal = statements.LastOrDefault();
                Expr Resolve(Expr expression) => Fold.Simplify(ExprMap.Map(expression, e =>
                {
                    if (e is not Read read || !values.TryGetValue(read.Storage, out var value)) return null;
                    return value.Width == read.Width ? value : new Convert(value.Width < read.Width ? ConvKind.ZeroExtend : ConvKind.Truncate, value, read.Width);
                }));
                foreach (var assign in statements.OfType<Assign>())
                {
                    var value = Resolve(assign.Value);
                    if (value is Const)
                        values[assign.Target] = value.Width == assign.Target.Width ? value : Fold.Simplify(new Convert(ConvKind.ZeroExtend, value, assign.Target.Width));
                    else if (value is Load { Width: 64, Address: Const address } && machine.Image.Imports.ContainsKey(address.Value))
                        values[assign.Target] = value;
                    else values.Remove(assign.Target);
                }
                var imported = terminal switch
                {
                    Call call => Import(Resolve(call.Target)),
                    IndirectJump jump => Import(Resolve(jump.Target)),
                    _ => null,
                };
                var importedNoReturn = imported is { } symbol && (IsNoReturnName(symbol.Name)
                    || symbol.Name == "RaiseException" && IsWindowsErrorModule(symbol.Module)
                        && values.GetValueOrDefault(Storage.Gpr(2)) is Const flags && (uint)flags.Value == 1);
                // unique 空间只在单条 SLEIGH 指令内有效；IAT 可被未知调用改写，不能跨指令缓存读取值。
                foreach (var key in values.Where(p => p.Key.Bank == Bank.Temp && p.Key.Index >= 1000 || p.Value is Load).Select(p => p.Key).ToArray()) values.Remove(key);
                void Push(ulong address) => ready.Push((address, new(values)));
                switch (terminal)
                {
                    case Return: return true;
                    // 调试器或原生异常处理可能恢复陷阱，不能把陷阱本身当作不返回契约。
                    case Trap: return true;
                    case Jump jump when range.Contains(jump.Target): Push(jump.Target); break;
                    case Jump jump: deferred.Enqueue((null, jump.Target, new(values))); break;
                    case Branch branch:
                        if (range.Contains(branch.Target)) Push(branch.Target);
                        else deferred.Enqueue((null, branch.Target, new(values)));
                        Push(next);
                        break;
                    case IndirectJump:
                        if (!importedNoReturn) return true;
                        break;
                    case Call call:
                        if (call.Op?.Kind == OpKind.MemoryBarrier) { Push(next); break; }
                        if (importedNoReturn) break;
                        foreach (var register in machine.Convention.Clobbered) values.Remove(register);
                        if (call is { Kind: CallKind.Direct or CallKind.Tail, Target: Const target })
                            deferred.Enqueue((call.Kind == CallKind.Tail ? null : next, target.Value, new(values)));
                        else if (call.Kind == CallKind.TailIndirect) return true;
                        else Push(next);
                        break;
                    default: Push(next); break;
                }
            }
            if (!deferred.TryDequeue(out var pending)) return false;
            if (IsNoReturn(pending.Target)) continue;
            if (pending.After is not { } after) return true;
            ready.Push((after, pending.Values));
        }

        (string Name, string? Module)? Import(Expr expression) => expression is Load { Width: 64, Address: Const slot }
            && machine.Image.Imports.TryGetValue(slot.Value, out var name)
            ? (name, machine.Image.ImportModules.GetValueOrDefault(slot.Value)) : null;
    }

    private static bool IsWindowsErrorModule(string? module) => module?.ToLowerInvariant() is
        "kernel32.dll" or "kernelbase.dll" or "api-ms-win-core-errorhandling-l1-1-0.dll";
}
