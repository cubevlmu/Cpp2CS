using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Image;

namespace Cpp2CS.X64;

/// <summary>选定函数及已证异常元数据归属的处理体引用；扫描不等于完成异常投影。</summary>
public static class X64References
{
    public static CodeScan Scan(CodeMap map, PcodeMachine machine, IEnumerable<ulong> entries)
    {
        var cfg = new CfgBuilder(machine, map);
        var references = new Dictionary<ulong, CodeRef[]>();
        foreach (var entry in entries.Distinct())
        {
            if (map.At(entry) is not { } range || range.Start != entry) continue;
            var found = new List<CodeRef>();
            var roots = new HashSet<ulong> { entry };
            if (range.WindowsRange is { Handler: not null } windows)
            {
                var analysis = WindowsEhReader.Read(machine.Image, windows);
                if (analysis.MetadataStatus == "parsed" && analysis.RuntimeContract == "msvc-fh4-runtime-contract")
                {
                    roots.UnionWith(analysis.CatchRegions.SelectMany(c => c.Handlers).Select(h => h.Entry));
                    // 续接体可能只经原生分派到达；首次扫描尚未证明包装身份，不能依赖异常投影发现它。
                    roots.UnionWith(analysis.CatchRegions.SelectMany(c => c.Handlers).SelectMany(h => h.Continuations).Where(range.Contains));
                    roots.UnionWith(analysis.UnwindActions.Where(a => a.Action is not null).Select(a => a.Action!.Value));
                }
            }
            foreach (var body in roots)
            foreach (var statement in (range.Contains(body) ? cfg.Build(body, range) : cfg.Build(body)).Blocks.SelectMany(b => b.Statements))
            {
                switch (statement)
                {
                    case Call { Op: null, Target: Const target, Kind: CallKind.Direct or CallKind.Tail } call:
                        found.Add(new(call.Address, target.Value, call.Kind == CallKind.Tail ? RefKind.TailCall : RefKind.Call, 0));
                        break;
                    case Assign assign:
                        if (assign.Value is Const { Width: 64 } address && machine.Image.SectionAt(address.Value) is not null)
                            found.Add(new(assign.Address, address.Value, RefKind.Address, 0));
                        Loads(assign.Address, assign.Value);
                        break;
                    case Store store:
                        if (store.Target is Const destination)
                            found.Add(new(store.Address, destination.Value, RefKind.Store, (byte)(store.Value.Width / 8)));
                        Loads(store.Address, store.Target);
                        Loads(store.Address, store.Value);
                        break;
                }
            }
            references[entry] = found.Distinct().ToArray();

            void Loads(ulong site, Expr expression)
            {
                foreach (var load in ExprMap.Walk(expression).OfType<Load>())
                    if (load.Address is Const address)
                        found.Add(new(site, address.Value, RefKind.Load, (byte)(load.Width / 8)));
            }
        }
        return CodeScan.FromReferences(map, references);
    }
}
