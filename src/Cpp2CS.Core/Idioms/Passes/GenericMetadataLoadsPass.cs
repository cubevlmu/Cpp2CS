using Cpp2CS.Ir;

namespace Cpp2CS.Idioms;

/// <summary>仅用已约束的类布局和匹配的注册表解析泛型上下文。</summary>
internal static class GenericMetadataLoadsPass
{
    internal static bool GenericMetadataLoads(this IdiomState state)
    {
        var offset = state.facts.Base.RuntimeOffsets?.ClassRgctxData;
        var changed = false;
        Expr? Map(Expr expression)
        {
            if (expression is Use use && state.defs.Raw(use.Variable) is Symbol { Kind: SymbolKind.Class } known)
            { changed = true; return known; }
            if (expression is not Load { Width: 64 } load) return null;
            var (basis, field) = SplitPass.Split(state.defs.Expand(load.Address));
            Symbol? replacement = null;
            if (offset is { } rgctxOffset && basis is Symbol { Kind: SymbolKind.Class, Value: DefinitionRef type } && field == (ulong)rgctxOffset)
            {
                var table = TablePass.Table(type);
                if (state.facts.Registrations.Rgctx.TryGetValue((table.Image, table.Token), out var entries) && entries.Length > 0)
                    replacement = new Symbol(SymbolKind.Rgctx, table);
            }
            else if (basis is Symbol { Kind: SymbolKind.Rgctx, Value: RgctxTable table } && field % 8 == 0 && field / 8 <= int.MaxValue)
                replacement = state.Entry(table, (int)(field / 8));
            if (replacement is null) return null;
            changed = true;
            return replacement;
        }
        foreach (var block in state.function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
                block.Statements[i] = ExprMap.MapOperands(block.Statements[i], e => ExprMap.Map(e, Map));
        return changed;
    }
}
