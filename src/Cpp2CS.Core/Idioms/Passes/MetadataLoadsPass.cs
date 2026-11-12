using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Ssa;

namespace Cpp2CS.Idioms;

/// <summary>仅把已核实槽位的指针读取转换为元数据实体；不删除初始化调用或守卫。</summary>
internal static class MetadataLoadsPass
{
    internal static IdiomResult Run(MachineFunction function, UsageSlots usages, IdiomResult? result = null, int? staticFieldsOffset = null, int? methodClassOffset = null)
    {
        result ??= new IdiomResult();
        Expr? Rewrite(Expr expression)
        {
            if (methodClassOffset is { } methodOffset && expression is Load { Width: 64, Address: Binary { Op: BinOp.Add,
                Left: Symbol { Kind: SymbolKind.Method, Value: MethodRef method }, Right: Const methodField } } && methodField.Value == (ulong)methodOffset)
                return new Symbol(SymbolKind.Class, method.DeclaringType);
            if (staticFieldsOffset is { } offset && expression is Load { Width: 64, Address: Binary { Op: BinOp.Add,
                Left: Symbol { Kind: SymbolKind.Class } klass, Right: Const field } } && field.Value == (ulong)offset)
            {
                result.Hit(Template.StaticFields);
                return new Symbol(SymbolKind.StaticFields, klass.Value);
            }
            if (expression is not Load { Width: 64, Address: Const address } || usages.At(address.Value) is not { } slot) return null;
            result.ReadSlots.Add(address.Value);
            result.Hit(Template.MetadataSlot);
            return new Symbol(SymbolOfPass.SymbolOf(slot.Usage.Kind), slot.Usage.Value);
        }
        foreach (var block in function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
                block.Statements[i] = ExprMap.MapOperands(block.Statements[i], e => ExprMap.Map(e, Rewrite));
        if (result.ReadSlots.Count > 0) Propagate.Run(function, Dominators.Compute(function));
        return result;
    }
}
