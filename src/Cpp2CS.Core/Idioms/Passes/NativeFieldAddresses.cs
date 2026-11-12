using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Recovery;

namespace Cpp2CS.Idioms;

/// <summary>已证 Win64 字段地址体与确定元数据合成普通地址运算，保留副本别名和原生空指针行为。</summary>
internal static class NativeFieldAddresses
{
    internal static bool Run(IdiomState state)
    {
        var changed = false;
        foreach (var block in state.function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Call { Kind: CallKind.Direct, Op: null, Target: Const target, Defines: [var result], Arguments.Length: 2 } call
                    || state.owner.HelperOf(call)?.Kind != HelperKind.FieldAddress
                    || Field(state, state.defs.Expand(call.Arguments[1])) is not { } field) continue;
                if (state.self is not null) field = (FieldRef)GenericContext.Instantiate(field, state.self)!;
                if (field.Field.IsStatic || field.DeclaringType is not DefinitionRef owner
                    || state.facts.Layouts.Of(owner)?.Field(field.Field) is not { } slot) continue;
                var offset = slot.Offset - (owner.Definition.IsValueType ? TypeLayout.ObjectHeaderSize : 0);
                if (offset < 0) continue;
                var address = Fold.Simplify(new Binary(BinOp.Add, call.Arguments[0], Expr.C((ulong)offset, 64), 64));
                block.Statements[i] = new Define(call.Address, result, address);
                state.function.NativeExpansions.Add(new(state.facts.Code.At(call.Address)?.Start ?? state.function.Entry,
                    call.Address, target.Value, "native-field-address-layout"));
                changed = true;
            }
        return changed;
    }

    private static FieldRef? Field(IdiomState state, Expr value)
    {
        if (value is Symbol { Kind: SymbolKind.Field, Value: FieldRef known }) return known;
        if (state.facts.Base.RuntimeOffsets is not { ClassFields: { } fields, FieldInfoSize: > 0 } offsets) return null;
        var (basis, offset) = SplitPass.Split(value);
        if (basis is not Load { Width: 64 } table || offset % (ulong)offsets.FieldInfoSize.Value != 0) return null;
        var (owner, member) = SplitPass.Split(state.defs.Expand(table.Address));
        if (member != (ulong)fields || owner is not Symbol { Kind: SymbolKind.Class, Value: DefinitionRef type }) return null;
        var index = offset / (ulong)offsets.FieldInfoSize.Value;
        return index < (ulong)type.Definition.Fields.Count ? new(type.Definition.Fields[(int)index], type) : null;
    }
}
