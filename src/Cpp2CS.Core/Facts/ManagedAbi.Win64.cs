using Cpp2CS.Ir;

namespace Cpp2CS.Facts;

public sealed partial class ManagedAbi
{
    private static readonly int[] Win64Registers = [1, 2, 8, 9];

    private AbiValue? Win64Return(TypeRef type, out string? problem)
    {
        problem = null;
        var kind = Kind(type);
        if (kind == ValueKind.Void) return null;
        var size = Size(type);
        if (kind is null || size <= 0 || SharedValue(type))
        {
            problem = "Win64 返回类型缺少已核实的大小或共享实例 ABI";
            return null;
        }
        if (kind == ValueKind.Struct && size is not (1 or 2 or 4 or 8))
            return new(type, Passing.Indirect, [new(Storage.Gpr(1), 64, 0)]);
        return new(type, Passing.Registers, [new(kind is ValueKind.Float or ValueKind.Double ? Storage.Vec(0) : Storage.Gpr(0), size * 8, 0)]);
    }

    /// <summary>Win64 按参数位置共享四个整数/浮点槽；栈偏移相对被调用者入口 RSP。</summary>
    private MachineSignature? MachineWin64(MethodRef method, out string? problem)
    {
        var returned = method.Concrete(method.Method.ReturnType);
        var classified = Win64Return(returned, out problem);
        if (problem is not null) return null;
        var position = classified?.Passing == Passing.Indirect ? 1 : 0;
        AbiPiece Place(TypeRef type, bool pointer = false)
        {
            var slot = position++;
            var width = pointer ? 64 : Size(type) * 8;
            var storage = slot >= 4 ? Storage.Slot(8 + slot * 8)
                : !pointer && Kind(type) is ValueKind.Float or ValueKind.Double ? Storage.Vec(slot) : Storage.Gpr(Win64Registers[slot]);
            return new(storage, width, 0);
        }
        var arguments = new List<MachineValue>();
        if (!method.Method.IsStatic)
        {
            var owner = method.DeclaringType;
            var type = method.Method.Owner.IsValueType ? (TypeRef)new ByRefRef(owner) : owner;
            arguments.Add(new(-1, type, method.Method.Owner.IsValueType ? Transfer.Reference : Transfer.Value,
                [Place(type, true)], method.Method.Owner.IsValueType ? Size(owner) : 8,
                method.Method.Owner.IsValueType ? MemoryAccess.ReadWrite : MemoryAccess.None));
        }
        for (var index = 0; index < method.Method.Parameters.Count; index++)
        {
            var parameter = method.Method.Parameters[index];
            var type = method.Concrete(parameter.Type);
            var size = Size(type);
            var kind = Kind(type);
            if (kind is null or ValueKind.Void || size <= 0 || SharedValue(type))
            {
                problem = $"Win64 参数 {index} 缺少已核实的布局或共享实例 ABI";
                return null;
            }
            var indirect = kind == ValueKind.Struct && size is not (1 or 2 or 4 or 8);
            var piece = Place(type, indirect);
            arguments.Add(indirect ? new(index, type, Transfer.Copy, [piece], size, MemoryAccess.Read)
                : Direct(index, type, [piece], parameter.Attributes));
        }
        var infoSlot = position++;
        var info = new AbiPiece(infoSlot < 4 ? Storage.Gpr(Win64Registers[infoSlot]) : Storage.Slot(8 + infoSlot * 8), 64, 0);
        MachineValue? result = classified is null ? null : new(MachineSignature.ReturnIndex, returned,
            classified.Passing == Passing.Indirect ? Transfer.ResultBuffer : Transfer.Value, classified.Pieces, Size(returned),
            classified.Passing == Passing.Indirect ? MemoryAccess.Write : MemoryAccess.None);
        return new(arguments.ToArray(), result, info, Math.Max(32, position * 8))
        {
            BufferPointerResult = result?.Transfer == Transfer.ResultBuffer ? Storage.Gpr(0) : null,
        };
    }

    private AbiSignature? ClassifyWin64(MethodRef method, out string? problem)
    {
        if (MachineWin64(method, out problem) is not { } signature) return null;
        static AbiValue Value(MachineValue value) => new(value.Type,
            value.Pieces[0].Register.Bank == Bank.Stack ? Passing.Stack : value.Transfer == Transfer.Copy ? Passing.Indirect : Passing.Registers,
            value.Pieces[0].Register.Bank == Bank.Stack ? [] : value.Pieces);
        return new(signature.This is { } self ? Value(self) : null,
            signature.Arguments.Where(a => a.Index >= 0).Select(Value).ToArray(),
            signature.MethodInfo?.Register.Bank == Bank.Stack ? null : signature.MethodInfo,
            signature.Return is { } result ? new(result.Type, result.Transfer == Transfer.ResultBuffer ? Passing.Indirect : Passing.Registers, result.Pieces) : null)
        {
            BufferPointerResult = signature.BufferPointerResult,
        };
    }
}
