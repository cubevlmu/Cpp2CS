
namespace Cpp2CS.Facts;

/// <summary>栈参数相对调用时 SP 的位置；Indirect 为大值类型副本的指针，而非值本身。</summary>
public sealed record StackAbiValue(int Index, TypeRef Type, int Offset, int Size, bool Indirect);
public sealed record StackAbiSignature(StackAbiValue[] Parameters, int? MethodInfoOffset, int Size);

public sealed partial class ManagedAbi
{
    public AbiPiece[] StackPieces(StackAbiValue value)
    {
        if (value.Indirect || Kind(value.Type) != ValueKind.Struct) return [];
        if (architecture == Architecture.X64) return value.Size is 1 or 2 or 4 or 8 ? [new(Ir.Storage.Slot(value.Offset), value.Size * 8, 0)] : [];
        if (Hfa(value.Type) is { } hfa)
            return Enumerable.Range(0, hfa.Count).Select(i => new AbiPiece(Ir.Storage.Slot(value.Offset + i * hfa.Width / 8), hfa.Width, i * hfa.Width / 8)).ToArray();
        if (value.Size is <= 0 or > 16) return [];
        return Enumerable.Range(0, (value.Size + 7) / 8).Select(i => new AbiPiece(Ir.Storage.Slot(value.Offset + i * 8), Math.Min(8, value.Size - i * 8) * 8, i * 8)).ToArray();
    }

    /// <summary>
    /// 补齐既有 Stack 分类未表达的存储位置。AAPCS64 B.4 先把大非 HFA 值替换为指针，
    /// C.6/C.17 按至少 8 字节对齐分配栈槽；隐藏 MethodInfo 是最后一个指针参数。
    /// 寄存器分类仍由 Classify 提供；独立 AAPCS 分类器逐签名复核这些偏移。
    /// </summary>
    public StackAbiSignature StackArguments(AbiSignature signature)
    {
        if (architecture == Architecture.X64)
        {
            var position = (signature.Return?.Passing == Passing.Indirect ? 1 : 0) + (signature.This is null ? 0 : 1);
            var values = new List<StackAbiValue>();
            for (var index = 0; index < signature.Parameters.Length; index++, position++)
            {
                var value = signature.Parameters[index];
                if (value.Passing != Passing.Stack) continue;
                var size = Size(value.Type);
                var indirect = Kind(value.Type) == ValueKind.Struct && size is not (1 or 2 or 4 or 8);
                values.Add(new(index, value.Type, 8 + position * 8, indirect ? 8 : size, indirect));
            }
            return new(values.ToArray(), signature.MethodInfo is null ? 8 + position * 8 : null, Math.Max(32, (position + 1) * 8));
        }
        var stack = 0;
        var parameters = new List<StackAbiValue>();
        static int Round(int n, int alignment) => checked((n + alignment - 1) / alignment * alignment);
        for (var i = 0; i < signature.Parameters.Length; i++)
        {
            var value = signature.Parameters[i];
            if (value.Passing != Passing.Stack) continue;
            var indirect = Kind(value.Type) == ValueKind.Struct && Size(value.Type) > 16 && Hfa(value.Type) is null;
            var shape = layouts.SizeAndAlignment(value.Type);
            var size = indirect ? 8 : shape.Size;
            var alignment = indirect ? 8 : Math.Max(8, shape.Alignment);
            stack = Round(stack, alignment);
            parameters.Add(new(i, value.Type, stack, size, indirect));
            stack += Round(size, 8);
        }
        int? methodInfo = null;
        if (signature.MethodInfo is null) { stack = Round(stack, 8); methodInfo = stack; stack += 8; }
        return new(parameters.ToArray(), methodInfo, stack);
    }
}
