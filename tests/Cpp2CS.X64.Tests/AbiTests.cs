using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Model;

namespace Cpp2CS.X64.Tests;

internal static class AbiTests
{
    public static void Run()
    {
        var owner = Type("Owner", false, 8);
        var integer = new DefinitionRef(Type("Int32", true, 4), []);
        var single = new DefinitionRef(Type("Single", true, 4), []);
        var wide = new DefinitionRef(Type("Double", true, 8), []);
        var aggregate = new DefinitionRef(Type("Aggregate", true, 16), []);
        var method = new MethodDef
        {
            Index = 0, Owner = owner, Name = "Mixed", Token = 0x06000001,
            Attributes = MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
            ReturnType = integer,
            Parameters = new[] { integer, single, integer, wide, integer }
                .Select((t, i) => new ParameterDef("p" + i, t, 0, null, false)).ToArray(),
        };
        var abi = new ManagedAbi(new Layouts(), Architecture.X64);
        var signature = abi.Machine(MethodRef.Open(method), out var problem) ?? throw new InvalidOperationException(problem);
        Check(signature.Arguments.Select(a => a.Pieces[0].Register).SequenceEqual(new[]
            { Storage.Gpr(1), Storage.Vec(1), Storage.Gpr(8), Storage.Vec(3), Storage.Slot(40) }), "混合参数按位置分配");
        Check(signature.MethodInfo?.Register == Storage.Slot(48), "隐藏 MethodInfo 栈位置");
        Check(signature.Return?.Pieces[0].Register == Storage.Gpr(0), "整数返回值");
        Check(signature.BufferPointerResult is null, "直接返回没有缓冲区地址别名");
        var arm = new ManagedAbi(new Layouts()).Machine(MethodRef.Open(method), out problem) ?? throw new InvalidOperationException(problem);
        Check(arm.Arguments.Select(a => a.Pieces[0].Register).SequenceEqual(new[]
            { Storage.Gpr(0), Storage.Vec(0), Storage.Gpr(1), Storage.Vec(1), Storage.Gpr(2) }), "默认 AAPCS64 分配保持不变");
        Check(arm.MethodInfo?.Register == Storage.Gpr(3), "默认 AAPCS64 隐藏参数");
        var slots = abi.StackArguments(abi.Classify(MethodRef.Open(method), out problem)!);
        Check(slots.Parameters is [{ Index: 4, Offset: 40 }] && slots.MethodInfoOffset == 48, "Win64 栈分类接口一致");
        method.ReturnType = aggregate;
        signature = abi.Machine(MethodRef.Open(method), out problem) ?? throw new InvalidOperationException(problem);
        Check(signature.Return is { Transfer: Transfer.ResultBuffer } && signature.Return.Pieces[0].Register == Storage.Gpr(1), "结构返回缓冲区");
        Check(signature.BufferPointerResult == Storage.Gpr(0)
            && abi.Classify(MethodRef.Open(method), out _)!.Results.SequenceEqual(new[] { Storage.Gpr(0) }), "Win64 大结构返回通过 RAX 回传缓冲区地址");
        Check(new ManagedAbi(new Layouts()).Machine(MethodRef.Open(method), out _)!.BufferPointerResult is null,
            "ARM64 不套用 Win64 的回传地址契约");
        Check(signature.Arguments[0].Pieces[0].Register == Storage.Gpr(2) && signature.Arguments[1].Pieces[0].Register == Storage.Vec(2), "返回缓冲区移动实参位置");
        Console.WriteLine("Win64 ABI 测试通过");
    }

    private static TypeDef Type(string name, bool value, int size) => new()
    {
        Index = 0, Assembly = "mscorlib.dll", Namespace = "System", Name = name, Token = 0x02000001,
        Attributes = TypeAttributes.Public, IsValueType = value, IsEnum = false, Size = size,
    };
    private sealed class Layouts : ITypeLayouts
    {
        public TypeLayout? Of(DefinitionRef type) => null;
        public (int Size, int Alignment) SizeAndAlignment(TypeRef type) => type is DefinitionRef d ? (d.Definition.Size, Math.Min(d.Definition.Size, 8)) : (8, 8);
        public (int Size, int Alignment)? TrySizeAndAlignment(TypeRef type) => SizeAndAlignment(type);
    }
    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
