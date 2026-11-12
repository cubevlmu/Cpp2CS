using System.Reflection;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Output;

namespace Cpp2CS.X64.Tests;

internal static class ConstructorShapeTests
{
    internal static void Run()
    {
        TypeDef Type(int index, string name) => new() { Index = index, Assembly = "Fixture.dll", Namespace = "Fixture", Name = name,
            Token = (uint)(0x02000001 + index), Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        var parent = Type(0, "Parent"); var owner = Type(1, "Holder"); var callable = Type(2, "Callback");
        var parentType = new DefinitionRef(parent, []); var ownerType = new DefinitionRef(owner, []);
        owner.BaseType = parentType;
        MethodRef Method(int index, string name, TypeDef declaring, bool isStatic = false) => MethodRef.Open(new MethodDef
        {
            Index = index, Owner = declaring, Name = name, Token = (uint)(0x06000001 + index), Slot = -1, ImplAttributes = 0,
            Attributes = MethodAttributes.Public | (isStatic ? MethodAttributes.Static : 0),
        });
        var baseCtor = Method(0, ".ctor", parent); var first = Method(1, ".ctor", owner); var second = Method(2, ".ctor", owner);
        var factory = Method(3, "Make", parent, true); var differentFactory = Method(4, "Other", parent, true);
        owner.Methods = [first.Method, second.Method];
        var field = new FieldDef { Index = 0, Owner = owner, Name = "value", Type = parentType, Offset = 16, Attributes = FieldAttributes.Private };
        owner.Fields = [field];
        ManagedBody Body(MethodRef method, ManagedValue initializer) => new(method, [new(0, [
            new ManagedStore(0, new FieldValue(new ArgumentValue(-1, ownerType, 64), new FieldRef(field, ownerType), parentType, 64), initializer),
            new ManagedCall(1, new ManagedInvocation(baseCtor, new ArgumentValue(-1, ownerType, 64), [], false), null), new ManagedReturn(2, null)])]);
        foreach (var delegateInitializer in new[] { false, true })
        {
            ManagedValue Value(MethodRef target, bool thisTarget = false) => delegateInitializer
                ? new DelegateValue(new DefinitionRef(callable, []), thisTarget ? new ArgumentValue(-1, ownerType, 64) : new ConstantValue(0, parentType, 64), target, DelegateBinding.Static)
                : new StaticCallValue(target, parentType, 64, false);
            var a = Body(first, Value(factory)); var b = Body(second, Value(factory));
            Check(SourceSuitability.Check([a, b]).Count == 0, "相同构造前缀中的工厂或委托初始化应可比较");
            Check(SourceSuitability.Check([a, Body(second, Value(differentFactory))]).Count == 2,
                "不同工厂／委托方法身份不能合并为相同初始化器");
            if (delegateInitializer)
            {
                var leaking = Body(first, Value(factory, true));
                Check(SourceSuitability.Check([leaking]).ContainsKey(leaking), "新增表达式比较不得放行构造前 this 逃逸");
            }
        }
        Console.WriteLine("构造初始化器比较通过：工厂及委托身份一致性、不同目标拒绝和构造前this逃逸");
    }

    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
