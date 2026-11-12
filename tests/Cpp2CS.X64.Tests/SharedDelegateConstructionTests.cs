using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;
using Mono.Cecil.Cil;

namespace Cpp2CS.X64.Tests;

internal static class SharedDelegateConstructionTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        foreach (var payloadClass in new[] { false, true })
        foreach (var staticTarget in new[] { false, true })
        foreach (var reverse in new[] { false, true })
        {
            const ulong basis = 0x180000000;
            var bytes = original.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x124), 12);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x700), 0x10e0);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x704), 0x10e1);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x708), 0x3140); bytes[0x740] = 1;
            var body = new List<byte>();
            void Hex(string hex) => body.AddRange(Convert.FromHexString(hex));
            void Relative(string prefix, uint rva)
            {
                Hex(prefix);
                var offset = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(offset, (int)rva - (0x1000 + body.Count + 4));
                body.AddRange(offset);
            }
            Hex("53564883EC28488BD9");
            Relative("488B0D", 0x2000); Relative("E8", 0x10e0); Hex("488BF0");
            Relative("4C8B05", 0x2008); Hex("4533C9"); Hex(staticTarget ? "33D2" : "488BD3");
            Hex("488BCE"); Relative("E8", 0x1080); Hex("488BC64883C4285E5BC3");
            body.ToArray().CopyTo(bytes, 0x200);
            // 构造入口存储目标和 MethodInfo；调用目标与共享规则由独立元数据登记给出。
            Convert.FromHexString("498B0048894110488951204C894128C3").CopyTo(bytes, 0x280);
            Convert.FromHexString(staticTarget ? "B825000000C3" : "8B4110C3").CopyTo(bytes, 0x2c0);
            bytes[0x2e0] = 0xc3;
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x400), 0x20000001);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x408), 0x60000009);
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException", "MulticastDelegate" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException" or "MulticastDelegate"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            if (!payloadClass && !staticTarget && !reverse) GenericReceiverSelectionTests.Run(original, decoder, core);
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = $"SharedDelegate{payloadClass}{staticTarget}{reverse}";
            TypeDef Define(int i, string name) => new() { Index = core.Length + i, Assembly = assemblyName + ".dll", Namespace = i == 0 ? "" : "Fixture", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public | (i is 4 or 5 ? TypeAttributes.Sealed : 0), IsValueType = false, IsEnum = false, Size = 24, BaseType = Corlib("Object") };
            var module = Define(0, "<Module>"); var owner = Define(1, "Factory"); var handler = Define(2, "Handler");
            var payload = Define(3, "Payload"); var signal = Define(4, "Signal`1"); var other = Define(5, "OtherSignal");
            var parameter = new GenericParameterDef { Name = "T", Position = 0, Attributes = GenericParameterAttributes.ReferenceTypeConstraint };
            signal.GenericParameters = [parameter];
            signal.BaseType = other.BaseType = Corlib("MulticastDelegate");
            TypeRef argument = payloadClass ? new DefinitionRef(payload, []) : Corlib("String");
            var actualType = new DefinitionRef(signal, [argument]);
            MethodDef Ctor(int i, TypeDef type) => new() { Index = i, Owner = type, Name = ".ctor", Token = (uint)(0x06000001 + i),
                Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, ImplAttributes = MethodImplAttributes.Runtime,
                Slot = -1, ReturnType = Corlib("Void"), Parameters = [new("target", Corlib("Object"), 0, null, false), new("method", Corlib("IntPtr"), 0, null, false)] };
            MethodDef Invoke(int i, TypeDef type, TypeRef arg) => new() { Index = i, Owner = type, Name = "Invoke", Token = (uint)(0x06000001 + i),
                Attributes = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot, ImplAttributes = MethodImplAttributes.Runtime,
                Slot = 0, ReturnType = Corlib("Int32"), Parameters = [new("value", arg, 0, null, false)] };
            var wrongCtor = Ctor(0, other); var wrongInvoke = Invoke(1, other, Corlib("Object"));
            var ctor = Ctor(2, signal); var invoke = Invoke(3, signal, new GenericParameterRef("T", false, 0) { Parameter = parameter });
            var handle = new MethodDef { Index = 4, Owner = handler, Name = "Handle", Token = 0x06000005, Address = basis + 0x10c0,
                Attributes = MethodAttributes.Public | (staticTarget ? MethodAttributes.Static : 0), ImplAttributes = 0, Slot = -1,
                ReturnType = Corlib("Int32"), Parameters = [new("value", argument, 0, null, false)] };
            var factory = new MethodDef { Index = 5, Owner = owner, Name = "Make", Token = 0x06000006, Address = basis + 0x1000,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = actualType,
                Parameters = [new("target", new DefinitionRef(handler, []), 0, null, false)] };
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 6, Owner = exception, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            var bias = new FieldDef { Index = 0, Owner = handler, Name = "Bias", Type = Corlib("Int32"), Offset = 16, Attributes = FieldAttributes.Public };
            handler.Fields = [bias]; handler.Methods = [handle]; owner.Methods = [factory]; signal.Methods = [ctor, invoke]; other.Methods = [wrongCtor, wrongInvoke]; exception.Methods = [exceptionCtor];
            var image = ImageDocument.Parse(bytes);
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            TypeDef[] fixtureTypes = [module, owner, handler, payload, signal, other];
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = fixtureTypes };
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, .. fixtureTypes],
                Methods = [wrongCtor, wrongInvoke, ctor, invoke, handle, factory, exceptionCtor], Fields = [bias], RuntimeTypes = [actualType], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            CodeEntry[] aliases = [new(basis + 0x1080, EntryKind.Method, MethodRef.Open(wrongCtor), 0, null),
                new(basis + 0x1080, EntryKind.GenericMethod, new MethodRef(ctor, [Corlib("Object")], []), 0, null)];
            var registered = (reverse ? aliases.Reverse() : aliases).Concat(new[] {
                new CodeEntry(handle.Address, EntryKind.Method, MethodRef.Open(handle), 0, null), new CodeEntry(factory.Address, EntryKind.Method, MethodRef.Open(factory), 0, null) }).ToArray();
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = registered,
                ByAddress = registered.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var addresses = registered.Select(e => e.Address).ToArray();
            var code = CodeMap.BuildPe(image, addresses); var scan = X64References.Scan(code, new PcodeMachine(image, decoder), addresses);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model),
                Helpers = RuntimeHelpers.FromEvidence(code, scan, [new(basis + 0x10e0, HelperKind.ObjectNew, null, "独立分配契约", 1)]),
                Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts); var recovery = new MethodDecompiler(facts, types);
            if (!payloadClass && !staticTarget && !reverse)
            {
                PipelineTests.Run(facts, bytes, assemblyName);
                ReferencePredicateTests.Run(bytes, decoder, core);
                ByRefLikeValidationTests.Run(core, bytes);
            }
            var result = recovery.Recover(MethodRef.Open(factory), factory.Address);
            Check(result.Body is not null, "共享泛型委托须通过完整恢复：" + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            // 被绑定方法独立写出；不使用恢复结果作为执行预期。
            var il = skeleton.Method(handle).Body.GetILProcessor(); il.Body.Instructions.Clear();
            if (staticTarget) il.Emit(OpCodes.Ldc_I4, 37);
            else { il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldfld, skeleton.Field(bias)); }
            il.Emit(OpCodes.Ret);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "共享委托须通过 CIL 写出检查");
            var emitted = skeleton.Method(factory).Body.Instructions;
            Check(emitted.Count(i => i.OpCode == OpCodes.Newobj) == 1 && emitted.Any(i => i.OpCode == OpCodes.Ldftn), "须复用委托构造，不得写普通 MethodInfo 指针");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray()); var make = loaded.GetType("Fixture.Factory", true)!.GetMethod("Make")!;
            var clrHandler = loaded.GetType("Fixture.Handler", true)!; var clrArgument = payloadClass ? loaded.GetType("Fixture.Payload", true)! : typeof(string);
            foreach (var value in new[] { int.MinValue, -1, 0, 37, int.MaxValue })
            {
                var target = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(clrHandler);
                clrHandler.GetField("Bias")!.SetValue(target, value);
                var actual = (Delegate)make.Invoke(null, [target])!;
                Check(actual.GetType().GetGenericTypeDefinition().FullName == "Fixture.Signal`1" && actual.GetType().GenericTypeArguments.Single() == clrArgument,
                    "构造类型必须保留分配时的泛型实参");
                Check(ReferenceEquals(actual.Target, staticTarget ? null : target), "静态与闭合实例绑定须保持目标身份");
                foreach (var input in new object?[] { null, payloadClass ? System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(clrArgument) : "payload" })
                    Check((int)actual.DynamicInvoke([input])! == (staticTarget ? 37 : value), "实际调用必须落到独立预期方法");
            }
        }
        Console.WriteLine("共享泛型委托完整恢复/CIL/CLR 对照通过：80 组输入，两个引用实参类型、静态/实例绑定及候选顺序");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
