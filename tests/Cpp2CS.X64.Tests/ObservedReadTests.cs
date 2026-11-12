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

internal static class ObservedReadTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        SelectedMemoryTests.Rejections();
        const ulong basis = 0x180000000;
        foreach (var variant in new[] { "field-address", "field-address-value", "field-address-write-copy", "field-address-unused", "field-address-static", "select-field", "select-object", "select-store", "select-loop", "select-null-store", "field", "nested", "unknown", "frame-read", "frame-opaque", "frame-struct", "overload", "overload-copy", "overload-extra", "overload-info", "overload-store", "overload-opaque",
            "overload-exception", "overload-prefix", "overload-return", "overload-name", "overload-owner", "overload-same-arity", "overload-stack" })
        {
            var frameRead = variant.StartsWith("frame-", StringComparison.Ordinal);
            var selected = variant.StartsWith("select-", StringComparison.Ordinal);
            var overload = frameRead || variant.StartsWith("overload", StringComparison.Ordinal);
            var frameStruct = variant == "frame-struct";
            var copy = variant is "overload-copy" or "field-address-value" or "field-address-write-copy" || frameStruct;
            var bytes = original.ToArray();
            var callerBytes = System.Convert.FromHexString("4883EC28E877000000B8070000004883C428C3");
            var calleeBytes = System.Convert.FromHexString(variant == "nested" ? "488B49108B4118C3" : "8B4118C3");
            var fieldAddress = variant.StartsWith("field-address", StringComparison.Ordinal);
            if (fieldAddress)
            {
                callerBytes = System.Convert.FromHexString(variant == "field-address-unused"
                    ? "4883EC28488B15F50F0000E870000000B8070000004883C428C3" : "4883EC28488B15F50F0000E8700000008B004883C428C3");
                calleeBytes = System.Convert.FromHexString("488B42104C6342184C03C183782800498D48F0490F49C8488BC1C3");
                if (variant == "field-address-write-copy") callerBytes = System.Convert.FromHexString("534883EC20488BD9C7430429000000488B15EA0F0000E865000000C7002B0000008B43044883C4205BC3");
            }
            if (overload)
            {
                callerBytes = System.Convert.FromHexString("4883EC288B5218E8740000004883C428C3");
                calleeBytes = System.Convert.FromHexString(variant switch {
                    "overload-extra" => "8BC203C1C3", "overload-info" => "418BC003C1C3", "overload-store" => "4883EC288912E8650000004883C4288BC1C3",
                    "overload-opaque" => "0F05C3", _ => "8BC1C3",
                });
            }
            if (copy && !fieldAddress) callerBytes = System.Convert.FromHexString("534883EC20498BD8E8730000000343044883C4205BC3");
            if (frameRead)
            {
                callerBytes = System.Convert.FromHexString("4883EC28894C2420488D4C2420E86E00000083C0054883C428C3");
                calleeBytes = System.Convert.FromHexString(variant == "frame-opaque" ? "0F0BC3" : "8B01C3");
                if (frameStruct) callerBytes = System.Convert.FromHexString("534883EC30488BD94889542420488D4C2420E8690000004863C08B4483204883C4305BC3");
            }
            if (selected) callerBytes = System.Convert.FromHexString(variant switch
            {
                "select-field" => "B81800000041B81C00000085D2490F45C08B0401C3",
                "select-object" => "4584C0480F45CA8B4118C3",
                "select-loop" => "31C04585C07E1B41B91800000041BA1C00000085D24D0F45CA4203040941FFC875F7C3",
                "select-null-store" => "31C085D2480F45C844894118418BC0C3",
                _ => "4584C0480F45CA448949188B4118C3",
            });
            callerBytes.CopyTo(bytes, 0x200); calleeBytes.CopyTo(bytes, 0x280);
            bytes[0x2f0] = 0xc3;
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + callerBytes.Length)); U32(0x708, 0x3140);
            U32(0x70c, 0x1080); U32(0x710, (uint)(0x1080 + calleeBytes.Length)); U32(0x714, 0x3150); bytes[0x740] = 1; bytes[0x750] = 1;
            if (variant == "overload-exception") { bytes[0x750] = 9; U32(0x754, 0x10f0); bytes[0x2f0] = 0xc3; }
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = "ObservedRead" + variant;
            var module = new TypeDef { Index = core.Length, Assembly = assemblyName + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001,
                Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false, Size = 0 };
            var holder = new TypeDef { Index = core.Length + 1, Assembly = module.Assembly, Namespace = "Fixture", Name = "Holder", Token = 0x02000002,
                Attributes = TypeAttributes.Public | (copy ? TypeAttributes.SequentialLayout : 0), IsValueType = copy, IsEnum = false,
                Size = frameStruct ? 8 : copy ? 12 : 32, BaseType = Corlib(copy ? "ValueType" : "Object") };
            var type = new DefinitionRef(holder, []);
            holder.Fields = [new() { Index = 0, Owner = holder, Name = "child", Type = type, Attributes = FieldAttributes.Public, Offset = 16 },
                new() { Index = 1, Owner = holder, Name = "number", Type = Corlib("Int32"), Attributes = FieldAttributes.Public
                    | (variant == "field-address-static" ? FieldAttributes.Static : 0), Offset = 24 }];
            if (selected) holder.Fields = [.. holder.Fields, new() { Index = 2, Owner = holder, Name = "other", Type = Corlib("Int32"), Attributes = FieldAttributes.Public, Offset = 28 }];
            if (copy) holder.Fields = Enumerable.Range(0, frameStruct ? 2 : 3).Select(i => new FieldDef { Index = i, Owner = holder, Name = i == 1 ? "number" : "p" + i,
                Type = Corlib("Int32"), Attributes = FieldAttributes.Public, Offset = i * 4 }).ToArray();
            var owner = new TypeDef { Index = core.Length + 2, Assembly = module.Assembly, Namespace = "Fixture", Name = "Reader", Token = 0x02000003,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16, BaseType = Corlib("Object") };
            var caller = MethodRef.Open(new MethodDef { Index = 0, Owner = owner, Name = "Run", Token = 0x06000001,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, Address = basis + 0x1000,
                ReturnType = Corlib("Int32"), Parameters = frameStruct ? [new("items", new ArrayRef(Corlib("Int32"), 1), 0, null, false), new("value", type, 0, null, false)] : frameRead ? [new("number", Corlib("Int32"), 0, null, false)] : copy
                    ? [new("number", Corlib("Int32"), 0, null, false), new("padding", Corlib("Int32"), 0, null, false), new("value", type, 0, null, false)] : overload
                    ? [new("number", Corlib("Int32"), 0, null, false), new("value", type, 0, null, false)]
                    : [new("value", variant == "unknown" ? Corlib("IntPtr") : type, 0, null, false)] });
            if (selected) caller.Method.Parameters = variant is "select-field" or "select-loop" or "select-null-store"
                ? [new("value", type, 0, null, false), new("flag", Corlib("Boolean"), 0, null, false),
                    .. variant is "select-loop" or "select-null-store" ? new[] { new ParameterDef("number", Corlib("Int32"), 0, null, false) } : []]
                : [new("left", type, 0, null, false), new("right", type, 0, null, false), new("flag", Corlib("Boolean"), 0, null, false),
                    .. variant == "select-store" ? new[] { new ParameterDef("number", Corlib("Int32"), 0, null, false) } : []];
            if (fieldAddress && copy) caller.Method.Parameters = [new("value", type, 0, null, false)];
            owner.Methods = [caller.Method];
            var other = new TypeDef { Index = core.Length + 3, Assembly = module.Assembly, Namespace = "Fixture", Name = "Other", Token = 0x02000004,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16, BaseType = Corlib("Object") };
            MethodDef Overload(int index, int count) => new() { Index = index, Owner = variant == "overload-owner" && index == 2 ? other : owner,
                Name = frameRead ? "Read" + index : variant == "overload-name" && index == 2 ? "Different" : "Pick", Token = (uint)(0x06000001 + index), Address = basis + 0x1080,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
                ReturnType = variant == "overload-return" && index == 2 ? Corlib("UInt32") : Corlib("Int32"),
                Parameters = Enumerable.Range(0, count).Select(i => new ParameterDef("arg" + i,
                    frameRead && i == 0 ? new ByRefRef(frameStruct ? type : Corlib("Int32")) : variant == "overload-prefix" && index == 2 && i == 0 ? Corlib("UInt32") : Corlib("Int32"), 0, null, false)).ToArray() };
            var shortest = Overload(1, variant == "overload-stack" ? 3 : 1);
            var longest = Overload(2, variant == "overload-stack" ? 4 : variant == "overload-same-arity" ? 1 : 2);
            if (overload)
            {
                owner.Methods = longest.Owner == owner ? [caller.Method, shortest, longest] : [caller.Method, shortest];
                if (longest.Owner != owner) other.Methods = [longest];
            }
            var nullReference = core.Single(t => t.Name == "NullReferenceException");
            var nullConstructor = new MethodDef { Index = overload ? 3 : 1, Owner = nullReference, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1 };
            nullReference.Methods = [nullConstructor];
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, holder, owner, other] };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, module, holder, owner, other],
                Methods = overload ? [caller.Method, shortest, longest, nullConstructor] : [caller.Method, nullConstructor], Fields = holder.Fields, RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var code = CodeMap.BuildPe(image, [caller.Method.Address]); var scan = CodeScan.Unscanned(code);
            CodeEntry[] entries = overload ? [new(caller.Method.Address, EntryKind.Method, caller, 0, null),
                new(basis + 0x1080, EntryKind.Method, MethodRef.Open(shortest), 0, null), new(basis + 0x1080, EntryKind.Method, MethodRef.Open(longest), 0, null)]
                : [new(caller.Method.Address, EntryKind.Method, caller, 0, null)];
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var helpers = fieldAddress ? RuntimeHelpers.FromEvidence(code, scan,
                [new(basis + 0x1080, HelperKind.FieldAddress, null, "独立字段地址契约", 1)]) : RuntimeHelpers.Unclassified(code, scan);
            var usages = fieldAddress ? new UsageSlots { Slots = new Dictionary<ulong, UsageSlot> {
                [basis + 0x2000] = new(basis + 0x2000, new(UsageKind.FieldInfo, 1, new FieldRef(holder.Fields[1], type)), 1, 0) },
                UnreferencedDecodable = new Dictionary<ulong, Usage>(), SlotAddressBeforeCall = new Dictionary<ulong, int>() } : UsageSlots.Build(model, code, scan);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model),
                Helpers = helpers, Usages = usages, Checks = new(),
                MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts);
            var recovery = new MethodDecompiler(facts, types);
            if (frameRead)
            {
                Check(recovery.Analyze(caller, caller.Method.Address).TryGet(out var analysis, out _), "栈上只读共享调用须完成分析");
                if (variant == "frame-opaque")
                {
                    Check(analysis!.Memory.Cells.Any(c => !c.Promoted) && analysis.Function.Blocks.SelectMany(b => b.Statements).OfType<Cpp2CS.Ir.Call>().Any(),
                        "未获原生证明的调用须保留真实逃逸");
                    Check(recovery.Recover(caller, caller.Method.Address).Body is null, "未知调用及栈槽不得冒充恢复成功");
                    continue;
                }
                Check(analysis!.Memory.Cells.All(c => c.Promoted) && !analysis.Function.Blocks.SelectMany(b => b.Statements).OfType<Cpp2CS.Ir.Call>().Any(),
                    "先展开再划分内存，不保留已消失调用的逃逸记录");
                var recovered = recovery.Recover(caller, caller.Method.Address);
                Check(recovered.Body is not null, "只读共享体须通过完整栈局部恢复：" + string.Join(';', recovered.Holes.Select(h => h.Reason)));
                var frameSkeleton = new Skeleton(model);
                var frameErrors = new BodyEmitter(frameSkeleton, types).Emit([recovered.Body!]);
                Check(frameErrors.Count == 0, "栈局部读取须通过 CIL 写出检查：" + string.Join(';', frameErrors) + "\n" + string.Join('\n', recovered.Body!.Blocks.SelectMany(b => b.Statements)));
                using var frameStream = new MemoryStream(); frameSkeleton.Assembly(module.Assembly).Write(frameStream);
                var frameAssembly = Assembly.Load(frameStream.ToArray()); var frameRun = frameAssembly.GetType("Fixture.Reader", true)!.GetMethod("Run")!;
                if (frameStruct)
                {
                    var payloadType = frameAssembly.GetType("Fixture.Holder", true)!; var payload = Activator.CreateInstance(payloadType)!;
                    var array = new[] { int.MinValue, -17, 0, 13, int.MaxValue };
                    foreach (var tag in new[] { int.MinValue, 0, int.MaxValue })
                    for (var position = 0; position < array.Length; position++)
                    {
                        payloadType.GetField("p0")!.SetValue(payload, position); payloadType.GetField("number")!.SetValue(payload, tag);
                        Check((int)frameRun.Invoke(null, [array, payload])! == array[position], "数组下标须投影结构体中的完整整数字段");
                    }
                    continue;
                }
                foreach (var number in new[] { int.MinValue, -17, -1, 0, 1, 7, int.MaxValue })
                    Check((int)frameRun.Invoke(null, [number])! == unchecked(number + 5), "独立原生栈读及后继算术须保持");
                continue;
            }
            if (overload)
            {
                Check(recovery.Analyze(caller, caller.Method.Address).TryGet(out var analysis, out _), "重载夹具的调用方须完整分析");
                var call = analysis!.Function.Blocks.SelectMany(b => b.Statements).OfType<Cpp2CS.Ir.Call>().SingleOrDefault();
                Check((call?.Resolved?.Method == shortest) == (variant is "overload" or "overload-copy"), "只按未用后缀、隐藏上下文、完整同名签名及 ABI 证明消歧：" + variant);
                if (variant is not ("overload" or "overload-copy"))
                {
                    if (call is not null) continue;
                    Check(analysis.Function.NativeExpansions.Any(e => e.Inlinee == basis + 0x1080), "不确定托管声明只能按完整原生体展开，不能伪造调用身份");
                    if (variant == "overload-info")
                    {
                        Check(recovery.Recover(caller, caller.Method.Address).Body is null, "未获托管表示的 MethodInfo 算术不能因原生展开冒充完整恢复");
                        continue;
                    }
                }
                if (copy) Check(analysis.Memory.Cells.Where(c => c.Space.Kind == Cpp2CS.Recovery.Memory.LocalKind.Argument).All(c => c.Promoted),
                    "确定签名后的多余 R8 不得使结构体副本逃逸");
            }
            var result = recovery.Recover(caller, caller.Method.Address);
            if (variant == "field-address-static")
            {
                Check(result.Body is null, "实例字段地址算法不能冒充静态字段访问");
                continue;
            }
            if (selected)
            {
                SelectedMemoryTests.NativeCheck(callerBytes, variant);
                Check(result.Body is not null && result.Holes.Count == 0, "条件地址必须完整恢复：" + string.Join(';', result.Holes.Select(h => h.Reason)));
                var selectedSkeleton = new Skeleton(model);
                var errors = new BodyEmitter(selectedSkeleton, types).Emit([result.Body!]);
                Check(errors.Count == 0, "条件访存须通过 CIL 检查：" + string.Join(';', errors.Values));
                using var selectedStream = new MemoryStream(); selectedSkeleton.Assembly(module.Assembly).Write(selectedStream);
                var selectedAssembly = Assembly.Load(selectedStream.ToArray());
                void ExecuteSelection(Assembly selectedAssembly)
                {
                    var payloadType = selectedAssembly.GetType("Fixture.Holder", true)!;
                    var invoke = selectedAssembly.GetType("Fixture.Reader", true)!.GetMethod("Run")!;
                    var left = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(payloadType);
                    var right = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(payloadType);
                    foreach (var number in new[] { int.MinValue, -1, 0, 1, 17, int.MaxValue })
                        foreach (var flag in new[] { false, true })
                        {
                            payloadType.GetField("number")!.SetValue(left, number); payloadType.GetField("other")!.SetValue(left, ~number);
                            payloadType.GetField("number")!.SetValue(right, ~number);
                            if (variant == "select-null-store")
                            {
                                if (flag) ThrowsNull(invoke, left, flag, 41);
                                else Check((int)invoke.Invoke(null, [left, flag, 41])! == 41 && (int)payloadType.GetField("number")!.GetValue(left)! == 41,
                                    "有类型的空引用选择不能退化成无类型绝对地址");
                                ThrowsNull(invoke, null, flag, 41);
                            }
                            else if (variant == "select-loop")
                            {
                                foreach (var count in new[] { -1, 0, 1, 3, 5 })
                                    Check((int)invoke.Invoke(null, [left, flag, count])! == unchecked((flag ? ~number : number) * Math.Max(0, count)), "循环中条件读取须保持入边 phi 与模加法");
                                Check((int)invoke.Invoke(null, [null, flag, 0])! == 0, "零次循环不得引入空引用读取");
                                ThrowsNull(invoke, null, flag, 1);
                            }
                            else if (variant == "select-field")
                            {
                                Check((int)invoke.Invoke(null, [left, flag])! == (flag ? ~number : number), "CMOV 字段地址选择保持实际读取");
                                ThrowsNull(invoke, null, flag);
                            }
                            else if (variant == "select-object")
                            {
                                Check((int)invoke.Invoke(null, [flag ? null : left, flag ? right : null, flag])! == (flag ? ~number : number), "未选中的空对象不能被提前读取");
                                ThrowsNull(invoke, flag ? left : null, flag ? null : right, flag);
                            }
                            else
                            {
                                Check((int)invoke.Invoke(null, [left, right, flag, 41])! == 41, "条件存储和后续读取必须指向同一位置");
                                Check((int)payloadType.GetField("number")!.GetValue(flag ? left : right)! == (flag ? number : ~number), "条件存储不能修改另一侧对象");
                                Check((int)invoke.Invoke(null, [flag ? null : left, flag ? right : null, flag, number])! == number, "未选中的空对象不能被写入");
                                ThrowsNull(invoke, flag ? left : null, flag ? null : right, flag, 41);
                            }
                        }
                }
                ExecuteSelection(selectedAssembly);
                if (Environment.GetEnvironmentVariable("CPP2CS_TEST_CSC") is not null)
                {
                    var directory = Path.Combine(Path.GetTempPath(), "Cpp2CS-selected-memory-" + Guid.NewGuid().ToString("N"));
                    var assemblies = Path.Combine(directory, "assemblies");
                    selectedSkeleton.Write(assemblies);
                    SourceProject.Write(Path.Combine(assemblies, module.Assembly), assemblies, Path.Combine(directory, "src"), _ => true);
                    if (SourceCompilation.Check(directory, assemblyName) is { } compiled) ExecuteSelection(Assembly.Load(File.ReadAllBytes(compiled)));
                }
                continue;
            }
            if (variant == "unknown")
            {
                Check(result.Body is null && result.Holes.Count > 0, "不能表达的未用读取须保留失败诊断");
                continue;
            }
            Check(result.Body is not null && result.Holes.Count == 0, "未用读取应经过完整恢复：" + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            if (overload)
                foreach (var definition in new[] { shortest, longest })
                {
                    var il = skeleton.Method(definition).Body.GetILProcessor(); il.Body.Instructions.Clear();
                    il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ret);
                }
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "未用读取须通过 CIL 写出检查");
            if (!fieldAddress) Check(skeleton.Method(caller.Method).Body.Instructions.Count(i => i.OpCode == OpCodes.Ldfld) == (variant == "nested" ? 2 : 1), "实际 CIL 必须保留未用字段读取");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray());
            var holderType = loaded.GetType("Fixture.Holder", true)!;
            var run = loaded.GetType("Fixture.Reader", true)!.GetMethod("Run")!;
            var instance = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(holderType);
            var child = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(holderType);
            if (!copy) holderType.GetField("child")!.SetValue(instance, child);
            holderType.GetField("number")!.SetValue(instance, int.MinValue);
            holderType.GetField("number")!.SetValue(child, int.MaxValue);
            if (fieldAddress)
            {
                if (variant == "field-address-unused")
                {
                    Check((int)run.Invoke(null, [null])! == 7, "只计算未使用地址时不得引入空引用异常");
                    continue;
                }
                foreach (var value in new[] { int.MinValue, -1, 0, 1, 17, int.MaxValue })
                {
                    holderType.GetField("number")!.SetValue(instance, value);
                    Check((int)run.Invoke(null, [instance])! == (variant == "field-address-write-copy" ? 43 : value), "实例字段地址必须保留实际位置、写入与读取");
                    if (copy) Check((int)holderType.GetField("number")!.GetValue(instance)! == value, "按值参数的副本写入不能修改调用者原值");
                }
                if (!copy) ThrowsNull(run, (object?)null);
                continue;
            }
            if (copy)
            {
                foreach (var input in new[] { int.MinValue, -1, 0, 1, 7, int.MaxValue })
                foreach (var field in new[] { int.MinValue, -1, 0, 1, 7, int.MaxValue })
                {
                    holderType.GetField("number")!.SetValue(instance, field);
                    Check((int)run.Invoke(null, [input, 19, instance])! == unchecked(input + field), "多余寄存器不影响副本字段及调用返回值");
                }
            }
            else if (overload)
            {
                foreach (var input in new[] { int.MinValue, -1, 0, 1, 7, int.MaxValue })
                    Check((int)run.Invoke(null, [input, instance])! == (variant == "overload-extra" ? unchecked(input + 7) : input), "共享重载及无身份展开应保持完整机器码的实际返回值");
                ThrowsNull(run, 7, null);
            }
            else
            {
                Check((int)run.Invoke(null, [instance])! == 7, "读取值未参与返回，但原生返回常量必须保持");
                ThrowsNull(run, (object?)null);
            }
            if (variant == "nested")
            {
                holderType.GetField("child")!.SetValue(instance, null);
                ThrowsNull(run, instance);
            }
        }
        Console.WriteLine("条件访存完整恢复/CIL/CLR 对照通过：36 组字段／对象／存储选择与 60 组循环输入，未选中空对象、零次循环、选中空对象异常及单侧写入；展开与共享重载、读取顺序和逃逸反例通过");
    }

    private static void ThrowsNull(MethodInfo method, params object?[] arguments)
    {
        try { method.Invoke(null, arguments); }
        catch (TargetInvocationException e) when (e.InnerException is NullReferenceException) { return; }
        throw new InvalidOperationException("原生未用读取的空引用异常被丢弃");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}
