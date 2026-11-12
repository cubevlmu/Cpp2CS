using Cpp2CS.Facts;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Ssa;

namespace Cpp2CS.Machine.Lifting;

using Storage = Cpp2CS.Ir.Storage;

/// <summary>一个调用目标读取与写出的寄存器，以及依据。</summary>
public sealed record CallSignature(Storage[] Reads, Storage[] Results, string Source)
{
    /// <summary>托管签名中 MethodInfo* 参数的寄存器（IL2CPP 常不设置它，或原样转传调用方收到的值）。</summary>
    public Storage? MethodInfo { get; init; }
}

/// <summary>
/// 按事实层确定调用读写的寄存器：
/// 托管方法入口按元数据签名（<see cref="ManagedAbi"/>）；调用器按 InvokerMethod 原型；
/// 运行时 helper 按 libil2cpp 2022.3 codegen 接口的原型（见 <see cref="Helper"/>）；
/// 其余（间接调用、未识别目标、无法分类的签名）退回保守约定。
/// 实例按目标缓存，不是线程安全的。
/// </summary>
public sealed class FactsCallModel : ICallModel
{
    private readonly ProgramFacts facts;
    private readonly ManagedAbi abi;
    private readonly ConservativeCallModel conservative;
    private readonly CallingConvention convention;
    private readonly bool useNativeCopies;
    private readonly Dictionary<ulong, CallSignature?> cache = new();

    public FactsCallModel(BaseFacts facts, CallingConvention convention) : this(new ProgramFacts(facts, new()), convention) { }

    public FactsCallModel(ProgramFacts facts, CallingConvention convention, bool useNativeCopies = true)
    {
        this.facts = facts;
        this.convention = convention;
        this.useNativeCopies = useNativeCopies;
        abi = facts.CreateAbi();
        conservative = new ConservativeCallModel(convention);
    }

    private static Storage X(int i) => Storage.Gpr(i);

    /// <summary>
    /// helper 原型（libil2cpp 2022.3 codegen/il2cpp-codegen.h 与 vm 导出）：
    /// InitMetadata(uintptr_t* slot) → 槽位的值；InitializedTypeInfo(klass) → klass；il2cpp_runtime_class_init(klass)；
    /// NullCheck(obj)（未内联的判空）；il2cpp_object_new(klass) → obj；il2cpp_array_new_specific(klass, length) → array；il2cpp_value_box(klass, data) → obj；
    /// IsInst(obj, klass) → obj；il2cpp_class_is_assignable_from(klass, oklass) → bool；il2cpp_gc_wbarrier_set_field 的写屏障(ptr, value)；
    /// 接口慢路径(obj, klass, slot) → VirtualInvokeData*；il2cpp_raise_exception(ex, lastManagedFrame)；Rethrow(ex)；
    /// InitMethodRgctx(method) → method；dmb 屏障无参数。其余 helper 退回保守约定。
    /// </summary>
    private static CallSignature? Helper(RuntimeHelper helper) => helper.Kind switch
    {
        // vm::MetadataCache::InitializeRuntimeMetadata(uintptr_t*) 返回槽位初始化之后的值；两个包装都保留 x0（一个加 dmb 后返回，一个直接尾调用）
        HelperKind.InitMetadata => new([X(0)], [X(0)], "helper"),
        HelperKind.InitializedTypeInfo or HelperKind.ObjectNew or HelperKind.InitMethodRgctx => new([X(0)], [X(0)], "helper"),
        HelperKind.ClassInit or HelperKind.NullCheck => new([X(0)], [], "helper"),
        HelperKind.NewArray or HelperKind.Box or HelperKind.IsInst or HelperKind.IsAssignableFrom => new([X(0), X(1)], [X(0)], "helper"),
        HelperKind.WriteBarrier => new([X(0), X(1)], [], "helper"),
        HelperKind.InterfaceLookup => new([X(0), X(1), X(2)], [X(0)], "helper"),
        HelperKind.Raise => new([X(0), X(1)], [], "helper"),
        HelperKind.Rethrow => new([X(0)], [], "helper"),
        HelperKind.Throw => new([], [], "helper"),
        HelperKind.GetException => new([], [X(0)], "helper"),
        HelperKind.MemoryBarrier => new([], [], "helper"),
        HelperKind.CompareExchangeReference => new([X(0), X(1), X(2)], [X(0)], "helper"),
        HelperKind.ReadByteArray => new([X(0), X(1)], [X(0)], "native-array-read"),
        HelperKind.GenericHasValue => new([X(0), X(1)], [X(0)], "generic-value-check"),
        HelperKind.ConstrainedCall => new([X(0), X(1), X(2), X(3), X(4), X(5)], [], "constrained-call"),
        HelperKind.UnboxAny => new([X(0), X(1), X(2)], [X(0)], "unbox-any"),
        HelperKind.Import => helper.Detail switch
        {
            "memcpy" or "memmove" or "memset" => new([X(0), X(1), X(2)], [X(0)], "libc"),
            "__stack_chk_fail" => new([], [], "libc"),
            "modf" => new([X(0), Storage.Vec(0)], [Storage.Vec(0)], "libm"),
            "sincosf" => new([X(0), X(1), Storage.Vec(0)], [], "libm"),
            var symbol when MathImportSignature.Find(symbol) is { } signature =>
                new(Enumerable.Range(0, signature.Parameters.Length).Select(signature.Register).ToArray(), [Storage.Vec(0)], "libm"),
            "__cxa_begin_catch" => new([X(0)], [X(0)], "libc++abi"),
            "__cxa_end_catch" => new([], [], "libc++abi"),
            _ => null,
        },
        _ => null,
    };

    /// <summary>目标的签名；没有可靠依据时为 null（调用方使用保守约定）。</summary>
    public CallSignature? Signature(ulong target)
    {
        if (cache.TryGetValue(target, out var cached)) return cached;
        CallSignature? signature = null;
        if (facts.AdjustorTargets.At(target) is { } adjusted && abi.Classify(adjusted.Method, out _) is { } adjustedSignature)
            signature = new(adjustedSignature.Reads, adjustedSignature.Results, "registered-adjustor-target") { MethodInfo = adjustedSignature.MethodInfo?.Register };
        else if (facts.Unregistered.At(target) is { } identity)
            signature = new(identity.Abi.Reads, identity.Abi.Results, "inferred-definition") { MethodInfo = identity.Abi.MethodInfo?.Register };
        else if (facts.Helpers.At(target) is { } helper) signature = facts.Model.Image.Architecture == Architecture.X64 ? Win64Helper(helper) : Helper(helper);
        else
        {
            if (facts.Model.Image.Architecture == Architecture.X64)
            {
                var entries = facts.EntriesAt(target);
                if (entries.Length == 0 && useNativeCopies) entries = facts.NativeCopies.At(target);
                // 元数据 31 的 InvokerMethod 返回 void；第五参数由调用点 SP 读取，不伪造寄存器结果。
                if (facts.Model.MetadataVersion == 31 && entries.Length > 0 && entries.All(e => e.Kind == EntryKind.Invoker))
                    return cache[target] = new([X(1), X(2), X(8), X(9)], [], "Win64-invoker");
                var classified = entries.Where(e => e.Kind is EntryKind.Method or EntryKind.GenericMethod or EntryKind.AdjustorThunk or EntryKind.GenericAdjustorThunk)
                    .Select(e => e.Method is { } method ? abi.Classify(method, out _) : null).ToArray();
                // ICF 可合并不同签名。机器层保留各候选的输入/输出并集，托管身份仍由后续形状和类型证明决定。
                if (!entries.Any(e => e.Kind == EntryKind.Invoker) && classified.Length > 0 && classified.All(s => s is not null))
                    signature = new(classified.SelectMany(s => s!.Reads).Distinct().ToArray(),
                        classified.SelectMany(s => s!.Results).Distinct().ToArray(),
                        facts.EntriesAt(target).Length == 0 ? "Win64-proven-copy-union" : "Win64-metadata-union")
                    {
                        MethodInfo = classified.Select(s => s!.MethodInfo?.Register).Distinct().ToArray() is [var info] ? info : null,
                    };
                if (signature is null && facts.NativeCalls.At(target) is { } native)
                    signature = new(native.Inputs, native.Written, "proven-native-straight-line");
                if (signature is null && facts.NativeInputs.TryGetValue(target, out var inputs))
                    signature = new(inputs.Reads, convention.IntegerResults.Concat(convention.FloatResults).ToArray(), "Win64-export-derived-native-inputs");
                return cache[target] = signature;
            }
            foreach (var entry in facts.EntriesAt(target))
            {
                if (entry.Kind == EntryKind.Invoker)
                {
                    if (facts.Model.Image.Architecture == Architecture.X64) break;
                    // void (*InvokerMethod)(Il2CppMethodPointer, const MethodInfo*, void* obj, void** args, void* returnValue)
                    signature = new([X(0), X(1), X(2), X(3), X(4)], [], "invoker");
                    break;
                }
                if (entry is { Method: { } method, Kind: EntryKind.Method or EntryKind.GenericMethod or EntryKind.AdjustorThunk or EntryKind.GenericAdjustorThunk }
                    && abi.Classify(method, out _) is { } classified)
                {
                    signature = new(classified.Reads, classified.Results, "metadata") { MethodInfo = classified.MethodInfo?.Register };
                    break;
                }
            }
        }
        cache[target] = signature;
        return signature;
    }

    private CallSignature? Of(Call call) =>
        call.Op?.Kind == OpKind.MemoryBarrier ? new([], [], "machine-memory-barrier") :
        facts.Model.Image.Architecture == Architecture.X64 && call.Target is Load { Width: 64, Address: Const slot }
            && facts.Model.Image.Imports.TryGetValue(slot.Value, out var name)
            && facts.Model.Image.ImportModules.GetValueOrDefault(slot.Value)?.ToLowerInvariant() is { } module
            && WindowsImport(module, name) is { } imported ? imported :
        call is { Kind: CallKind.Direct or CallKind.Tail, Target: Const target } ? Signature(target.Value) : null;

    private static CallSignature? WindowsImport(string module, string name)
    {
        // MSVC 无参自由函数的完整修饰尾部给出 ABI；这里只取得机器读写位置，不推断副作用。
        if (name.StartsWith('?') && new[] { "@@YA_JXZ", "@@YA_KXZ", "@@YAHXZ", "@@YAIXZ", "@@YA_NXZ" }
            .Any(tail => name.EndsWith(tail, StringComparison.Ordinal))) return new([], [X(0)], "Win64-decorated-import");
        if (name.StartsWith('?') && name.EndsWith("@@YAXXZ", StringComparison.Ordinal)) return new([], [], "Win64-decorated-import");
        if (module is not ("kernel32.dll" or "kernelbase.dll" or "ntdll.dll") && !module.StartsWith("api-ms-win-core-", StringComparison.Ordinal)) return null;
        return name switch
    {
        "GetCurrentThreadId" or "GetCurrentProcessId" or "GetCurrentProcess" or "GetLastError" => new([], [X(0)], "Win64-system-import"),
        "EnterCriticalSection" or "LeaveCriticalSection" or "RtlEnterCriticalSection" or "RtlLeaveCriticalSection" => new([X(1)], [], "Win64-system-import"),
        _ => null,
    };
    }

    private static CallSignature? Win64Helper(RuntimeHelper helper) => helper.Kind switch
    {
        HelperKind.ObjectNew or HelperKind.InitMetadata or HelperKind.InitializedTypeInfo => new([X(1)], [X(0)], "Win64-runtime"),
        HelperKind.NewArray or HelperKind.Box or HelperKind.IsAssignableFrom => new([X(1), X(2)], [X(0)], "Win64-export"),
        HelperKind.FieldAddress => new([X(1), X(2)], [X(0)], "Win64-field-address-proof"),
        HelperKind.ClassInit or HelperKind.Raise or HelperKind.Rethrow => new([X(1)], [], "Win64-export"),
        HelperKind.Throw => new([], [], "Win64-exception"),
        HelperKind.CodegenRaise => new([X(1), X(2)], [], "Win64-codegen-throw"),
        HelperKind.InterfaceLookup => new([X(1), X(2), X(8)], [X(0)], "Win64-interface-lookup"),
        HelperKind.GcNotification => new([X(1)], [], "Win64-GC-notification"),
        HelperKind.Import when helper.Detail == "_CxxThrowException" => new([X(1), X(2)], [], "Win64-Cxx-throw"),
        HelperKind.Import when helper.Detail == "modf" => new([X(2), Storage.Vec(0)], [Storage.Vec(0)], "Win64-UCRT-out"),
        HelperKind.Import when helper.Detail is "memcpy" or "memmove" or "memset" => new([X(1), X(2), X(8)], [X(0)], "Win64-CRT-memory"),
        HelperKind.Import when MathImportSignature.Find(helper.Detail) is { } math =>
            new(Enumerable.Range(0, math.Parameters.Length).Select(i => math.IsInteger(i) ? X(i == 0 ? 1 : 2) : Storage.Vec(i)).ToArray(),
                [Storage.Vec(0)], "Win64-UCRT-math"),
        _ => null,
    };

    public IReadOnlyList<Storage> Reads(Call call) => Of(call)?.Reads ?? conservative.Reads(call);

    public IReadOnlyList<Storage> Results(Call call) =>
        call.Kind is CallKind.Tail or CallKind.TailIndirect ? [] : Of(call)?.Results ?? conservative.Results(call);

    public IReadOnlyList<Storage> Clobbers(Call call) => call.Op?.Kind == OpKind.MemoryBarrier ? [] : convention.Clobbered;
}
