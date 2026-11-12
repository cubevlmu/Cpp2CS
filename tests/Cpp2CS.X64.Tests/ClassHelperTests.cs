using System.Buffers.Binary;
using System.Text;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class ClassHelperTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        var bytes = original.ToArray();
        const ulong basis = 0x180000000;
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        void Code(int at, string value) => System.Convert.FromHexString(value).CopyTo(bytes, at - 0xe00);
        void Relative(int at, int target) => BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(at - 0xe00), target - at - 4);
        foreach (var directory in new[] { 0x130, 0x134, 0x150, 0x154, 0x158, 0x15c }) U32(directory, 0);
        Array.Clear(bytes, 0x400, 0x200);
        U32(0x10c, 0x200); U32(0x414, 5); U32(0x418, 5);
        U32(0x41c, 0x2040); U32(0x420, 0x2060); U32(0x424, 0x2080);
        (string Name, uint Address)[] exports = [
            ("il2cpp_class_instance_size", 0x1060), ("mono_class_instance_size", 0x1040),
            ("il2cpp_class_is_inited", 0x10b0), ("il2cpp_gchandle_get_target", 0x10c0),
            ("il2cpp_raise_exception", 0x10d0)];
        var nameAt = 0x490;
        for (var i = 0; i < exports.Length; i++)
        {
            U32(0x440 + i * 4, exports[i].Address); U32(0x460 + i * 4, (uint)(nameAt + 0x1c00));
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x480 + i * 2), (ushort)i);
            nameAt += Encoding.ASCII.GetBytes(exports[i].Name + "\0", bytes.AsSpan(nameAt));
        }
        Code(0x1000, "40534883EC20488BD9E8000000004883BBA0010000007509488BC34883C4205BC3488B8BA0010000E800000000488BC833D2E800000000CC");
        Relative(0x100a, 0x1080); Relative(0x1029, 0x10c0); Relative(0x1033, 0x10e0);
        Code(0x1040, "40534883EC20488BD9E800000000488BCB4883C4205BE900000000");
        Relative(0x104a, 0x1080); Relative(0x1057, 0x1060);
        Code(0x1060, "8B81F8000000C3");
        Code(0x1080, "48895C241048896C24184889742420574883EC20488BF9F68155010000020F8500000000C3");
        Code(0x10b0, "0FB68155010000D0E82401C3");
        Code(0x10c0, "C3");
        Code(0x10d0, "4883EC2833D2E800000000CC"); Relative(0x10d7, 0x10e0);
        Code(0x10e0, "BA01000000FF1500000000CC"); Relative(0x10e7, 0x3090);
        U32(0x704, 0x1038); U32(0x708, 0x3140); U32(0x124, 24);
        U32(0x70c, 0x10e0); U32(0x710, 0x10ec); U32(0x714, 0x3140); bytes[0x740] = 1;
        RuntimeHelper[] Identify(byte[] data, bool managed = false)
        {
            var image = ImageDocument.Parse(data);
            var map = CodeMap.BuildPe(image, managed ? [basis + 0x1000] : []);
            var scan = CodeScan.FromReferences(map, new Dictionary<ulong, CodeRef[]> {
                [basis + 0x1000] = [new(basis + 0x1000, basis + 0x1000, RefKind.Call, 0)] });
            return X64RuntimeHelpers.Identify(map, scan, new PcodeMachine(image, decoder));
        }
        Check(Identify(bytes).Any(h => h.Address == basis + 0x1000 && h.Kind == HelperKind.InitializedTypeInfo), "布局初始化返回包装与独立导出锚点");
        var contractImage = ImageDocument.Parse(bytes); var contractMap = CodeMap.BuildPe(contractImage, []);
        var contracts = X64NativeContracts.Identify(contractMap);
        Check(contracts.TryGetValue(basis + 0x1080, out var native) && native.Reads.SequenceEqual([Storage.Gpr(1)]),
            "布局初始化输入契约由完整导出转发及两个布局访问器核对，不声明托管 cctor 语义");
        var model = new Cpp2CS.Model.ProgramModel { Image = contractImage, MetadataVersion = 31, Assemblies = [], Types = [], Methods = [], Fields = [],
            RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
        var contractScan = CodeScan.Unscanned(contractMap);
        var facts = new ProgramFacts(new BaseFacts { Model = model, Code = contractMap, Scan = contractScan, NativeInputs = contracts,
            Layouts = new FieldLayouts(model), Helpers = RuntimeHelpers.Unclassified(contractMap, contractScan),
            Registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = [], ByAddress = new Dictionary<ulong, CodeEntry[]>(),
                Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<Cpp2CS.Model.MethodDef, int>() },
            MachineFactory = () => new PcodeMachine(contractImage, decoder) }, new());
        var calls = new FactsCallModel(facts, facts.CreateMachine().Convention);
        Check(calls.Signature(basis + 0x1080) is { Source: "Win64-export-derived-native-inputs", Reads: [var input] }
            && input == Storage.Gpr(1) && calls.Clobbers(new(0x1000, CallKind.Direct, Expr.C(basis + 0x1080, 64))).Contains(Storage.Gpr(8)),
            "输入证明仍保留未知返回寄存器与 volatile clobber");
        var shape = new Cpp2CS.Recovery.Calls.CallShapes(facts, facts.CreateAbi(), (_, _) => false).Of(new(0x1000, CallKind.Direct, Expr.C(basis + 0x1080, 64)));
        Check(shape.Candidates.Count == 0 && shape.Signature is null && shape.NativeSummary is null,
            "输入契约不能制造托管方法、返回关系或纯内存摘要");
        foreach (var offset in new[] { 0x247, 0x24a, 0x257, 0x260, 0x299, 0x2b3 })
        {
            var changed = bytes.ToArray(); changed[offset] ^= 1;
            Check(X64NativeContracts.Identify(CodeMap.BuildPe(ImageDocument.Parse(changed), [])).Count == 0,
                "输入、转发目标、大小访问器和初始化位不一致时拒绝原生契约");
        }
        Check(Identify(bytes, true).All(h => h.Kind != HelperKind.InitializedTypeInfo), "不把托管入口归为布局初始化");
        foreach (var offset in new[] { 0x20a, 0x216, 0x21a, 0x224, 0x229, 0x233, 0x24a, 0x257, 0x299, 0x2b3, 0x2d7, 0x2e1 })
        {
            var changed = bytes.ToArray(); changed[offset] ^= 1;
            Check(Identify(changed).All(h => h.Kind != HelperKind.InitializedTypeInfo), "调用身份、分支、返回、异常字段、布局标志和不返回证据变化时拒绝");
        }
        var shifted = bytes.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(shifted.AsSpan(0xb0), basis + 0x10000000);
        // 普查入口随映像平移，调用目标不得使用固定基址。
        var movedImage = ImageDocument.Parse(shifted);
        var movedMap = CodeMap.BuildPe(movedImage, []);
        var movedScan = CodeScan.FromReferences(movedMap, new Dictionary<ulong, CodeRef[]> {
            [basis + 0x10001000] = [new(basis + 0x10001000, basis + 0x10001000, RefKind.Call, 0)] });
        Check(X64RuntimeHelpers.Identify(movedMap, movedScan, new PcodeMachine(movedImage, decoder))
            .Any(h => h.Kind == HelperKind.InitializedTypeInfo), "布局包装识别不依赖映像基址");
    }

    private static void Check(bool value, string reason)
    {
        if (!value) throw new InvalidOperationException(reason);
    }
}
