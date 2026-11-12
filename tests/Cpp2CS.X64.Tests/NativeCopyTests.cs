using System.Buffers.Binary;
using Cpp2CS.Facts;
using Cpp2CS.Facts.Derived;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Model;
using Cpp2CS.Recovery.Calls;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class NativeCopyTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        var bytes = original.ToArray();
        const ulong basis = 0x180000000;
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        U32(0x124, 24); U32(0x704, 0x100b); U32(0x708, 0x3140);
        U32(0x70c, 0x1080); U32(0x710, 0x108b); U32(0x714, 0x3140); bytes[0x740] = 1;
        U32(0x744, 0x10f0);
        System.Convert.FromHexString("B807000000E8E6000000C3").CopyTo(bytes, 0x200);
        System.Convert.FromHexString("B807000000E866000000C3").CopyTo(bytes, 0x280);
        bytes[0x2f0] = 0xc3;
        var owner = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000001,
            Attributes = System.Reflection.TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        var method = new MethodRef(new MethodDef { Index = 0, Owner = owner, Name = "Read", Token = 0x06000001,
            Attributes = System.Reflection.MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = new DefinitionRef(owner, []), Parameters = [] }, [], []);
        ProgramFacts Facts(byte[] data, ulong imageBase = basis)
        {
            var image = ImageDocument.Parse(data);
            var code = CodeMap.BuildPe(image, [imageBase + 0x1080]);
            CodeEntry[] entries = [new(imageBase + 0x1080, EntryKind.Method, method, 0, null)];
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = new Dictionary<ulong, CodeEntry[]> { [imageBase + 0x1080] = entries }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [owner], Methods = [method.Method], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            return new(new BaseFacts { Model = model, Code = code, Scan = CodeScan.Unscanned(code), Registrations = registrations,
                Layouts = new FieldLayouts(model), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
        }
        Check(new NativeCopyProof(Facts(bytes)).Matches(basis + 0x1000, method), "不同 CALL 位移须解析到同一外部目标");
        Check(new NativeCopyProof(Facts(bytes)).At(basis + 0x1000) is [{ Method: var indexed }] && indexed == method,
            "按全体注册见证发现副本，不依赖调用者残留的 MethodInfo");
        var facts = Facts(bytes);
        var concurrent = Facts(bytes);
        var proofs = Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => (
            Match: concurrent.NativeCopies.Matches(basis + 0x1000, method), Copies: concurrent.NativeCopies.At(basis + 0x1000))))).GetAwaiter().GetResult();
        Check(proofs.All(p => p.Match && p.Copies is [{ Method: var candidate }] && candidate == method),
            "并行恢复共享同一映像事实时，副本证明不能暴露未完成缓存或并发改写字典");
        var shapes = new CallShapes(facts, new ManagedAbi(facts.Layouts, Architecture.X64), (_, _) => false);
        var call = new Call(basis + 0x1100, CallKind.Direct, Expr.C(basis + 0x1000, 64)) { Sources = [Storage.Gpr(1)], Arguments = [new Symbol(SymbolKind.Method, method)] };
        Check(shapes.Of(call) is { Signature: not null, LocalCopy: true, Candidates: [var proven] } && proven == method,
            "未登记调用取得已登记见证的签名并标记副本");
        Check(shapes.Of(call with { Arguments = [Expr.C(0, 64)] }) is { Signature: not null, LocalCopy: true },
            "完整机器码见证可独立提供 ABI，空 MethodInfo 不妨碍证明副本");
        foreach (var offset in new[] { 0x201, 0x206, 0x20a, 0x704, 0x740 })
        {
            var changed = bytes.ToArray(); changed[offset] ^= (byte)(offset == 0x740 ? 8 : 1);
            Check(!new NativeCopyProof(Facts(changed)).Matches(basis + 0x1000, method), "常量、外部目标、返回、边界或异常展开信息不同不得接受");
            Check(new NativeCopyProof(Facts(changed)).At(basis + 0x1000).Length == 0, "副本索引沿用完整反例拒绝");
        }
        var rip = bytes.ToArray();
        System.Convert.FromHexString("488B05F90F0000C3909090").CopyTo(rip, 0x200);
        System.Convert.FromHexString("488B05F90F0000C3909090").CopyTo(rip, 0x280);
        Check(!new NativeCopyProof(Facts(rip)).Matches(basis + 0x1000, method), "相同 RIP 位移在不同位置指向不同全局，不能按相同字节接受");
        var moved = bytes.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(moved.AsSpan(0xb0), basis + 0x10000000);
        Check(new NativeCopyProof(Facts(moved, basis + 0x10000000)).Matches(basis + 0x10001000, method), "副本证明不依赖固定映像基址");
    }

    private static void Check(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }
}
