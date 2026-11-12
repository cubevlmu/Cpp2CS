using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Model;
using Cpp2CS.Recovery.Calls;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class SkippedBaseThunkTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        foreach (var invalid in new[] { "", "callee-write", "witness-write", "witness-read", "cycle", "missing", "ambiguous", "receiver", "exception", "static" })
        {
            var bytes = original.ToArray();
            System.Convert.FromHexString("E87B000000C3").CopyTo(bytes, 0x200);
            System.Convert.FromHexString(invalid == "callee-write" ? "C60101C3" : "C20000").CopyTo(bytes, 0x280);
            var witness = System.Convert.FromHexString(invalid switch {
                "witness-write" => "C60101C3",
                "witness-read" => "8B01C3",
                "cycle" => "33D2E9F9FFFFFF",
                _ => "33D2E9B9FFFFFF",
            });
            witness.CopyTo(bytes, 0x2c0); bytes[0x2d0] = 0xc3;
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 36); U32(0x700, 0x1000); U32(0x704, 0x1006); U32(0x708, 0x3140);
            U32(0x70c, 0x1080); U32(0x710, 0x1084); U32(0x714, 0x3140);
            U32(0x718, 0x10c0); U32(0x71c, (uint)(0x10c0 + witness.Length)); U32(0x720, 0x3160);
            bytes[0x740] = 1; bytes[0x760] = (byte)(invalid == "exception" ? 9 : 1); U32(0x764, 0x10f0);
            TypeDef Type(int index, string name) => new() { Index = index, Assembly = "Fixture.dll", Namespace = "", Name = name,
                Token = (uint)(0x02000001 + index), Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
            var parent = Type(0, "Parent"); var child = Type(1, "Child"); child.BaseType = new DefinitionRef(parent, []);
            MethodRef Method(int index, TypeDef owner, string name, ulong entry, bool isStatic, int arguments = 0) => MethodRef.Open(new MethodDef {
                Index = index, Owner = owner, Name = name, Address = entry, Token = (uint)(0x06000001 + index), Slot = -1, ImplAttributes = 0,
                Attributes = MethodAttributes.Public | (isStatic ? MethodAttributes.Static : 0),
                Parameters = Enumerable.Range(0, arguments).Select(i => new ParameterDef("p" + i, new PointerRef(new PrimitiveRef("void")), 0, null, false)).ToArray(),
            });
            var constructor = Method(0, parent, ".ctor", invalid == "missing" ? 0 : basis + 0x10c0, invalid == "static");
            var caller = Method(1, child, ".ctor", basis + 0x1000, false);
            var unrelated = new[] { Method(2, child, "Empty", basis + 0x1080, true), Method(3, child, "OtherEmpty", basis + 0x1080, true, 1) };
            parent.Methods = invalid == "ambiguous" ? [constructor.Method, Method(4, parent, ".ctor", basis + 0x10d0, false).Method] : [constructor.Method];
            var image = ImageDocument.Parse(bytes); var code = CodeMap.BuildPe(image, [basis + 0x1000, basis + 0x1080, basis + 0x10c0, basis + 0x10d0]);
            var entries = unrelated.Select(m => new CodeEntry(m.Method.Address, EntryKind.Method, m, 0, null)).ToArray();
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = new Dictionary<ulong, CodeEntry[]> { [basis + 0x1080] = entries }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [parent, child], Methods = [.. parent.Methods, caller.Method, .. unrelated.Select(m => m.Method)],
                Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = CodeScan.Unscanned(code), Registrations = registrations,
                Layouts = new FieldLayouts(model), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var call = new Call(basis + 0x1000, CallKind.Direct, Expr.C(basis + 0x1080, 64)) { Sources = [Storage.Gpr(1), Storage.Gpr(2)],
                Arguments = [invalid == "receiver" ? Expr.C(0, 64) : new Use(new Variable(Storage.Gpr(1), 0), 64), Expr.C(0, 64)] };
            var shape = new CallShapes(facts, facts.CreateAbi(), (_, _) => false).Of(call, caller);
            Check(invalid == "" ? shape.Candidates is [var actual] && actual.Method == constructor.Method && shape.Signature is not null : shape.Signature is null,
                "跳过空构造跳板须有唯一直接基类见证，不能丢失读写或异常：" + invalid);
        }
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}
