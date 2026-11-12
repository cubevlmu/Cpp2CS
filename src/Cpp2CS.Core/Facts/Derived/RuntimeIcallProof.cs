using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using Cpp2CS.Ir;

namespace Cpp2CS.Facts.Derived;

/// <summary>受限 Win64 内部调用桩：核对缓存、解析导出、完整签名及只转发一个 32 位实参的尾调用。</summary>
internal static class RuntimeIcallProof
{
    internal static bool IgnoresMethodInfo(ProgramFacts facts, ulong entry, MethodRef[] candidates, MachineSignature signature)
    {
        if (facts.Model.Image.Architecture != Architecture.X64 || signature.This is not null
            || signature.Arguments is not [{ Transfer: Transfer.Value, Pieces: [{ Register: var input, Width: 32 }] }]
            || input != Storage.Gpr(1) || signature.MethodInfo?.Register != Storage.Gpr(2)
            || !facts.Model.Image.Exports.TryGetValue("il2cpp_resolve_icall", out var exported)
            || facts.Code.At(entry) is not { HasUnmodeledExceptions: false } range || range.Start != entry || range.Size < 49) return false;
        var image = facts.Model.Image;
        const string stub = "40 53 48 83 ec 20 48 8b 05 ?? ?? ?? ?? 8b d9 48 85 c0 75 13 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 8b cb 48 83 c4 20 5b 48 ff e0";
        if (!Matches(entry, stub) || Relative(entry + 9) != Relative(entry + 35)) return false;
        var cache = Relative(entry + 9);
        if (image.SectionAt(cache) is not { Flags: var flags } || (flags & 1) == 0
            || !(image.Resolve(cache).Kind == Cpp2CS.Image.AddressKind.ZeroFill
                || image.ReadUpTo(cache, 8) is [0, 0, 0, 0, 0, 0, 0, 0])) return false;
        var resolver = Relative(entry + 28);
        // 导出可能直接指向解析器；codegen 包装正常返回非空目标，失败路径不转发原始 RDX。
        if (!ExportedResolver(resolver))
        {
            const string wrapper = "40 53 48 83 ec 20 48 8b d9 e8 ?? ?? ?? ?? 48 85 c0 74 06 48 83 c4 20 5b c3 48 8b cb e8 ?? ?? ?? ?? 48 8b c8 33 d2 e8 ?? ?? ?? ?? cc";
            if (facts.Code.At(resolver) is not { HasUnmodeledExceptions: false } body || body.Start != resolver || body.Size < 44
                || !Matches(resolver, wrapper) || !ExportedResolver(Relative(resolver + 10))) return false;
        }
        var name = Relative(entry + 23);
        return candidates.Any(method => method.Method.Address == entry && method.Method.IsStatic
            && (method.Method.ImplAttributes & MethodImplAttributes.InternalCall) != 0
            && method.Method.Owner.DeclaringType is null && method.Method.Owner.GenericParameters.Count == 0
            && method.Method.GenericParameters.Count == 0 && method.Method.Parameters is [{ Type: DefinitionRef parameter }]
            && StringMatches(method.Method.Owner.FullName + "::" + method.Method.Name + "(" + parameter.Definition.FullName + ")"));

        bool StringMatches(string expected)
        {
            var bytes = Encoding.UTF8.GetBytes(expected + '\0');
            return image.ReadUpTo(name, bytes.Length).SequenceEqual(bytes);
        }
        bool ExportedResolver(ulong target)
        {
            var seen = new HashSet<ulong>();
            var current = exported;
            for (var depth = 0; depth < 8 && seen.Add(current); depth++)
            {
                if (current == target) return true;
                if (image.ReadUpTo(current, 5) is not [0xe9, ..]) return false;
                current = Relative(current + 1);
            }
            return false;
        }
        bool Matches(ulong at, string pattern)
        {
            var parts = pattern.Split(' ');
            var bytes = image.ReadUpTo(at, parts.Length);
            if (bytes.Length != parts.Length) return false;
            for (var i = 0; i < parts.Length; i++)
                if (parts[i] != "??" && bytes[i] != System.Convert.ToByte(parts[i], 16)) return false;
            return true;
        }
        ulong Relative(ulong at) => unchecked(at + 4 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(image.ReadUpTo(at, 4)));
    }
}
