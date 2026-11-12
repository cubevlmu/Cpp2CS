using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Facts.Derived;

/// <summary>由解析导出、完整内部调用名称、零初始化缓存和 SSA 目标共同证明的原生内部调用输入。</summary>
internal sealed class NativeIcallBindings(ProgramFacts facts)
{
    private readonly Lazy<Dictionary<string, MethodRef[]>> names = new(() => facts.Model.Methods
        .Where(m => (m.ImplAttributes & MethodImplAttributes.InternalCall) != 0 && m.Owner.DeclaringType is null
            && m.Owner.GenericParameters.Count == 0 && m.GenericParameters.Count == 0)
        .Select(MethodRef.Open).Where(m => m.Method.Parameters.All(p => Name(p.Type) is not null))
        .GroupBy(m => m.Method.Owner.FullName + "::" + m.Method.Name + "(" + string.Join(",", m.Method.Parameters.Select(p => Name(p.Type))) + ")")
        .ToDictionary(g => g.Key, g => g.ToArray()));
    private readonly Storage stackPointer = facts.CreateMachine().Convention.StackPointer;

    private static string? Name(TypeRef type) => type switch
    {
        DefinitionRef { Arguments.Count: 0 } definition => definition.Definition.FullName,
        ByRefRef reference when Name(reference.Element) is { } element => element + "&",
        _ => null,
    };

    internal Dictionary<Call, IReadOnlyDictionary<Storage, int>> Inputs(MachineFunction function)
    {
        var result = new Dictionary<Call, IReadOnlyDictionary<Storage, int>>(ReferenceEqualityComparer.Instance);
        if (facts.Model.Image.Architecture != Architecture.X64 || !facts.Model.Image.Exports.TryGetValue("il2cpp_resolve_icall", out var exported)
            || facts.Code.At(function.Entry) is not { HasUnmodeledExceptions: false } range || range.Start != function.Entry) return result;
        var image = facts.Model.Image;
        var statements = function.Blocks.SelectMany(b => b.Statements).ToArray();
        var starts = statements.Select(s => s.Address).ToHashSet();
        var definitions = statements.OfType<Define>().ToDictionary(d => d.Target, d => d.Value);
        var definitionSites = statements.OfType<Define>().ToDictionary(d => d.Target, d => d.Address);
        var phis = statements.OfType<Phi>().ToDictionary(p => p.Target, p => p.Sources);
        var calls = statements.OfType<Call>().ToArray();
        var abi = facts.CreateAbi();
        void Trace(string message)
        {
            if (facts.Options.Diagnostics.Typing.Contains(function.Entry)) facts.Options.Diagnostics.Write("icall-inputs", function.Entry, message);
        }
        foreach (var start in starts)
        {
            // mov rax,[cache]; test rax,rax; jne join; lea rcx,name; call resolver; mov [cache],rax; join:
            if (start < range.Start || !Matches(start, "48 8b 05 ?? ?? ?? ??")) continue;
            var gap = Enumerable.Range(0, 17).FirstOrDefault(g => start + (ulong)(31 + g) <= range.End
                && starts.Contains(start + (ulong)(7 + g))
                && Matches(start + (ulong)(7 + g), "48 85 c0 75 13 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ??")
                && statements.Where(s => s.Address >= start + 7 && s.Address < start + (ulong)(7 + g))
                    .All(s => s is Define define && define.Target.Storage != Storage.Gpr(0)
                        && !ExprMap.Walk(define.Value).Any(e => e is Load or Intrinsic)), -1);
            if (gap < 0) continue;
            Trace($"缓存读取：0x{start:x}");
            var resolverSite = start + (ulong)(19 + gap);
            var storeSite = start + (ulong)(24 + gap);
            var cache = Relative(start + 3);
            if (cache > ulong.MaxValue - 8 || cache != Relative(storeSite + 3) || !ZeroCache(cache) || !Resolver(Relative(resolverSite + 1))) continue;
            var name = CString(Relative(start + (ulong)(15 + gap)));
            if (name is null || !names.Value.TryGetValue(name, out var methods)) { Trace($"名称无声明绑定：{name}"); continue; }
            Trace($"完整名称：{name}；声明数 {methods.Length}");
            var signatures = methods.Select(m => abi.Machine(m, out _)).ToArray();
            if (signatures.Length == 0 || signatures[0] is not { } signature || signatures.Any(s => s is null || !Cpp2CS.Recovery.Calls.CallShapes.SameShape(s, signature))
                || signature.Return is { Transfer: not Transfer.Value }
                || signature.Arguments.Any(a => a.Transfer is not (Transfer.Value or Transfer.Reference)
                    || a.Pieces is not [{ Register.Bank: Bank.Gpr or Bank.Vec }])) { Trace("签名未证明"); continue; }
            var resolver = calls.SingleOrDefault(c => c.Address == resolverSite && c.Kind == CallKind.Direct && c.Target is Const);
            if (resolver is null || Array.IndexOf(resolver.Results, Storage.Gpr(0)) is not (var returnIndex and >= 0)
                || returnIndex >= resolver.Defines.Length || resolver.Defines[returnIndex] is not { } returned) continue;
            // 目标的所有 SSA 来源都必须是这个缓存读取或这次解析结果，不能混入其他函数指针。
            var budget = 0;
            bool Origin(Expr expression, HashSet<Variable> seen, int depth, bool allowCache = true)
            {
                if (depth == 0 || ++budget > 4096) return false;
                if (expression is not Use use) return false;
                if (use.Variable == returned) return true;
                if (!seen.Add(use.Variable)) return false;
                if (definitions.TryGetValue(use.Variable, out var value))
                    return value is Load { Width: 64, Address: Const location } ? allowCache && location.Value == cache && definitionSites[use.Variable] == start
                        : Origin(value, seen, depth - 1, allowCache);
                return phis.TryGetValue(use.Variable, out var inputs) && inputs.Length > 0
                    && inputs.All(v => Origin(new Use(v, 64), new(seen), depth - 1, allowCache));
            }
            // 此缓存只允许已核实的解析结果写入；未知别名存储仍由输入分析保留，不据此消除内存效果。
            var stores = statements.OfType<Store>().Select(s => (Store: s, Address: Address(s.Target, [], 64))).ToArray();
            if (stores.Any(s => s.Address.Kind == 0 || s.Address.Kind == 1 && s.Address.Offset > ulong.MaxValue - (ulong)((s.Store.Value.Width + 7) / 8))) { Trace("存在未知写入地址"); continue; }
            var writes = stores.Where(s => s.Address.Kind == 1 && s.Address.Offset < cache + 8
                && s.Address.Offset + (ulong)((s.Store.Value.Width + 7) / 8) > cache).Select(s => s.Store).ToArray();
            if (writes is not [var write] || write.Address != storeSite || write.Value.Width != 64
                || !Origin(write.Value, [], 64, allowCache: false)) continue;
            var inputs = signature.Arguments.SelectMany(a => a.Pieces).ToDictionary(p => p.Register, p => p.Width);
            var bound = calls.Where(c => c.Kind is CallKind.Indirect or CallKind.TailIndirect && Origin(c.Target, [], 64)).ToArray();
            Trace($"缓存写入及来源已证明；间接调用数 {bound.Length}");
            if (bound.Length == 0) continue;
            foreach (var call in bound) result[call] = inputs;
            result[resolver] = new Dictionary<Storage, int> { [Storage.Gpr(1)] = 64 };
        }
        return result;

        (int Kind, ulong Offset) Address(Expr expression, HashSet<Variable> seen, int depth)
        {
            if (depth == 0) return default;
            return expression switch
            {
                Const constant => (1, constant.Value),
                FrameAddress frame => (2, unchecked((ulong)frame.Offset)),
                Use { Variable.Version: 0, Variable.Storage: var storage, Width: 64 }
                    when storage == stackPointer => (2, 0),
                Use use when seen.Add(use.Variable) && definitions.TryGetValue(use.Variable, out var value) => Address(value, seen, depth - 1),
                Binary { Op: BinOp.Add, Left: var left, Right: Const offset } => Add(Address(left, seen, depth - 1), offset.Value),
                _ => default,
            };
        }
        static (int Kind, ulong Offset) Add((int Kind, ulong Offset) basis, ulong offset) =>
            basis.Kind == 0 ? default : (basis.Kind, unchecked(basis.Offset + offset));

        bool ZeroCache(ulong cache) => image.SectionAt(cache) is { Flags: var flags, Executable: false } && (flags & 1) != 0
            && (image.Resolve(cache).Kind == AddressKind.ZeroFill || image.ReadUpTo(cache, 8) is [0, 0, 0, 0, 0, 0, 0, 0]);
        string? CString(ulong address)
        {
            if (image.SectionAt(address) is not { Executable: false, Flags: var flags } || (flags & 1) != 0) return null;
            var bytes = image.ReadUpTo(address, 1024);
            var length = bytes.IndexOf((byte)0);
            return length > 0 && bytes[..length].ToArray().All(b => b is >= 32 and <= 126) ? Encoding.ASCII.GetString(bytes[..length]) : null;
        }
        bool Resolver(ulong target)
        {
            if (Export(target)) return true;
            return facts.Code.At(target) is { HasUnmodeledExceptions: false } body && body.Start == target && body.Size >= 44
                && Matches(target, "40 53 48 83 ec 20 48 8b d9 e8 ?? ?? ?? ?? 48 85 c0 74 06 48 83 c4 20 5b c3 48 8b cb e8 ?? ?? ?? ?? 48 8b c8 33 d2 e8 ?? ?? ?? ?? cc")
                && Export(Relative(target + 10));
        }
        bool Export(ulong target)
        {
            var current = exported;
            var seen = new HashSet<ulong>();
            for (var depth = 0; depth < 8 && seen.Add(current); depth++)
            {
                if (current == target) return true;
                if (image.ReadUpTo(current, 5) is not [0xe9, ..]) return false;
                current = Relative(current + 1);
            }
            return false;
        }
        bool Matches(ulong address, string pattern)
        {
            var parts = pattern.Split(' ');
            var bytes = image.ReadUpTo(address, parts.Length);
            if (bytes.Length != parts.Length) return false;
            for (var i = 0; i < parts.Length; i++)
                if (parts[i] != "??" && bytes[i] != System.Convert.ToByte(parts[i], 16)) return false;
            return true;
        }
        ulong Relative(ulong address) => unchecked(address + 4 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(image.ReadUpTo(address, 4)));
    }
}
