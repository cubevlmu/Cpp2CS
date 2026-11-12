using System.Buffers.Binary;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Facts.Derived;

/// <summary>未登记副本须与该方法的已登记实现逐指令一致；仅重定位相对调用与跳转。</summary>
internal sealed class NativeCopyProof(ProgramFacts facts)
{
    private readonly object gate = new();
    private readonly IMachine machine = facts.CreateMachine();
    private readonly Dictionary<(ulong, MethodDef), bool> cache = new();
    private Dictionary<MethodDef, ulong[]>? registered;
    private Dictionary<ulong, CodeEntry[]>? sizes;
    private readonly Dictionary<ulong, CodeEntry[]> copies = new();
    private GuardedNativeCopyProof? guarded;

    internal CodeEntry[] At(ulong address)
    {
        lock (gate) return AtCore(address);
    }

    private CodeEntry[] AtCore(ulong address)
    {
        if (facts.Model.Image.Architecture != Architecture.X64 || facts.Registrations.At(address).Length != 0) return [];
        if (copies.TryGetValue(address, out var known)) return known;
        if (facts.Code.At(address) is not { Start: var start, Size: > 5 and <= 1024, HasUnmodeledExceptions: false } range || start != address)
            return copies[address] = [];
        sizes ??= facts.Registrations.Entries.Where(e => e.Method is not null && e.Kind is EntryKind.Method or EntryKind.GenericMethod)
            .Where(e => facts.Code.At(e.Address) is { HasUnmodeledExceptions: false } f && f.Start == e.Address && f.Size <= 1024)
            .GroupBy(e => facts.Code.At(e.Address)!.Size).ToDictionary(g => g.Key, g => g.ToArray());
        if (!sizes.TryGetValue(range.Size, out var candidates)) return copies[address] = [];
        // 大小与首字节仅用于筛选；接受仍须逐条指令和实际访存/调用地址相同。
        var header = machine.Image.ReadUpTo(address, 1);
        if (header.IsEmpty) return copies[address] = [];
        var first = header[0];
        return copies[address] = candidates.GroupBy(e => e.Address)
            .Where(g => machine.Image.ReadUpTo(g.Key, 1) is [var opcode] && opcode == first
                && (EqualBodies(address, g.Key) || (guarded ??= new(facts)).Matches(address, g.Key, g.Select(e => e.Method!))))
            .SelectMany(g => g).ToArray();
    }

    internal bool Matches(ulong address, MethodRef method)
    {
        lock (gate) return MatchesCore(address, method);
    }

    private bool MatchesCore(ulong address, MethodRef method)
    {
        if (facts.Model.Image.Architecture != Architecture.X64) return false;
        if (cache.TryGetValue((address, method.Method), out var known)) return known;
        registered ??= facts.Registrations.Entries.Where(e => e.Method is not null && e.Kind is EntryKind.Method or EntryKind.GenericMethod)
            .GroupBy(e => e.Method!.Method).ToDictionary(g => g.Key, g => g.Select(e => e.Address).Distinct().ToArray());
        var match = registered.TryGetValue(method.Method, out var entries)
            && entries.Any(entry => entry != address && (EqualBodies(address, entry)
                || (guarded ??= new(facts)).Matches(address, entry, [method])));
        return cache[(address, method.Method)] = match;
    }

    private bool EqualBodies(ulong candidate, ulong witness)
    {
        var left = facts.Code.At(candidate);
        var right = facts.Code.At(witness);
        if (left is not { HasUnmodeledExceptions: false, Size: > 0 and <= 1024 }
            || right is not { HasUnmodeledExceptions: false } || left.Start != candidate || right.Start != witness || left.Size != right.Size)
            return false;
        for (ulong offset = 0; offset < left.Size;)
        {
            var a = new List<Stmt>(); var b = new List<Stmt>();
            var size = machine.Lift(candidate + offset, a);
            if (size <= 0 || machine.Lift(witness + offset, b) != size || offset + (ulong)size > left.Size
                || a.Count != b.Count || a.Concat(b).Any(s => s is Opaque)) return false;
            var first = machine.Image.ReadUpTo(candidate + offset, size);
            var second = machine.Image.ReadUpTo(witness + offset, size);
            if (first.Length != size || second.Length != size) return false;
            if (size == 5 && first[0] is 0xe8 or 0xe9 && first[0] == second[0])
            {
                var targetA = unchecked(candidate + offset + 5 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(first[1..]));
                var targetB = unchecked(witness + offset + 5 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(second[1..]));
                if (Target(targetA, left) != Target(targetB, right)) return false;
            }
            else if (!first.SequenceEqual(second)) return false;
            // 绝对数据地址和间接目标必须保持一致；不能把相同 RIP 位移误当成相同内存位置。
            if (!a.Select(s => Describe(s, left)).SequenceEqual(b.Select(s => Describe(s, right)))) return false;
            offset += (ulong)size;
        }
        return true;
    }

    private static string Target(ulong target, CodeFunction function) => function.Contains(target)
        ? $"local:{target - function.Start:x}" : $"absolute:{target:x}";

    private static string Describe(Stmt statement, CodeFunction function) => statement switch
    {
        Branch branch => $"branch:{branch.Condition}:{Target(branch.Target, function)}:{Target(branch.Fallthrough, function)}",
        Jump jump => $"jump:{Target(jump.Target, function)}",
        // CALL 即使落在本函数内部也保留绝对身份，不能由递归同形推断副本身份。
        _ => statement.ToString() ?? "",
    };
}
