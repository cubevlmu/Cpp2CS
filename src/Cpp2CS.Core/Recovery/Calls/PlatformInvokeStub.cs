using CallingConvention = System.Runtime.InteropServices.CallingConvention;
using CharSet = System.Runtime.InteropServices.CharSet;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Storage;

namespace Cpp2CS.Recovery.Calls;

/// <summary>
/// extern 方法的原生入口是 IL2CPP 生成的 P/Invoke 桩：第一次调用时用栈上的 PInvokeArguments 解析函数指针，缓存后转发。
/// 元数据不含 DllImport 的库名与入口，只能从描述符读取：
/// moduleName（指针、长度）、entryPoint（指针、长度）、callingConvention、charSet、parameterSize、isNoMangle。
/// 两个字符串的长度与内容一致才算认出描述符。
/// </summary>
internal static class PlatformInvokeStub
{
    private const int ModuleField = 0, ModuleLength = 8, EntryField = 16, EntryLength = 24, ConventionField = 32, CharacterField = 36, NoMangleField = 44;

    public static NativeImport? Read(MachineFunction function, ImageDocument image, IFrameCallEffects effects) => Read(function, image, effects, out _);

    public static NativeImport? Read(MachineFunction function, ImageDocument image, IFrameCallEffects effects, out string? failure)
    {
        var model = new FrameModel(function, effects);
        var imports = new List<NativeImport>();
        string? rejected = null;
        foreach (var block in function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
                if (block.Statements[i] is Call { Kind: CallKind.Direct, Arguments: [var first, ..] } resolver
                    && model.Slot(first) is { } descriptor)
                {
                    if (!ForwardsResult(function, resolver, model))
                    {
                        rejected ??= $"0x{resolver.Address:x} 解析结果未形成唯一转发，或桩含额外调用／外部写入";
                        continue;
                    }
                    var (import, reason) = Describe(model, block, i, descriptor, image);
                    if (import is not null) imports.Add(import);
                    else rejected ??= $"0x{resolver.Address:x} {reason}";
                }
        // 同一桩出现互相冲突的解析结果时不选先遍历到的描述符。
        var distinct = imports.Distinct().ToArray();
        failure = distinct.Length == 1 ? null : distinct.Length > 1 ? "不同解析路径的导入声明冲突"
            : rejected ?? "没有可证明的帧描述符及解析调用";
        return distinct is [var unique] ? unique : null;
    }

    /// <summary>描述符调用的返回指针必须流向实际间接转发；只出现相似栈布局不足以认定导入。</summary>
    private static bool ForwardsResult(MachineFunction function, Call resolver, FrameModel model)
    {
        var result = Array.FindIndex(resolver.Results, r => r.Bank == Bank.Gpr && r.Index == 0);
        if (result < 0 || result >= resolver.Defines.Length || resolver.Defines[result].Width != 64) return false;
        var returned = resolver.Defines[result];
        var statements = function.Blocks.SelectMany(b => b.Statements).ToArray();
        var definitions = statements.OfType<Define>().ToDictionary(d => d.Target, d => d.Value);
        var phis = statements.OfType<Phi>().ToDictionary(p => p.Target);
        var visiting = new HashSet<Variable>();
        bool Direct(Expr value, int depth = 0) => depth < 32 && value is Use use
            && (use.Variable == returned || definitions.TryGetValue(use.Variable, out var expression) && Direct(expression, depth + 1));
        // 缓存仅接受同一槽的所有本地写均来自该返回指针；任意别名写仍阻止此证明。
        var caches = statements.OfType<Store>().Where(s => s.Target is Const && Direct(s.Value))
            .Select(s => ((Const)s.Target).Value).ToHashSet();
        caches.RemoveWhere(slot => statements.OfType<Store>().Any(s => s.Target is not Const address
            ? model.Slot(s.Target) is null : address.Value == slot && !Direct(s.Value)));
        var observed = false;
        bool Origin(Expr expression, int depth)
        {
            if (depth >= 32 || expression.Width != 64) return false;
            if (expression is Load { Width: 64, Address: Const address }) return caches.Contains(address.Value);
            if (expression is not Use use) return false;
            if (use.Variable == returned) { observed = true; return true; }
            if (!visiting.Add(use.Variable)) return false;
            var valid = definitions.TryGetValue(use.Variable, out var value) ? Origin(value, depth + 1)
                : phis.TryGetValue(use.Variable, out var phi) && phi.Sources.Length > 0
                    && phi.Sources.All(v => v is not null && Origin(new Use(v, v.Width), depth + 1));
            visiting.Remove(use.Variable);
            return valid;
        }
        foreach (var call in statements.OfType<Call>().Where(c => c.Kind is CallKind.Indirect or CallKind.TailIndirect))
        {
            observed = false;
            if (Origin(call.Target, 0) && observed
                && statements.OfType<Call>().All(c => ReferenceEquals(c, resolver) || ReferenceEquals(c, call))
                && statements.OfType<Store>().All(s => model.Slot(s.Target) is not null
                    || s.Target is Const slot && caches.Contains(slot.Value) && Direct(s.Value))) return true;
        }
        return false;
    }

    private static (NativeImport? Import, string? Reason) Describe(FrameModel model, Block block, int index, long descriptor, ImageDocument image)
    {
        string? issue = null;
        string Name(int offset) => offset switch { ModuleField => "moduleName", ModuleLength => "moduleName.length", EntryField => "entryPoint",
            EntryLength => "entryPoint.length", ConventionField => "callingConvention", CharacterField => "charSet", NoMangleField => "isNoMangle", _ => $"offset{offset}" };
        ulong? Field(int offset, int width)
        {
            ulong result = 0;
            // 逐字节证明所有可达路径上的同一常量，允许相邻窄写或向量存储共同覆盖描述符字段。
            for (var part = 0; part < width / 8; part++)
            {
                var at = descriptor + offset + part;
                var reach = model.Reach(block, index, at, 1);
                if (!reach.Complete)
                {
                    issue ??= $"描述符 {Name(offset)} 字节 {part}：" + (reach.Exhausted ? "证明超过预算"
                        : reach.Clobber is { } clobber ? $"被 0x{clobber.Address:x} 的未知写入破坏" : "未在所有入边完整初始化");
                    return null;
                }
                var values = reach.Stores.Select(s => model.Slot(s.Target) is { } start
                    ? Fold.Extract(s.Value, checked((int)(at - start) * 8), 8) as Const : null).Distinct().ToArray();
                if (values is not [{ } value])
                {
                    issue ??= $"描述符 {Name(offset)} 字节 {part}：来源不是同一常量";
                    return null;
                }
                result |= value.Value << (part * 8);
            }
            return result;
        }
        string? Text(int pointer, int length)
        {
            if (Field(pointer, 64) is not { } address || Field(length, 64) is not { } size) return null;
            if (RuntimeHelpers.CString(image, address) is { } text && (ulong)text.Length == size) return text;
            issue ??= $"描述符 {Name(pointer)}：只读映射、编码、终止符或长度不匹配";
            return null;
        }
        if (Text(ModuleField, ModuleLength) is not { } library || Text(EntryField, EntryLength) is not { } entry) return (null, issue);
        if (Convention(Field(ConventionField, 32)) is not { } convention) return (null, issue ?? "描述符 callingConvention 编码不支持");
        if (Characters(Field(CharacterField, 32)) is not { } characters) return (null, issue ?? "描述符 charSet 编码不支持");
        var noMangle = Field(NoMangleField, 8);
        if (noMangle is not (0 or 1)) return (null, issue ?? "描述符 isNoMangle 不是布尔编码");
        return (new NativeImport(library, entry) { CallingConvention = convention, CharSet = characters, ExactSpelling = noMangle == 1 }, null);
    }

    /// <summary>Il2CppCallConvention。</summary>
    private static CallingConvention? Convention(ulong? value) => value switch
    {
        0 => CallingConvention.Winapi,
        1 => CallingConvention.Cdecl,
        2 => CallingConvention.StdCall,
        3 => CallingConvention.ThisCall,
        4 => CallingConvention.FastCall,
        _ => null,
    };

    /// <summary>Il2CppCharSet。</summary>
    private static CharSet? Characters(ulong? value) => value switch
    {
        0 => CharSet.Ansi,
        1 => CharSet.Unicode,
        2 => CharSet.None,
        _ => null,
    };
}
