using Cpp2CS.Facts;
using static Cpp2CS.Pipeline.RecoveryReport;

namespace Cpp2CS.Pipeline;

internal static class DecompileStage
{
    internal static int Write(RecoveryRequest request, ProgramFacts facts, string sourceAssemblies,
        IEnumerable<MethodRecoveryResult> emitted, IEnumerable<MethodRecoveryResult> partialEmitted,
        MethodRecoveryResult[] results, MethodDef[] methods, Action<string> Log)
    {
        var output = request.Output;
        var noSource = request.NoSource;
        var sourceLayout = request.SourceLayout;
        var list = request.Methods;
        var namespaces = request.Namespaces;
        var assembliesFilter = request.Assemblies;
        var excludeAssemblies = request.ExcludeAssemblies;
        var types = request.TypeNames();
        var all = request.All || assembliesFilter is not null;
        IDecompileTransformProvider? transforms = null;
        // 占位程序集只在有类型反编译失败时才写出。
        var stubDirectory = new Lazy<string>(() =>
        {
            var directory = Path.Combine(output, "assemblies-stubs");
            new Skeleton(facts.Model).Write(directory);
            return directory;
        });
        Func<string>? stubs = request.KeepGoing ? () => stubDirectory.Value : null;
        var sources = Path.Combine(output, "src");
        if (Directory.Exists(sources)) Directory.Delete(sources, true);
        Directory.CreateDirectory(sources);
        var invalid = Path.GetInvalidFileNameChars();
        var files = 0;
        var sourceTypes = sourceLayout == "project"
            ? facts.Model.Types.Where(t => t.DeclaringType is null && (list is not null ? methods.Any(m => Top(m.Owner) == t)
                : (all || (types is not null ? types.Contains(t.FullName) : InNamespaces(t, namespaces)))
                  && (assembliesFilter is null || assembliesFilter.Contains(t.Assembly, StringComparer.OrdinalIgnoreCase))
                  && (excludeAssemblies is null || !excludeAssemblies.Contains(t.Assembly, StringComparer.OrdinalIgnoreCase))))
            : emitted.Concat(partialEmitted).Concat(results.Where(r => r.Declaration is not null))
                .Select(r => Top(r.Method.Method.Owner))
                .Where(t => excludeAssemblies is null || !excludeAssemblies.Contains(t.Assembly, StringComparer.OrdinalIgnoreCase))
                .Distinct();
        var sourceGroups = sourceTypes.GroupBy(t => t.Assembly).ToDictionary(g => g.Key, g => g.Select(t => (t.Namespace, t.SimpleName)).ToHashSet());
        var sourceAssemblyNames = sourceLayout == "project" && all
            ? facts.Model.Assemblies.Select(a => a.Name)
                .Where(a => assembliesFilter is null || assembliesFilter.Contains(a, StringComparer.OrdinalIgnoreCase))
                .Where(a => excludeAssemblies is null || !excludeAssemblies.Contains(a, StringComparer.OrdinalIgnoreCase))
            : sourceGroups.Keys.AsEnumerable();
        foreach (var assemblyName in sourceAssemblyNames.Where(_ => !noSource))
        {
            var wanted = sourceGroups.GetValueOrDefault(assemblyName) ?? [];
            Log($"[阶段 6/6: Decompile] 开始反编译程序集: {assemblyName} (目标类型数: {wanted.Count})...");
            if (sourceLayout == "project")
            {
                var count = SourceProject.Write(Path.Combine(sourceAssemblies, Skeleton.ImageFileName(assemblyName)), sourceAssemblies, sources,
                    t => all || wanted.Contains((t.Namespace, t.Name)), transforms, stubs, Log);
                files += count;
                Log($"[阶段 6/6: Decompile] 程序集 {assemblyName} 项目已输出完成：生成 {count} 个类型文件，当前累计 {files}");
                continue;
            }
            var assemFiles = 0;
            foreach (var source in Decompilation.Decompile(Path.Combine(sourceAssemblies, Skeleton.ImageFileName(assemblyName)), sourceAssemblies,
                t => wanted.Contains((t.Namespace, t.Name)) || t.FullName == "Cpp2CS.NativeImports", false, recoveringBodies: true, transforms: transforms, stubs: stubs))
            {
                File.WriteAllText(Path.Combine(sources, new string((assemblyName + "_" + source.TypeName).Select(c => invalid.Contains(c) ? '_' : c).ToArray()) + ".cs"), source.Source);
                files++;
                assemFiles++;
                if (assemFiles % 20 == 0)
                {
                    Log($"[Decompile] {assemblyName}: 已写入 {assemFiles} 个 C# 文件 (最新: {source.TypeName})...");
                }
            }
            Log($"[Decompile] 程序集 {assemblyName} 输出完成：共 {assemFiles} 个 C# 文件");
        }
        if (stubDirectory.IsValueCreated)
        {
            // 反编译器可能还映射着这些文件；留下目录不影响工程，引用的是 assemblies。
            try { Directory.Delete(stubDirectory.Value, true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Log($"占位程序集目录留在 {stubDirectory.Value}：{e.Message}"); }
        }
        return files;
    }
}
