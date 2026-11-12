using Cpp2CS.Facts;
using Cpp2CS.Input;
using static Cpp2CS.Pipeline.RecoveryReport;

namespace Cpp2CS.Pipeline;

internal static class CoreProfile
{
    /// <summary>跳过恢复，骨架的占位体原样写出。没有方法体可以挑选，所以源码总按工程布局导出整个范围。</summary>
    private static RecoveryRunResult Stubs(RecoveryRequest request, RunManifest manifest, ProgramFacts facts, SelectionStage.Selection selection, Action<string> Log)
    {
        var skeleton = new Skeleton(facts.Model);
        Directory.CreateDirectory(request.Output);
        var assemblies = Path.Combine(request.Output, "assemblies");
        manifest.Step("publication", () => { skeleton.Write(assemblies); return 0; });
        ReportStage.WriteUnselected(request.Output, selection);
        var files = manifest.Step("decompile", () => DecompileStage.Write(request with { SourceLayout = "project" }, facts, assemblies, [], [], [], selection.Methods, Log));
        var report = $"只导出桩：范围内方法 {selection.Targets.Length}，全部是占位体，没有恢复方法体；C# {files} 个类型文件\n";
        File.WriteAllText(Path.Combine(request.Output, "holes.txt"), report);
        var outcome = new RecoveryRunResult(request.Output, report, selection.Targets.Length, 0, 0, 0);
        manifest.Complete(outcome);
        return outcome;
    }

    internal static RecoveryRunResult Run(RecoveryRequest request, Action<string>? progress,
        Func<Action<string>, ProgramFacts>? buildFacts = null)
    {
        void Log(string message) => progress?.Invoke(message);
        Log($"=== Cpp2CS 启动恢复流程 ===");
        Log($"[配置] 二进制: {request.Binary}");
        Log($"[配置] 元数据: {request.Metadata}");
        Log($"[配置] 输出路径: {request.Output}");
        Log($"[配置] 并行工作线程: {request.Jobs}");
        Log($"[配置] 单方法时限: {request.MethodTimeoutSeconds} 秒");
        Log($"[配置] 内存上限: {(request.MaxMemoryMB > 0 ? $"{request.MaxMemoryMB} MB" : "未限制")}");
        if (request.Assemblies is not null)
            Log($"[配置] 筛选程序集: {string.Join(", ", request.Assemblies)}");

        var manifest = new RunManifest(request);
        Log($"[阶段 1/6: Facts] 开始建立基础事实与代码映射...");
        var facts = manifest.Step("facts", () => buildFacts is null
            ? FactsBuilder.Build(request.Binary, request.Metadata, Log, options: request.Options) : buildFacts(Log));
        Log($"[阶段 1/6: Facts] 基础事实构建完成");

        var types = new ManagedTypes(facts.Model, facts.Layouts);
        Log($"[阶段 2/6: Selection] 正在筛选恢复目标方法...");
        var selection = manifest.Step("selection", () => SelectionStage.Select(request, facts, Log));
        if (request.StubsOnly) return Stubs(request, manifest, facts, selection, Log);

        var guard = (request.KeepGoing || request.MethodTimeoutSeconds > 0 || request.MaxMemoryMB > 0)
            ? new MethodGuard(() => new(facts, types), TimeSpan.FromSeconds(request.MethodTimeoutSeconds), Log, request.MaxMemoryMB)
            : null;

        Log($"[阶段 3/6: Recovery] 开始恢复方法体 (目标方法: {selection.Targets.Length} 个)...");
        var batch = manifest.Step("recovery", () => RecoveryStage.RecoverMethods(selection.Targets, facts, types, request.Jobs, Log, guard, request.MaxMemoryMB));
        var targets = batch.Targets;
        Log($"[阶段 3/6: Recovery] 方法体恢复阶段完成");

        Log($"[阶段 4/6: Dependencies] 开始解析依赖闭包...");
        var summaries = guard is null ? new MethodSummaryService(batch.Recovery) : new MethodSummaryService(batch.Recovery, guard);
        for (var i = 0; i < targets.Length; i++) summaries.Seed(selection.Targets[i], targets[i]);
        var dependencies = new List<MethodRecoveryResult>();
        manifest.Step("dependencies", () =>
        {
            if (request.RecoverDependencies)
                DependencyClosure.Complete(targets, dependencies, targets.ToDictionary(r => r.Method.Method), summaries, Log);
            return dependencies.Count;
        });
        Log($"[阶段 4/6: Dependencies] 依赖解析完成，补充 {dependencies.Count} 个依赖方法");

        var results = targets.Concat(dependencies).ToArray();
        var dependencyMethods = dependencies.Select(r => r.Method.Method).ToHashSet();
        var skeleton = new Skeleton(facts.Model);
        skeleton.ApplyDeclarations(results);

        Log($"[阶段 5/6: Publication] 开始写出 CIL 程序集...");
        var emitter = new BodyEmitter(skeleton, types, diagnostics: request.Options.Diagnostics);
        var bodies = results.Where(r => r.Body is not null).Select(r => r.Body!);
        var effectiveKeepGoing = request.KeepGoing || guard is not null;
        var problems = effectiveKeepGoing ? emitter.CheckEach(bodies, EmissionPolicy.Recovered) : emitter.Check(bodies, EmissionPolicy.Recovered);
        var checkedProblems = emitter.Check(bodies, EmissionPolicy.Checked);
        DependencyClosure.Validate(results, problems);
        var published = PublishStage.Run(results, dependencyMethods, emitter, problems, effectiveKeepGoing);
        var marked = PublishStage.MarkUnrecovered(results, published, emitter);
        var emitted = published.Emitted;
        var partialEmitted = published.PartialEmitted;
        var emitProblems = published.Problems;
        var output = request.Output;
        Directory.CreateDirectory(output);
        var assemblies = Path.Combine(output, "assemblies");
        manifest.Step("publication", () => { skeleton.Write(assemblies); return emitted.Count; });
        Log($"[阶段 5/6: Publication] CIL 程序集写出完成 (成功: {emitted.Count}，部分: {partialEmitted.Count}，未恢复桩: {marked})");

        ReportStage.WritePublications(output, results, skeleton);
        var bytes = results.Select(r => r.Entry).Distinct().ToDictionary(e => e, e => e == 0 ? 0 : checked((long)facts.Code.At(e)!.Size));
        ReportStage.WriteRecovery(output, results, bytes, dependencyMethods, emitProblems, partialEmitted,
            _ => "native-recovery", _ => null);
        ReportStage.WriteTraces(output, targets);
        ReportStage.WriteManagedChecks(output, facts, results, emitted, dependencyMethods, skeleton, checkedProblems);
        ReportStage.WriteWindowsExceptions(output, facts, results);
        ReportStage.WriteNativeContracts(output, facts);
        ReportStage.WriteEmitted(output, emitted, skeleton, dependencyMethods);
        var sourceProblems = SourceSuitability.Check(emitted.Select(r => r.Body!).Concat(partialEmitted.Select(r => r.Partial!)));
        ReportStage.WriteSourceProblems(output, sourceProblems);
        ReportStage.WriteCoverage(output, facts, targets, emitted, checkedProblems, sourceProblems);
        ReportStage.WriteUnselected(output, selection);
        var selectedSet = targets.ToHashSet();
        var report = Report(targets, emitted.Where(selectedSet.Contains).ToList(), emitProblems.Where(p => selectedSet.Contains(p.Key)).ToDictionary(),
            targets.Select(r => r.Entry).Distinct().ToDictionary(e => e, e => bytes[e]));

        Log($"[阶段 6/6: Decompile] 开始反编译生成 C# 源码...");
        var files = manifest.Step("decompile", () => DecompileStage.Write(request with { KeepGoing = effectiveKeepGoing }, facts, assemblies, emitted, partialEmitted, results, selection.Methods, Log));
        Log($"[阶段 6/6: Decompile] C# 源码生成完成，共生成 {files} 个文件");

        report.AppendLine($"core：依赖 {dependencies.Count}，部分体 {partialEmitted.Count}，C# {files} 个类型文件");
        report.AppendLine($"源码形式限制 {sourceProblems.Count}（独立于 CIL 写出，不代表源码编译结果）");
        if (guard is not null) report.AppendLine($"防护机制：标记 Unrecovered 的方法 {marked}，恢复崩溃 {guard.Crashes}，超时 {guard.Timeouts}，内存超限跳过 {guard.MemSkips}");
        File.WriteAllText(Path.Combine(output, "holes.txt"), report.ToString());
        var outcome = new RecoveryRunResult(output, report.ToString(), targets.Length, emitted.Count(selectedSet.Contains),
            emitProblems.Count(p => selectedSet.Contains(p.Key)), partialEmitted.Count);
        manifest.Complete(outcome);
        Log($"=== 恢复全流程结束！产物位于: {output} ===");
        return outcome;
    }
}
