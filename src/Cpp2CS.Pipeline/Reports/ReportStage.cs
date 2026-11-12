using System.Text.Json;
using System.Security.Cryptography;
using static Cpp2CS.Pipeline.RecoveryReport;

namespace Cpp2CS.Pipeline;

internal static class ReportStage
{
    public static void WriteNativeContracts(string output, Cpp2CS.Facts.ProgramFacts facts) =>
        File.WriteAllLines(Path.Combine(output, "native-input-contracts.jsonl"), facts.NativeInputs.OrderBy(p => p.Key).Select(p =>
            JsonSerializer.Serialize(new { nativeEntry = $"0x{p.Key:x}", imageSha256 = facts.Model.Image.Sha256,
                reads = p.Value.Reads.Select(r => r.ToString()).ToArray(), p.Value.Evidence,
                managedIdentity = "not-proven", returnRelation = "unknown", memoryEffects = "unknown" }, Json)));

    public static void WriteWindowsExceptions(string output, Cpp2CS.Facts.ProgramFacts facts, IReadOnlyList<MethodRecoveryResult> results)
    {
        File.WriteAllLines(Path.Combine(output, "windows-eh.jsonl"), results
            .Where(r => facts.Code.At(r.Entry)?.WindowsRange is { } range && (range.Handler is not null || range.Fragments.Length > 0))
            .Select(result =>
            {
                var range = facts.Code.At(result.Entry)!.WindowsRange!;
                var analysis = Cpp2CS.Image.WindowsEhReader.Read(facts.Model.Image, range);
                if (result.NativeExpansions.Any(e => e.Mode == "win64-fh4-state"))
                    analysis = analysis with { ManagedProjection = "native-cfg-projected",
                        BlockingProof = result.Holes.Count == 0 ? "" : "see-method-recovery-diagnostics" };
                return JsonSerializer.Serialize(new
                {
                    methodIndex = result.Method.Method.Index, assembly = result.Method.Method.Owner.Assembly, method = result.Method.ToString(),
                    nativeEntry = $"0x{result.Entry:x}", imageSha256 = facts.Model.Image.Sha256,
                    range.WindowsUnwind, range.Handler, range.HandlerData, range.HasSeparatedFragments,
                    fragments = range.Fragments.Select(f => new { f.Start, f.End, f.WindowsUnwind }),
                    analysis,
                }, Json);
            }));
    }

    /// <summary>逐方法保存托管静态检查；发布成功、依赖身份与检查通过分别记录。</summary>
    public static void WriteManagedChecks(string output, Cpp2CS.Facts.ProgramFacts facts,
        IReadOnlyList<MethodRecoveryResult> results, IReadOnlyList<MethodRecoveryResult> published,
        IReadOnlySet<MethodDef> dependencies, Skeleton skeleton,
        IReadOnlyDictionary<ManagedBody, EmissionProblem> problems)
    {
        var emitted = published.ToHashSet();
        using var all = new StreamWriter(Path.Combine(output, "managed-checks.jsonl"));
        using var failed = new StreamWriter(Path.Combine(output, "managed-check-diagnostics.jsonl"));
        foreach (var result in results.Where(r => r.Body is not null))
        {
            var problem = problems.GetValueOrDefault(result.Body!);
            var message = problem?.Message;
            var il = message is null ? null : System.Text.RegularExpressions.Regex.Match(message, @"\b(IL_[0-9a-fA-F]+)\s+([^：:\s]+)");
            var row = JsonSerializer.Serialize(new
            {
                assembly = result.Method.Method.Owner.Assembly,
                methodIndex = result.Method.Method.Index,
                metadataToken = $"0x{skeleton.Method(result.Method.Method).MetadataToken.ToUInt32():x8}",
                method = result.Method.ToString(),
                nativeEntry = $"0x{result.Entry:x}",
                nativeEntryRva = result.Entry >= facts.Model.Image.PreferredBase ? $"0x{result.Entry - facts.Model.Image.PreferredBase:x}" : null,
                imageSha256 = facts.Model.Image.Sha256,
                dependency = dependencies.Contains(result.Method.Method),
                published = emitted.Contains(result),
                stage = "managed-static-check",
                policy = EmissionPolicy.Checked.ToString(),
                status = problem is null ? "passed" : "failed",
                kind = problem?.Kind.ToString(),
                reason = message,
                ilOffset = il is { Success: true } ? il.Groups[1].Value : null,
                opcode = il is { Success: true } ? il.Groups[2].Value : null,
            }, Json);
            all.WriteLine(row);
            if (problem is not null) failed.WriteLine(row);
        }
    }

    public static void WriteSourceProblems(string output, IReadOnlyDictionary<ManagedBody, EmissionProblem> problems)
    {
        File.WriteAllLines(Path.Combine(output, "source-diagnostics.jsonl"), problems.Select(p => JsonSerializer.Serialize(new
        {
            method = p.Key.Method.ToString(),
            kind = p.Value.Kind.ToString(),
            reason = p.Value.Message,
        }, Json)));
    }

    public static void WritePublications(string output, MethodRecoveryResult[] results, Skeleton skeleton)
    {
        File.WriteAllLines(Path.Combine(output, "publication.jsonl"), results.Select(result =>
        {
            var method = skeleton.Method(result.Method.Method);
            return JsonSerializer.Serialize(new
            {
                address = $"0x{result.Entry:x}",
                method = result.Method.ToString(),
                assembly = method.Module.Name,
                token = method.MetadataToken.ToUInt32(),
                cil = method.HasBody ? Convert.ToHexString(SHA256.HashData(CilBodyFingerprint.Describe(method))) : null,
            }, Json);
        }));
    }

    public static void WriteTraces(string output, MethodRecoveryResult[] targets)
    {
        File.WriteAllLines(Path.Combine(output, "native-expansions.jsonl"), targets.SelectMany(r => r.NativeExpansions.Select(expansion => JsonSerializer.Serialize(new
        {
            methodIndex = r.Method.Method.Index, assembly = r.Method.Method.Owner.Assembly, method = r.Method.ToString(),
            entry = $"0x{r.Entry:x}", caller = $"0x{expansion.Caller:x}", site = $"0x{expansion.CallSite:x}",
            inlinee = $"0x{expansion.Inlinee:x}", expansion.Mode,
        }, Json))));
        File.WriteAllLines(Path.Combine(output, "analysis.jsonl"), targets.Select(r => JsonSerializer.Serialize(new
        {
            entry = $"0x{r.Entry:x}",
            method = r.Method.ToString(),
            steps = r.Analyses,
            passes = r.Passes,
        }, Json)));
        File.WriteAllLines(Path.Combine(output, "rules.jsonl"), targets.SelectMany(r => r.Rules.Select(rule => JsonSerializer.Serialize(new
        {
            entry = $"0x{r.Entry:x}",
            method = r.Method.ToString(),
            rule.Rule,
            rule.Site,
            status = rule.Status.ToString(),
            rule.Code,
            rule.Detail,
            rule.Evidence,
        }, Json))));
        File.WriteAllLines(Path.Combine(output, "call-resolution.jsonl"), targets.SelectMany(r => r.Calls.Select(c => JsonSerializer.Serialize(new
        {
            entry = $"0x{r.Entry:x}",
            method = r.Method.ToString(),
            site = $"0x{c.Site:x}",
            c.NativeEntry,
            c.TypeVersion,
            c.Status,
            selected = c.Selected?.ToString(),
            candidates = c.Candidates.Select(p => new { method = p.Method.ToString(), p.Evidence, p.Rejection }),
        }, Json))));
    }

    public static void WriteRecovery(string output, MethodRecoveryResult[] results, IReadOnlyDictionary<ulong, long> bytes,
        IReadOnlySet<MethodDef> dependencies, IReadOnlyDictionary<MethodRecoveryResult, string> emitProblems,
        IReadOnlySet<MethodRecoveryResult> partialEmitted, Func<MethodRecoveryResult, string?> bodySource,
        Func<MethodRecoveryResult, string?> accessorProof)
    {
        using (var writer = new StreamWriter(Path.Combine(output, "recovery.jsonl")))
            foreach (var result in results)
            {
                var status = result.Declaration is not null ? "runtime-declaration" : result.Body is null ? "hole" : emitProblems.ContainsKey(result) ? "emit-failed" : "emitted";
                writer.WriteLine(JsonSerializer.Serialize(new
                {
                    address = $"0x{result.Entry:x}",
                    method = result.Method.ToString(),
                    status,
                    methodIndex = result.Method.Method.Index,
                    assembly = result.Method.Method.Owner.Assembly,
                    bytes = bytes[result.Entry],
                    dependency = dependencies.Contains(result.Method.Method),
                    bodySource = result.Declaration is not null ? "runtime-declaration" : result.Body is null ? null : bodySource(result),
                    declaration = result.Declaration?.ToString(),
                    platformImport = result.PlatformImport,
                    accessorProof = accessorProof(result),
                    holes = result.Holes.Select(h => new { address = $"0x{h.Address:x}", reason = h.Reason, derived = h.Derived, code = h.Code, category = h.Category, id = h.Id, causeId = h.CauseId }),
                    rejections = result.Body is null ? result.Rejections.Select(r => new { rule = r.Rule, address = $"0x{r.Address:x}", reason = r.Reason }) : null,
                    emitProblem = emitProblems.GetValueOrDefault(result),
                    partial = partialEmitted.Contains(result),
                    statements = result.Body?.Blocks.Sum(b => b.Statements.Count),
                    regions = result.Body?.Regions.Count,
                    features = result.Body is { } body ? Features(body) : null,
                }, Json));
            }

    }

    public static void WriteEmitted(string output, IReadOnlyList<MethodRecoveryResult> emitted, Skeleton skeleton,
        IReadOnlySet<MethodDef> dependencyMethods)
    {
        File.WriteAllLines(Path.Combine(output, "emitted.tsv"), emitted.Select(r =>
        {
            var top = Top(r.Method.Method.Owner);
            return $"{top.Assembly}\t{top.Namespace}\t{top.SimpleName}\t0x{r.Entry:x}\t{r.Method}\t0x{skeleton.Method(r.Method.Method).MetadataToken.ToUInt32():x8}\t{(dependencyMethods.Contains(r.Method.Method) ? "dependency" : "target")}";
        }));
    }

    public static void WriteUnselected(string output, SelectionStage.Selection selection)
    {
        File.WriteAllLines(Path.Combine(output, "unselected-methods.tsv"), new[] { "method\tdefinition_index\tkind\tnative_entries" }.Concat(selection.Unselected.Select(m =>
            $"{MethodRef.Open(m)}\t{m.Index}\t{(m.IsAbstract ? "abstract" : selection.NativeEntries.ContainsKey(m) ? "native-omitted" : "no-native-entry")}\t{string.Join(",", selection.NativeEntries.GetValueOrDefault(m, []).Select(e => $"0x{e:x}"))}")));
    }

    /// <summary>目标方法单独计数；依赖、部分体和运行时声明不计为完整方法体。</summary>
    public static void WriteCoverage(string output, Cpp2CS.Facts.ProgramFacts facts,
        MethodRecoveryResult[] targets, IReadOnlyList<MethodRecoveryResult> published,
        IReadOnlyDictionary<ManagedBody, EmissionProblem> checkedProblems,
        IReadOnlyDictionary<ManagedBody, EmissionProblem> sourceProblems)
    {
        var selected = targets.ToHashSet();
        var emitted = published.Where(selected.Contains).ToArray();
        File.WriteAllText(Path.Combine(output, "coverage.json"), JsonSerializer.Serialize(new
        {
            architecture = facts.Model.Image.Architecture.ToString(),
            selected = targets.Length,
            emitted = emitted.Length,
            emittedPercent = targets.Length == 0 ? 0 : 100.0 * emitted.Length / targets.Length,
            selectedNativeEntries = targets.Select(r => r.Entry).Distinct().Count(),
            emittedNativeEntries = emitted.Select(r => r.Entry).Distinct().Count(),
            managedCheckedMethods = emitted.Count(r => !checkedProblems.ContainsKey(r.Body!)),
            sourceFormCheckedMethods = emitted.Count(r => !checkedProblems.ContainsKey(r.Body!) && !sourceProblems.ContainsKey(r.Body!)),
            runtimeDeclarations = targets.Count(r => r.Declaration is not null),
            facts.Base.Timings,
        }, Json));
    }
}
