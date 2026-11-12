using Cpp2CS.Facts;
using Cpp2CS.Input;
using Cpp2CS.Model;
using Cpp2CS.Pipeline;
using Cpp2CS.Recovery;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Cli;

internal static class RecoveryCommand
{
    /// <summary>只收集指定程序集全部原生入口的基础事实，不执行恢复或扩大依赖恢复范围。</summary>
    public static void WriteFacts(string binary, string metadata, string sla, string output, string assembly)
    {
        Directory.CreateDirectory(output);
        using var decoders = new ThreadLocal<SleighDecoder>(() => new(sla), trackAllValues: true);
        try
        {
            var facts = BuildFacts(new RecoveryRequest(binary, metadata, output), assembly, decoders, Console.WriteLine);
            File.WriteAllLines(Path.Combine(output, "helper-inputs.jsonl"), facts.Scan.All.Where(r => r.Kind is RefKind.Call or RefKind.TailCall)
                .GroupBy(r => r.Target).Select(group => System.Text.Json.JsonSerializer.Serialize(new
                {
                    target = $"0x{group.Key:x}", calls = group.Count(), slotCalls = facts.Usages.SlotAddressBeforeCall.GetValueOrDefault(group.Key),
                    range = facts.Code.At(group.Key), helper = facts.Helpers.At(group.Key), imageSha256 = facts.Model.Image.Sha256,
                })));
            var shapes = new Cpp2CS.Recovery.Calls.CallShapes(facts, facts.CreateAbi(), (_, _) => false);
            File.WriteAllLines(Path.Combine(output, "call-candidates.jsonl"), facts.Scan.All.Where(r => r.Kind is RefKind.Call or RefKind.TailCall)
                .Select(r => r.Target).Distinct().Select(target => shapes.Of(new Cpp2CS.Ir.Call(0, Cpp2CS.Ir.CallKind.Direct, Cpp2CS.Ir.Expr.C(target, 64))))
                .Where(shape => shape.Candidates.Count > 1).Select(shape => System.Text.Json.JsonSerializer.Serialize(new
                {
                    target = shape.Call.Target.ToString(), abiAgreement = shape.Signature is not null, shape.MethodInfoUnused,
                    methodInfo = shape.Signature?.MethodInfo?.Register.ToString(),
                    candidates = shape.Candidates.Select(m => new { method = m.ToString(), owner = m.DeclaringType.ToString(),
                        attributes = m.Method.Attributes.ToString(), returned = m.Concrete(m.Method.ReturnType).ToString(),
                        parameters = m.Method.Parameters.Select(p => m.Concrete(p.Type).ToString()).ToArray() }),
                })));
        }
        finally { foreach (var decoder in decoders.Values) decoder.Dispose(); }
    }

    public static void Run(string binary, string metadata, string sla, string output, string assembly, int limit, string[]? options = null)
    {
        var request = RecoveryRequest.Parse(binary, metadata, output,
            ["--assemblies", assembly, "--limit", limit.ToString(System.Globalization.CultureInfo.InvariantCulture),
             "--source-layout", "project", "--method-timeout", "0", "--max-memory-mb", "0", .. options ?? []]);
        // 每个工作线程独享原生上下文，管线结束后统一释放。
        using var decoders = new ThreadLocal<SleighDecoder>(() => new(sla), trackAllValues: true);
        try
        {
            RecoverySession.Run(request, log => BuildFacts(request, assembly, decoders, log), Console.WriteLine);
        }
        finally
        {
            foreach (var decoder in decoders.Values) decoder.Dispose();
        }
    }

    private static ProgramFacts BuildFacts(RecoveryRequest request, string assembly,
        ThreadLocal<SleighDecoder> decoders, Action<string> log)
    {
        var binary = request.Binary;
        var metadata = request.Metadata;
        var (model, builder) = ModelBuilder.Load(binary, metadata);
        if (model.Image.Architecture != Architecture.X64) throw new NotSupportedException("恢复入口要求 x64 PE");
        var decoder = decoders.Value!;
        var (registrations, registrationProblems) = RegistrationReader.Read(model, builder.CodeRegistration, builder.MetadataRegistration);
        if (registrationProblems.Count > 0) throw new InvalidDataException(string.Join(Environment.NewLine, registrationProblems));
        // 无展开表的泛型实例也需要入口边界；注册信息只补充分析依据，不扩大恢复程序集。
        var code = CodeMap.BuildPe(model.Image, model.Methods.Select(m => m.Address).Concat(registrations.Entries
            .Where(e => e.Kind is EntryKind.Method or EntryKind.GenericMethod).Select(e => e.Address)));
        var layouts = new FieldLayouts(model);
        var types = new ManagedTypes(model, layouts);
        var entries = new MethodEntries(model, registrations, types);
        var nativeMethods = entries.Definitions.Where(e => e.Instance.Method.Owner.Assembly == assembly)
            .Select(e => new RecoveryTarget(e.Instance, e.Address)).ToArray();
        var selected = nativeMethods.Take(request.Limit).ToArray();
        if (selected.Length == 0) throw new ArgumentException("选定程序集没有带原生地址的方法");
        var scan = X64References.Scan(code, new PcodeMachine(model.Image, decoder), selected.Select(m => m.Entry));
        var usages = UsageSlots.Build(model, code, scan);
        var helpers = X64RuntimeHelpers.Identify(code, scan, new PcodeMachine(model.Image, decoder), usages, model);
        var facts = new ProgramFacts(new BaseFacts
        {
            Model = model, Code = code, Scan = scan, Registrations = registrations,
            Layouts = layouts, Helpers = RuntimeHelpers.FromEvidence(code, scan, helpers),
            RuntimeOffsets = X64RuntimeOffsets.Identify(new PcodeMachine(model.Image, decoder), helpers, model.MetadataVersion),
            Usages = usages,
            Checks = new(), Timings = new Dictionary<string, double>(),
            MachineFactory = () => new PcodeMachine(model.Image, decoders.Value!),
            NativeInputs = X64NativeContracts.Identify(code),
            Options = request.Options,
        }, new());
        log($"[Facts] x64：原生见证定义 {nativeMethods.Length}，引用 {scan.All.Count}，辅助函数 {helpers.Length}");
        return facts;
    }
}
