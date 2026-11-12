
namespace Cpp2CS.Facts;

/// <summary>独立原生输入契约；不提供托管身份、返回关系或内存效果。</summary>
public sealed record NativeInputContract(Cpp2CS.Ir.Storage[] Reads, string Evidence);

public sealed record BaseFacts
{
    public Func<Cpp2CS.Machine.Flow.IMachine>? MachineFactory { get; init; }
    public IReadOnlyDictionary<ulong, NativeInputContract> NativeInputs { get; init; } = new Dictionary<ulong, NativeInputContract>();
    public ProgramModel Model { get; init; } = null!;
    public CodeMap Code { get; init; } = null!;
    public CodeScan Scan { get; init; } = null!;
    public Registrations Registrations { get; init; } = null!;
    public UsageSlots Usages { get; init; } = null!;
    public RuntimeHelpers Helpers { get; init; } = null!;
    public RuntimeOffsets? RuntimeOffsets { get; init; }
    public FieldLayouts Layouts { get; init; } = null!;
    public FactChecks Checks { get; init; } = null!;
    public IReadOnlyDictionary<string, double> Timings { get; init; } = null!;
    public Cpp2CS.Options.RecoveryOptions Options { get; init; } = new();
    public CodeEntry[] EntriesAt(ulong address) => Registrations.At(address);
}
