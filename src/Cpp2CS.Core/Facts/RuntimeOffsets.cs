namespace Cpp2CS.Facts;

/// <summary>由目标运行时导出代码核实的字段位置；未知字段不沿用其他平台的布局。</summary>
public sealed record RuntimeOffsets(int? ClassCctorFinished, int? ClassStaticFields, string Evidence)
{
    public int? ClassInitializationFlags { get; init; }
    public int? MethodClass { get; init; }
    public int? ClassRgctxData { get; init; }
    public int? ClassVtable { get; init; }
    public int? MethodPointer { get; init; }
    public int? MethodVirtualPointer { get; init; }
    public int? MethodInvoker { get; init; }
    public int? ClassFields { get; init; }
    public int? FieldInfoSize { get; init; }
}
