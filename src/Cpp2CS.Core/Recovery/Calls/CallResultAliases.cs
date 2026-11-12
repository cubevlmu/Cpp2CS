using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Recovery.Calls;

/// <summary>将 ABI 规定回传的结果缓冲区地址写成显式 SSA 别名，供公共内存分析使用。</summary>
internal static class CallResultAliases
{
    internal static bool Run(MachineFunction function, Func<Call, CallShape> shapes)
    {
        var changed = false;
        foreach (var block in function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Call { DoesNotReturn: false, Kind: CallKind.Direct or CallKind.Indirect } call
                    || shapes(call) is not { IsRuntime: false, Signature: { BufferPointerResult: { } returned,
                        Return: { Transfer: Transfer.ResultBuffer, Pieces: [var buffer] } } }
                    || call.Defines.Length != call.Results.Length
                    || Array.IndexOf(call.Results, returned) is not (var result and >= 0)
                    || call.Defines[result] is not { Width: 64 } definition
                    || call.ArgumentIndex(buffer.Register) is not (var argument and >= 0)
                    || argument >= call.Arguments.Length || call.Arguments[argument].Width != 64) continue;
                // 结果是传入地址本身；调用对缓冲区内容的写入和抛出效果仍由原调用表达。
                block.Statements[i] = call with
                {
                    Results = call.Results.Where((_, at) => at != result).ToArray(),
                    Defines = call.Defines.Where((_, at) => at != result).ToArray(),
                };
                block.Statements.Insert(++i, new Define(call.Address, definition, call.Arguments[argument]));
                changed = true;
            }
        return changed;
    }
}
