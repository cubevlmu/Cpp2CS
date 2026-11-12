using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Recovery.Values;

namespace Cpp2CS.Recovery.Calls;

/// <summary>已证明的零参数接口桩按槽号恢复 callvirt；运行时实现和 MethodInfo 仍由接口分派选择。</summary>
internal static class InterfaceInvokeCalls
{
    internal static bool Run(MachineFunction function, ValueModel values, ProgramFacts facts, ManagedAbi abi)
    {
        var changed = false;
        foreach (var call in function.Blocks.SelectMany(b => b.Statements).OfType<Call>().ToArray())
        {
            if (call is not { Op: null, Resolved: null, Kind: CallKind.Direct or CallKind.Tail, Target: Const target }
                || !facts.NativeInterfaceInvokes.Matches(target.Value)) continue;
            var slotAt = call.ArgumentIndex(Storage.Gpr(1)); var classAt = call.ArgumentIndex(Storage.Gpr(2)); var receiverAt = call.ArgumentIndex(Storage.Gpr(8));
            var operands = values.Operands(call);
            if (slotAt < 0 || classAt < 0 || receiverAt < 0
                || SymTable.Resolve(operands[slotAt + 1]) is not ConstSym slot
                || SymTable.Resolve(operands[classAt + 1]) is not EntitySym { Symbol: { Kind: SymbolKind.Class, Value: DefinitionRef { Definition.IsInterface: true } type } }
                || DispatchResolution.Slot(type, (ushort)slot.Value, interfaceOnly: true) is not { Method: { IsStatic: false, Parameters.Count: 0, GenericParameters.Count: 0 } } method
                || abi.Machine(method, out _) is not { This.Pieces: [{ Register: var receiver }], Return: not { Transfer: Transfer.ResultBuffer } }
                || receiver != Storage.Gpr(1)) continue;
            Machine.Ssa.ReadEffects.PreserveInputs(function, call.Arguments);
            var block = values.BlockOf(call);
            var at = block.Statements.IndexOf(call);
            block.Statements[at] = call with { Op = new(OpKind.CallInterface, ((object)type, (int)(ushort)slot.Value)), Resolved = method,
                Arguments = [call.Arguments[receiverAt]], Sources = [Storage.Gpr(1)], StackPointer = null };
            changed = true;
        }
        return changed;
    }
}
