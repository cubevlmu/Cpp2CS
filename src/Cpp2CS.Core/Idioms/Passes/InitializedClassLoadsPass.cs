using Cpp2CS.Ir;
using Cpp2CS.Facts;
namespace Cpp2CS.Idioms;

internal static class InitializedClassLoadsPass
{
    internal static bool InitializedClassLoads(this IdiomState state)
    {
        var x64 = state.facts.Model.Image.Architecture == Architecture.X64;
        return ClassInitializationFacts.Run(state.function, constructorFacts: state.self?.Method.Name != ".cctor",
            classFlagsOffset: x64 ? state.facts.Base.RuntimeOffsets?.ClassInitializationFlags ?? -1 : RuntimeLayout.ClassBitflags1,
            constructorFinishedOffset: x64 ? state.facts.Base.RuntimeOffsets?.ClassCctorFinished ?? -1 : RuntimeLayout.ClassCctorFinishedOrNoCctor);
    }
}
