using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.CSharp.Transforms;
using ICSharpCode.Decompiler.Semantics;
using ICSharpCode.Decompiler.TypeSystem;

namespace Cpp2CS.Output;

public static partial class Decompilation
{
    /// <summary>裁剪库不能证明短类型名在完整引用库里唯一；外部静态成员与 typeof 保留已解析的全限定类型身份。</summary>
    private sealed class ExternalStaticTypeNames : IAstTransform
    {
        public void Run(AstNode rootNode, TransformContext context)
        {
            var builder = new TypeSystemAstBuilder { AlwaysUseGlobal = true };
            var targets = rootNode.Descendants.OfType<TypeReferenceExpression>().Select(t => t.Type)
                .Concat(rootNode.Descendants.OfType<TypeOfExpression>().Select(t => t.Type)).ToArray();
            foreach (var target in targets)
            {
                if (target is not SimpleType || target.Annotation<TypeResolveResult>()?.Type is not { } type
                    || type.GetDefinition() is not { } definition || ReferenceEquals(definition.ParentModule, context.TypeSystem.MainModule)) continue;
                target.ReplaceWith(builder.ConvertType(type));
            }
        }
    }
}
