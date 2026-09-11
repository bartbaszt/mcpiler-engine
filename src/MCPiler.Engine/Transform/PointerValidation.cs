using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Transform;

/// <summary>Whether an addressed location is read or written.</summary>
internal enum PointerPosition
{
    /// <summary>The step reads here.</summary>
    Source,

    /// <summary>The step writes here.</summary>
    Target,
}

/// <summary>
/// Where a pointer is addressed from: the program's own document, or the item of an
/// enclosing iteration.
/// </summary>
internal enum PointerScope
{
    /// <summary>A top-level step, addressing the request or response parts and the agent side.</summary>
    Program,

    /// <summary>A step inside <c>mapArray</c> or <c>mapObject</c>, addressing the item.</summary>
    Item,
}

/// <summary>
/// Validates that every pointer a program declares is a well-formed RFC 6901 pointer rooted
/// where its direction and position allow.
/// </summary>
/// <remarks>
/// <para>
/// The seven roots come from <see cref="ManifestPointerRoots"/>, which compound mappings
/// already address, and the syntax rule from <see cref="JsonPointer"/>, which the manifest's
/// own diagnostics already use. Restating either here would be a second definition of a
/// boundary that only means anything if there is one.
/// </para>
/// <para>
/// Inside an iteration the addressed document is the item, which has no request parts and no
/// response status. A part-selector root there is a category error and is refused: it would
/// read <c>/headers</c> out of an array element that merely happens to have a member of that
/// name, which is the kind of accidental agreement a security boundary must not rely on.
/// Anything else is item-relative, because that is what the evaluator resolves against.
/// </para>
/// </remarks>
internal static class PointerValidation
{
    /// <summary>Reports every pointer defect in <paramref name="program"/>.</summary>
    internal static void Validate(TransformProgram program, ICollection<TransformFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(findings);

        foreach ((TransformStep step, int index, string location, PointerScope scope) in
            StepWalk.Descend(program.Steps))
        {
            foreach ((string pointer, PointerPosition position) in PointersOf(step))
            {
                if (!JsonPointer.IsSyntacticallyValid(pointer))
                {
                    findings.Add(new TransformFinding(
                        TransformCodes.PointerSyntax,
                        $"The pointer '{DiagnosticText.Echo(pointer)}' is not a valid RFC 6901 JSON Pointer.",
                        index,
                        location));
                    continue;
                }

                if (!RootIsAllowed(pointer, scope, program.Direction, position))
                {
                    findings.Add(new TransformFinding(
                        TransformCodes.PointerRoot,
                        $"The pointer '{DiagnosticText.Echo(pointer)}' is rooted outside the set permitted " +
                        $"for a {Name(position)} in the {Name(program.Direction)} direction{Qualifier(scope)}.",
                        index,
                        location));
                }
            }
        }
    }

    /// <summary>Whether a syntactically valid pointer is rooted where it is allowed to be.</summary>
    internal static bool RootIsAllowed(
        string pointer,
        PointerScope scope,
        TransformDirection direction,
        PointerPosition position)
    {
        if (scope == PointerScope.Item)
        {
            // The item is the document root, and it has no parts.
            return !IsPartRooted(pointer);
        }

        bool httpSide = (direction, position) switch
        {
            (TransformDirection.Input, PointerPosition.Target) => true,
            (TransformDirection.Output, PointerPosition.Source) => true,
            _ => false,
        };

        if (!httpSide)
        {
            // The agent side is a plain document, so anything that is not a part selector
            // addresses into it. The empty pointer is that document.
            return !IsPartRooted(pointer);
        }

        return direction == TransformDirection.Input
            ? ManifestPointerRoots.IsRequestTarget(pointer)
            : ManifestPointerRoots.IsResponseSource(pointer);
    }

    /// <summary>Whether the pointer starts at any of the seven part selectors.</summary>
    private static bool IsPartRooted(string pointer)
        => ManifestPointerRoots.IsRequestTarget(pointer) || ManifestPointerRoots.IsResponseSource(pointer);

    private static string Name(PointerPosition position)
        => position == PointerPosition.Source ? "source" : "target";

    private static string Name(TransformDirection direction)
        => direction == TransformDirection.Input ? "input" : "output";

    private static string Qualifier(PointerScope scope)
        => scope == PointerScope.Item ? ", inside an iteration whose root is the item" : string.Empty;

    /// <summary>
    /// Every location the step addresses, including the ones a caller supplies indirectly.
    /// </summary>
    /// <remarks>
    /// A template's argument pointers are here. They are read at evaluation exactly like a
    /// step source, so leaving them out would make <c>template</c> the one operation whose
    /// reads are unchecked - an output-direction program could bind an argument to
    /// <c>/parts</c> and no root rule would ever see it.
    /// </remarks>
    private static IEnumerable<(string Pointer, PointerPosition Position)> PointersOf(TransformStep step)
        => step switch
        {
            CopyStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            MoveStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            OmitStep s => [(s.Target, PointerPosition.Target)],
            PickStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            NestStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            FlattenStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            FlattenArrayStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            MergeStep s => s.Sources
                .Select(static source => (source, PointerPosition.Source))
                .Append((s.Target, PointerPosition.Target)),
            SetConstantStep s => [(s.Target, PointerPosition.Target)],
            DefaultStep s => [(s.Target, PointerPosition.Target)],
            ConvertStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            TemplateStep s => s.Arguments
                .Select(static argument => (argument.Pointer, PointerPosition.Source))
                .Append((s.Target, PointerPosition.Target)),
            CoalesceStep s => s.Sources
                .Select(static source => (source, PointerPosition.Source))
                .Append((s.Target, PointerPosition.Target)),
            EnumMapStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            MapArrayStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            MapObjectStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            LimitArrayStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            FileRefStep s => [(s.Source, PointerPosition.Source), (s.Target, PointerPosition.Target)],
            WhenStep s => PointersOf(s.Condition),
            _ => [],
        };

    private static IEnumerable<(string, PointerPosition)> PointersOf(TransformPredicate predicate)
        => predicate switch
        {
            ExistsPredicate p => [(p.Pointer, PointerPosition.Source)],
            ComparePredicate p => [(p.Pointer, PointerPosition.Source)],
            InPredicate p => [(p.Pointer, PointerPosition.Source)],
            NotPredicate p => PointersOf(p.Inner),
            GroupPredicate p => p.Children.SelectMany(PointersOf),
            _ => [],
        };
}
