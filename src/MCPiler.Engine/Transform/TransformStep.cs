using System.Text.Json.Nodes;

namespace MCPiler.Engine.Transform;

/// <summary>
/// One step of a transformation program.
/// </summary>
/// <remarks>
/// <para>
/// Every location a step reads or writes is declared syntactically as an RFC 6901 pointer
/// parameter. A step never computes its own source or target, which is what makes the
/// addressing statically checkable and is the reason the exclusions in
/// <c>ExclusionValidation</c> are enforceable at all.
/// </para>
/// <para>
/// The model carries no expression string, no regular expression, no host function and no
/// ambient source. That absence is the security boundary, not a stylistic choice.
/// </para>
/// </remarks>
internal abstract record TransformStep
{
    /// <summary>Which vocabulary entry this step is.</summary>
    internal abstract TransformOperation Op { get; }
}

/// <summary>Copies the value at the source to the target.</summary>
/// <param name="Source">Where to read.</param>
/// <param name="Target">Where to write.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record CopyStep(string Source, string Target, TransformOnMissing OnMissing)
    : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Copy;
}

/// <summary>Moves the value at the source to the target.</summary>
/// <param name="Source">Where to read and remove.</param>
/// <param name="Target">Where to write.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record MoveStep(string Source, string Target, TransformOnMissing OnMissing)
    : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Move;
}

/// <summary>Removes the value at the target.</summary>
/// <param name="Target">What to remove.</param>
internal sealed record OmitStep(string Target) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Omit;
}

/// <summary>Projects the listed members of a source object into a new object at the target.</summary>
/// <param name="Source">The object to project from.</param>
/// <param name="Members">The member names to keep.</param>
/// <param name="Target">Where to write the projection.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record PickStep(
    string Source,
    IReadOnlyList<string> Members,
    string Target,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Pick;
}

/// <summary>Wraps the value at the source under a named member at the target.</summary>
/// <param name="Source">The value to wrap.</param>
/// <param name="Name">The member name to wrap it under.</param>
/// <param name="Target">Where to write the wrapper.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record NestStep(
    string Source,
    string Name,
    string Target,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Nest;
}

/// <summary>Promotes the members of a source object one level up onto the target.</summary>
/// <param name="Source">The object to promote from.</param>
/// <param name="Target">The object to promote onto.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record FlattenStep(string Source, string Target, TransformOnMissing OnMissing)
    : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Flatten;
}

/// <summary>Concatenates an array of arrays into one array at the target.</summary>
/// <param name="Source">The array of arrays.</param>
/// <param name="Target">Where to write the concatenation.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record FlattenArrayStep(string Source, string Target, TransformOnMissing OnMissing)
    : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.FlattenArray;
}

/// <summary>Shallow-merges the source objects, in order, into an object at the target.</summary>
/// <param name="Sources">The objects to merge, in precedence order.</param>
/// <param name="Target">Where to write the merged object.</param>
/// <param name="OnMissing">What to do when a source does not resolve.</param>
internal sealed record MergeStep(
    IReadOnlyList<string> Sources,
    string Target,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Merge;
}

/// <summary>Writes a literal value at the target.</summary>
/// <param name="Target">Where to write.</param>
/// <param name="Value">The literal.</param>
internal sealed record SetConstantStep(string Target, JsonNode Value) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.SetConstant;
}

/// <summary>Writes a literal value only where the target is absent or null.</summary>
/// <param name="Target">Where to write.</param>
/// <param name="Value">The literal.</param>
internal sealed record DefaultStep(string Target, JsonNode Value) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Default;
}

/// <summary>Coerces the value at the source to a declared JSON type.</summary>
/// <param name="Source">Where to read.</param>
/// <param name="Target">Where to write the coerced value.</param>
/// <param name="To">The type to coerce to.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record ConvertStep(
    string Source,
    string Target,
    TransformConvertType To,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Convert;
}

/// <summary>One named value a template pattern may substitute.</summary>
/// <param name="Name">The placeholder name.</param>
/// <param name="Pointer">Where the value is read from.</param>
internal sealed record TemplateArgument(string Name, string Pointer);

/// <summary>
/// Renders literal text with named placeholders bound to declared pointer arguments.
/// </summary>
/// <param name="Target">Where to write the rendered string.</param>
/// <param name="Pattern">The literal text and its placeholders.</param>
/// <param name="Arguments">The declared placeholder bindings.</param>
/// <param name="OnMissing">What to do when an argument does not resolve.</param>
/// <remarks>
/// This is the vocabulary's named-substitution entry and the only place a pattern string
/// appears at all, which is why its admitted syntax is checked rather than assumed.
/// </remarks>
internal sealed record TemplateStep(
    string Target,
    string Pattern,
    IReadOnlyList<TemplateArgument> Arguments,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Template;
}

/// <summary>Writes the first source that resolves to a non-null value.</summary>
/// <param name="Sources">The candidate sources, in order.</param>
/// <param name="Target">Where to write.</param>
internal sealed record CoalesceStep(IReadOnlyList<string> Sources, string Target) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.Coalesce;
}

/// <summary>One entry of an enumeration remapping.</summary>
/// <param name="From">The value to match.</param>
/// <param name="To">The value to write instead.</param>
internal sealed record EnumMapping(JsonNode From, JsonNode To);

/// <summary>Rewrites the value at the source through a declared value table.</summary>
/// <param name="Source">Where to read.</param>
/// <param name="Target">Where to write.</param>
/// <param name="Mappings">The value table.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record EnumMapStep(
    string Source,
    string Target,
    IReadOnlyList<EnumMapping> Mappings,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.EnumMap;
}

/// <summary>
/// Transforms each item of an array through a nested step list that addresses the item as its
/// document root.
/// </summary>
/// <param name="Source">The array to iterate.</param>
/// <param name="Target">Where to write the transformed array.</param>
/// <param name="MaxItems">The mandatory iteration bound.</param>
/// <param name="Steps">The steps applied to each item.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record MapArrayStep(
    string Source,
    string Target,
    int MaxItems,
    IReadOnlyList<TransformStep> Steps,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.MapArray;
}

/// <summary>
/// Transforms each entry value of an object through a nested step list that addresses the
/// value as its document root.
/// </summary>
/// <param name="Source">The object to iterate.</param>
/// <param name="Target">Where to write the transformed object.</param>
/// <param name="MaxEntries">The mandatory iteration bound.</param>
/// <param name="Steps">The steps applied to each entry value.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record MapObjectStep(
    string Source,
    string Target,
    int MaxEntries,
    IReadOnlyList<TransformStep> Steps,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.MapObject;
}

/// <summary>Truncates an array to its first items.</summary>
/// <param name="Source">The array to truncate.</param>
/// <param name="Target">Where to write the truncation.</param>
/// <param name="MaxItems">The mandatory bound.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
internal sealed record LimitArrayStep(
    string Source,
    string Target,
    int MaxItems,
    TransformOnMissing OnMissing) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.LimitArray;
}

/// <summary>
/// A condition over the document, expressed as a closed predicate object.
/// </summary>
/// <remarks>
/// The closure is the point. A condition expressed as a string would be an expression
/// language, and an expression language is the escape hatch the exclusions forbid.
/// </remarks>
internal abstract record TransformPredicate;

/// <summary>True when the pointer resolves.</summary>
/// <param name="Pointer">What to test for.</param>
internal sealed record ExistsPredicate(string Pointer) : TransformPredicate;

/// <summary>Compares the value at a pointer against a literal.</summary>
/// <param name="Operator">One of the declared comparison operators.</param>
/// <param name="Pointer">Where to read.</param>
/// <param name="Value">The literal to compare against.</param>
internal sealed record ComparePredicate(string Operator, string Pointer, JsonNode Value)
    : TransformPredicate;

/// <summary>True when the value at a pointer is one of a declared set.</summary>
/// <param name="Pointer">Where to read.</param>
/// <param name="Values">The admitted values.</param>
internal sealed record InPredicate(string Pointer, IReadOnlyList<JsonNode> Values)
    : TransformPredicate;

/// <summary>Negates another predicate.</summary>
/// <param name="Inner">The predicate to negate.</param>
internal sealed record NotPredicate(TransformPredicate Inner) : TransformPredicate;

/// <summary>Combines predicates with a declared connective.</summary>
/// <param name="Operator">Either <c>and</c> or <c>or</c>.</param>
/// <param name="Children">The combined predicates, never empty.</param>
internal sealed record GroupPredicate(string Operator, IReadOnlyList<TransformPredicate> Children)
    : TransformPredicate;

/// <summary>Applies one of two step lists depending on a condition.</summary>
/// <param name="Condition">The predicate to evaluate.</param>
/// <param name="Steps">Applied when the condition holds.</param>
/// <param name="ElseSteps">Applied when it does not.</param>
internal sealed record WhenStep(
    TransformPredicate Condition,
    IReadOnlyList<TransformStep> Steps,
    IReadOnlyList<TransformStep> ElseSteps) : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.When;
}

/// <summary>
/// Moves a file handle from source to target by reference.
/// </summary>
/// <param name="Source">Where the handle is read from.</param>
/// <param name="Target">Where the handle is written.</param>
/// <param name="OnMissing">What to do when the source does not resolve.</param>
/// <remarks>
/// The only operation permitted to place a file into a binary or multipart slot. File bytes
/// never enter the transformed document, so no other step can read, encode or decode them.
/// </remarks>
internal sealed record FileRefStep(string Source, string Target, TransformOnMissing OnMissing)
    : TransformStep
{
    /// <inheritdoc/>
    internal override TransformOperation Op => TransformOperation.FileRef;
}
