namespace MCPiler.Engine.Transform;

/// <summary>The closed step vocabulary.</summary>
/// <remarks>
/// Nineteen entries, fixed by the format version. The enum and the wire names in
/// <see cref="StepVocabulary"/> are the whole of it; there is no registration point, no
/// configuration key and no plug-in surface anywhere in this namespace, and
/// <c>ExclusionValidation</c> asserts that absence rather than trusting it.
/// </remarks>
internal enum TransformOperation
{
    /// <summary>Copy a value.</summary>
    Copy,

    /// <summary>Move a value.</summary>
    Move,

    /// <summary>Remove a value.</summary>
    Omit,

    /// <summary>Project named members.</summary>
    Pick,

    /// <summary>Wrap a value under a member.</summary>
    Nest,

    /// <summary>Promote an object's members one level.</summary>
    Flatten,

    /// <summary>Concatenate an array of arrays.</summary>
    FlattenArray,

    /// <summary>Shallow-merge objects.</summary>
    Merge,

    /// <summary>Write a literal.</summary>
    SetConstant,

    /// <summary>Write a literal where absent.</summary>
    Default,

    /// <summary>Coerce a value's type.</summary>
    Convert,

    /// <summary>Render literal text with bound placeholders.</summary>
    Template,

    /// <summary>Write the first source that resolves.</summary>
    Coalesce,

    /// <summary>Remap values through a declared table.</summary>
    EnumMap,

    /// <summary>Iterate an array.</summary>
    MapArray,

    /// <summary>Iterate an object.</summary>
    MapObject,

    /// <summary>Truncate an array.</summary>
    LimitArray,

    /// <summary>Apply steps conditionally.</summary>
    When,

    /// <summary>Move a file handle by reference.</summary>
    FileRef,
}

/// <summary>
/// The one place a wire operation name becomes a vocabulary entry.
/// </summary>
/// <remarks>
/// <para>
/// The map is private and there is no method that adds to it. That is the entirety of the
/// extension story: the vocabulary grows by editing this file under a new
/// <c>transformVersion</c>, and it cannot grow through configuration, a host registration
/// call or a plug-in, because no such entry point exists to call.
/// </para>
/// <para>
/// Lookup is ordinal. A case-insensitive match would admit <c>SetConstant</c> and
/// <c>setconstant</c> as the same operation, which would make two byte-different programs
/// behave identically and quietly defeat the format's byte-identity rules.
/// </para>
/// </remarks>
internal static class StepVocabulary
{
    private static readonly Dictionary<string, TransformOperation> ByName =
        new(StringComparer.Ordinal)
        {
            ["copy"] = TransformOperation.Copy,
            ["move"] = TransformOperation.Move,
            ["omit"] = TransformOperation.Omit,
            ["pick"] = TransformOperation.Pick,
            ["nest"] = TransformOperation.Nest,
            ["flatten"] = TransformOperation.Flatten,
            ["flattenArray"] = TransformOperation.FlattenArray,
            ["merge"] = TransformOperation.Merge,
            ["setConstant"] = TransformOperation.SetConstant,
            ["default"] = TransformOperation.Default,
            ["convert"] = TransformOperation.Convert,
            ["template"] = TransformOperation.Template,
            ["coalesce"] = TransformOperation.Coalesce,
            ["enumMap"] = TransformOperation.EnumMap,
            ["mapArray"] = TransformOperation.MapArray,
            ["mapObject"] = TransformOperation.MapObject,
            ["limitArray"] = TransformOperation.LimitArray,
            ["when"] = TransformOperation.When,
            ["fileRef"] = TransformOperation.FileRef,
        };

    /// <summary>The number of entries the vocabulary is fixed at for this version.</summary>
    internal const int Size = 19;

    /// <summary>Every wire name, in declaration order.</summary>
    internal static IReadOnlyList<string> Names { get; } = [.. ByName.Keys];

    /// <summary>Resolves a wire name to its vocabulary entry.</summary>
    internal static bool TryRead(string? name, out TransformOperation operation)
    {
        if (name is null)
        {
            operation = default;
            return false;
        }

        return ByName.TryGetValue(name, out operation);
    }

    /// <summary>Returns the wire name of a vocabulary entry.</summary>
    internal static string WireName(TransformOperation operation)
        => ByName.First(entry => entry.Value == operation).Key;
}
