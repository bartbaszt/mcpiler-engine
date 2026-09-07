namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The single authority that inspects binding shape.
/// </summary>
/// <remarks>
/// <para>
/// Every component that needs to know what a binding executes — validation, capability and
/// security gates, tool derivation, search indexing, and eventually invocation — asks this
/// type instead of writing its own <c>binding is X</c> test.
/// </para>
/// <para>
/// The rule exists because of a real defect class: a capability gate once resolved an
/// execution key with a local type switch in which a transformed binding fell through to the
/// source key, while invocation executed the transformed binding's base key. The two answers
/// diverged, and a file upload passed a gate that forbade files. With one seam, inspection and
/// execution cannot disagree, because there is only one answer to disagree about.
/// </para>
/// <para>
/// Section reading is not a consumer: constructing a binding from JSON necessarily discriminates
/// on the declared type. What is forbidden is re-deriving, elsewhere, what an already
/// constructed binding does.
/// </para>
/// </remarks>
public static class ManifestBindingDispatcher
{
    /// <summary>
    /// Returns the HTTP execution shape <paramref name="binding"/> resolves to, or <c>null</c>
    /// when it does not execute a single HTTP operation.
    /// </summary>
    /// <remarks>
    /// A transformed binding resolves through its base. Returning <c>null</c> rather than
    /// throwing keeps this usable by a validator that must report every finding, and a caller
    /// that requires an HTTP shape refuses the <c>null</c> explicitly.
    /// </remarks>
    public static HttpBinding? TryResolveHttp(ManifestBinding? binding) => binding switch
    {
        HttpBinding http => http,
        TransformedHttpBinding transformed => transformed.Base,
        _ => null,
    };

    /// <summary>
    /// Returns the operations-section execution key <paramref name="binding"/> runs, or
    /// <c>null</c> for a binding that runs no single key.
    /// </summary>
    public static string? TryResolveOperationKey(ManifestBinding? binding)
        => TryResolveHttp(binding)?.Operation;

    /// <summary>
    /// Returns the per-operation destination override, or <c>null</c> when the operation uses
    /// the policy base URL.
    /// </summary>
    public static string? TryResolveServerUrl(ManifestBinding? binding)
        => TryResolveHttp(binding)?.ServerUrl;

    /// <summary>
    /// Returns the workflow steps <paramref name="binding"/> runs, or <c>null</c> when it is
    /// not a compound binding.
    /// </summary>
    public static IReadOnlyList<CompoundStepEntry>? TryResolveCompoundSteps(ManifestBinding? binding)
        => binding is CompoundBinding compound ? compound.Steps : null;

    /// <summary>
    /// Returns the operation kind <paramref name="binding"/> implies.
    /// </summary>
    /// <remarks>
    /// A source-backed and a custom HTTP operation are indistinguishable from the binding
    /// alone — both execute one HTTP key — so the distinction stays an authoring statement and
    /// derivation reports the source-backed shape. The kind is validated against the binding
    /// rather than trusted, which is why this returns the derived value instead of the declared
    /// one.
    /// </remarks>
    public static AgentOperationKind DeriveKind(ManifestBinding? binding) => binding switch
    {
        CompoundBinding => AgentOperationKind.Compound,
        _ => AgentOperationKind.SourceBacked,
    };

    /// <summary>
    /// True when <paramref name="declared"/> is compatible with <paramref name="binding"/>.
    /// </summary>
    /// <remarks>
    /// Compound is the only kind the binding shape pins exactly: a compound binding requires
    /// the compound kind and no other binding may claim it. The source-backed and custom HTTP
    /// kinds are both satisfied by a single-key HTTP binding.
    /// </remarks>
    public static bool KindAgreesWithBinding(AgentOperationKind declared, ManifestBinding? binding)
    {
        bool isCompoundBinding = binding is CompoundBinding;
        bool isCompoundKind = declared == AgentOperationKind.Compound;

        return isCompoundBinding == isCompoundKind;
    }
}
