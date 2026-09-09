using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>How an agent operation executes.</summary>
/// <remarks>
/// <para>
/// Exactly three shapes exist. Adding a fourth is a format-version change, not an
/// implementation detail, because every consumer that branches on binding shape has to learn
/// it at the same time.
/// </para>
/// <para>
/// <b>Single-seam rule.</b> Only the binding dispatcher may branch on the concrete binding
/// type. Every other Engine component must resolve the executed operation through the
/// dispatcher. A local <c>binding is X</c> switch elsewhere is exactly how a capability gate
/// and the actual execution path came to disagree once before: a transformation wrapping a
/// binary upload behind a file-free source key slipped past a profile without file support,
/// because inspection and execution resolved different keys. An Engine architecture test
/// enforces the rule.
/// </para>
/// </remarks>
public abstract record ManifestBinding
{
    /// <summary>
    /// An authoring identity with no runtime meaning. Defaults to the operation slug.
    /// </summary>
    public string? BindingId { get; init; }
}

/// <summary>A direct HTTP operation invocation.</summary>
/// <param name="Operation">
/// The <c>operations</c>-section execution key. An unknown key is a load-time refusal, not a
/// runtime surprise.
/// </param>
/// <param name="ServerUrl">
/// Overrides the policy base URL for this one operation. It remains fully subject to the
/// policy origin allow-list and can therefore never widen the perimeter.
/// </param>
/// <param name="CredentialRef">
/// The ids of the <c>credentials</c>-section entries that apply to this operation.
/// </param>
/// <remarks>
/// <para>
/// <b>Absent means none.</b> An omitted member and an empty list are one representation and
/// both mean that no credential is applied. The default fails safe: a manifest that forgets to
/// state a scope sends an unauthenticated request rather than sending every declared secret to
/// whichever origin this operation happens to address.
/// </para>
/// <para>
/// A transformed binding reaches this member through its base, because a transformation
/// rewrites arguments and never changes which upstream identity executes. A compound binding
/// has no scope of its own: each step resolves its own binding, so a credential authorized for
/// one step is not thereby authorized for another.
/// </para>
/// </remarks>
public sealed record HttpBinding(
    string Operation,
    string? ServerUrl = null,
    IReadOnlyList<string> CredentialRef = null!) : ManifestBinding
{
    /// <summary>The wire discriminator.</summary>
    public const string TypeName = "http";

    /// <summary>The referenced credential ids, never null.</summary>
    public IReadOnlyList<string> CredentialRef { get; init; } = CredentialRef ?? [];
}

/// <summary>An HTTP operation wrapped in input and output transformation programs.</summary>
/// <param name="Base">The underlying HTTP invocation.</param>
/// <param name="InputProgram">
/// The input transformation program, as a transformation document. Held as JSON because the
/// program grammar is a separate versioned contract with its own validator and its own
/// diagnostic codes.
/// </param>
/// <param name="OutputProgram">The output transformation program.</param>
/// <remarks>
/// The authoring-time dry-run samples that accompany a transformation in Studio are
/// validation evidence, not execution input, and are excluded from the manifest.
/// </remarks>
public sealed record TransformedHttpBinding(
    HttpBinding Base,
    JsonObject? InputProgram = null,
    JsonObject? OutputProgram = null) : ManifestBinding
{
    /// <summary>The wire discriminator.</summary>
    public const string TypeName = "transformedHttp";
}

/// <summary>
/// Compound binding grammar versions, declared outside the record so they can be parameter
/// defaults.
/// </summary>
public static class CompoundBindingVersions
{
    /// <summary>The only compound binding version this format version accepts.</summary>
    public const int Supported = 1;
}

/// <summary>A multi-step workflow over other agent operations.</summary>
/// <param name="Steps">The ordered steps. At least one is required.</param>
/// <param name="BindingVersion">The compound binding grammar version.</param>
/// <param name="FailurePolicy">How a failing step is handled.</param>
/// <param name="MaxTotalResponseBytes">
/// Total response budget across all steps. Defaults to the policy compound bound.
/// </param>
/// <param name="WorkflowTimeout">
/// Whole-workflow budget. Defaults to the policy compound bound.
/// </param>
/// <param name="OutputSelection">
/// What the workflow returns. When absent the workflow returns an empty object.
/// </param>
/// <remarks>
/// A compound operation is advertised as one tool. Nesting is forbidden: a step may not
/// reference another compound operation.
/// </remarks>
public sealed record CompoundBinding(
    IReadOnlyList<CompoundStepEntry> Steps,
    int BindingVersion = CompoundBindingVersions.Supported,
    CompoundFailurePolicy FailurePolicy = CompoundFailurePolicy.FailFast,
    long? MaxTotalResponseBytes = null,
    TimeSpan? WorkflowTimeout = null,
    CompoundOutputSelection? OutputSelection = null) : ManifestBinding
{
    /// <summary>The wire discriminator.</summary>
    public const string TypeName = "compound";
}

/// <summary>One step of a compound workflow.</summary>
/// <param name="StepId">Identifier used to reference this step's response from a later step.</param>
/// <param name="Operation">
/// An <c>agentSurface</c> slug. Must resolve, and must not itself be compound.
/// </param>
/// <param name="InputMappings">How the step's arguments are assembled.</param>
/// <param name="Name">Display name, used in Navigator output and in the search index.</param>
/// <param name="Summary">Short description.</param>
/// <param name="InputProgram">An optional input transformation applied after mapping.</param>
public sealed record CompoundStepEntry(
    string StepId,
    string Operation,
    IReadOnlyList<StepInputMapping> InputMappings = null!,
    string? Name = null,
    string? Summary = null,
    JsonObject? InputProgram = null)
{
    /// <summary>The declared mappings, never null.</summary>
    public IReadOnlyList<StepInputMapping> InputMappings { get; init; } = InputMappings ?? [];
}

/// <summary>Assembles one argument of one step.</summary>
/// <param name="Target">
/// A JSON Pointer into the step's request document. The permitted roots are the request
/// scopes <c>/path</c>, <c>/query</c>, <c>/headers</c>, <c>/cookies</c>, <c>/body</c> and
/// <c>/parts</c>.
/// </param>
/// <param name="Source">Where the value comes from.</param>
public sealed record StepInputMapping(string Target, MappingSource Source);

/// <summary>One entry of a compound workflow's result.</summary>
/// <param name="Target">A JSON Pointer into the workflow result document.</param>
/// <param name="Source">Where the value comes from.</param>
public sealed record CompoundOutputEntry(string Target, MappingSource Source);

/// <summary>What a compound workflow returns.</summary>
/// <param name="Entries">Result entries.</param>
/// <param name="OutputProgram">An optional output transformation applied after selection.</param>
public sealed record CompoundOutputSelection(
    IReadOnlyList<CompoundOutputEntry> Entries = null!,
    JsonObject? OutputProgram = null)
{
    /// <summary>The declared entries, never null.</summary>
    public IReadOnlyList<CompoundOutputEntry> Entries { get; init; } = Entries ?? [];
}

/// <summary>
/// Where a mapped value comes from. Exactly one variant is populated.
/// </summary>
public sealed record MappingSource
{
    private MappingSource()
    {
    }

    /// <summary>A JSON Pointer into the tool call's arguments.</summary>
    public string? Argument { get; private init; }

    /// <summary>The step whose response supplies the value.</summary>
    public string? FromStep { get; private init; }

    /// <summary>
    /// A JSON Pointer into the referenced step's response. The permitted roots are the
    /// response scopes <c>/status</c>, <c>/headers</c> and <c>/body</c>.
    /// </summary>
    public string? Response { get; private init; }

    /// <summary>A literal value.</summary>
    public JsonNode? Constant { get; private init; }

    /// <summary>True when the value comes from the tool call's arguments.</summary>
    public bool IsArgument => Argument is not null;

    /// <summary>True when the value comes from an earlier step's response.</summary>
    public bool IsStepOutput => FromStep is not null;

    /// <summary>True when the value is a literal.</summary>
    public bool IsConstant => Constant is not null && !IsArgument && !IsStepOutput;

    /// <summary>Creates an argument source.</summary>
    public static MappingSource FromArgument(string pointer)
        => new() { Argument = Require(pointer, nameof(pointer)) };

    /// <summary>Creates a step-response source.</summary>
    public static MappingSource FromStepResponse(string stepId, string responsePointer)
        => new()
        {
            FromStep = Require(stepId, nameof(stepId)),
            Response = Require(responsePointer, nameof(responsePointer)),
        };

    /// <summary>Creates a literal source.</summary>
    public static MappingSource FromConstant(JsonNode value)
        => new() { Constant = value ?? throw new ArgumentNullException(nameof(value)) };

    private static string Require(string value, string parameterName)
        => string.IsNullOrEmpty(value)
            ? throw new ArgumentException("A mapping source must be non-empty.", parameterName)
            : value;
}

/// <summary>
/// The permitted JSON Pointer roots for compound mappings and transformation programs.
/// </summary>
public static class ManifestPointerRoots
{
    /// <summary>Path template scope.</summary>
    public const string Path = "/path";

    /// <summary>Query-string scope.</summary>
    public const string Query = "/query";

    /// <summary>Request header scope.</summary>
    public const string Headers = "/headers";

    /// <summary>Cookie scope.</summary>
    public const string Cookies = "/cookies";

    /// <summary>Request body scope.</summary>
    public const string Body = "/body";

    /// <summary>Multipart parts scope.</summary>
    public const string Parts = "/parts";

    /// <summary>Response status scope.</summary>
    public const string Status = "/status";

    /// <summary>Roots a request-side pointer may target.</summary>
    public static IReadOnlyList<string> RequestTargets { get; } = [Path, Query, Headers, Cookies, Body, Parts];

    /// <summary>Roots a response-side pointer may read.</summary>
    public static IReadOnlyList<string> ResponseSources { get; } = [Status, Headers, Body];

    /// <summary>Returns true when <paramref name="pointer"/> starts at a request-side root.</summary>
    public static bool IsRequestTarget(string? pointer) => StartsAtRoot(pointer, RequestTargets);

    /// <summary>Returns true when <paramref name="pointer"/> starts at a response-side root.</summary>
    public static bool IsResponseSource(string? pointer) => StartsAtRoot(pointer, ResponseSources);

    private static bool StartsAtRoot(string? pointer, IReadOnlyList<string> roots)
    {
        if (string.IsNullOrEmpty(pointer))
        {
            return false;
        }

        foreach (var root in roots)
        {
            if (!pointer.StartsWith(root, StringComparison.Ordinal))
            {
                continue;
            }

            // "/bodyguard" must not pass as the "/body" root.
            if (pointer.Length == root.Length || pointer[root.Length] == '/')
            {
                return true;
            }
        }

        return false;
    }
}
