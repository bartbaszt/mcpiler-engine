using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using Json.Schema;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Files;
using MCPiler.Engine.Mcp.Navigator;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Mcp;

/// <summary>
/// One tool call, from the name a caller sent to what it is told.
/// </summary>
/// <remarks>
/// <para>
/// Every decision a call needs is here: whether the surface advertises the name, whether the
/// arguments satisfy the contract that was advertised for it, which operation runs, and what
/// an outcome means. A transport hands over a name and an argument object and receives a
/// rendered answer, which is what keeps two transports from disagreeing about any of it.
/// </para>
/// <para>
/// Order is the substance. Resolution, then exposure, then validation, then execution, and
/// nothing reaches an upstream that has not passed all three. Validating after compilation
/// would mean an argument the advertised schema forbids could still have been serialized;
/// resolving after validating would mean a name the surface does not advertise could be
/// measured against a schema; and checking exposure after validating would let the shape of a
/// refusal reveal whether an excluded operation exists.
/// </para>
/// <para>
/// A Navigator tool branches after resolution and rejoins before validation. It is the same
/// order with the same steps: the Navigator settles exposure for the operation a caller named
/// instead of the surface listing settling it, and everything after that is shared code. There
/// is one path to an upstream and it starts here.
/// </para>
/// </remarks>
internal static class ToolInvocation
{
    /// <summary>What a successful call with an empty body is rendered as.</summary>
    /// <remarks>
    /// An empty string would leave a caller unable to tell an empty answer from a lost one.
    /// </remarks>
    internal const string NoBody = "(no body)";

    /// <summary>
    /// The answer for a name the addressed surface does not advertise.
    /// </summary>
    /// <remarks>
    /// It repeats the name the caller sent and says nothing else. The caller already knows
    /// what it asked for; a near match, a count, or a hint that a larger catalogue sits
    /// behind the surface would each be a fact about what the surface holds. This is also the
    /// answer a hidden operation gets, so the two cannot be told apart.
    /// </remarks>
    internal static string UnknownTool(string name)
        => string.Create(CultureInfo.InvariantCulture, $"No tool named '{name}' is available here.");

    /// <summary>Resolves, validates, executes and renders one call.</summary>
    internal static Task<ToolOutcome> InvokeAsync(
        ExecutionService executions,
        MountedManifest mount,
        MountedSurface surface,
        string invocationScope,
        string tool,
        JsonObject arguments,
        string? negotiatedProtocolRevision,
        CancellationToken cancellationToken,
        CallerPartition? callerPartition = null)
    {
        if (surface.Find(tool) is not { } advertised)
        {
            return Task.FromResult(new ToolOutcome(UnknownTool(tool), IsError: true));
        }

        // The Navigator trio backs no operation, so there is no exposure entry to consult for
        // it: a surface either advertises the three or it does not, and the listing the caller
        // just read is that decision. Its own arguments are still measured first, so a page
        // size outside the advertised bounds is refused by the contract that published them.
        if (advertised.Operation is null)
        {
            return Validate(advertised, arguments) is { } malformed
                ? Task.FromResult(new ToolOutcome(malformed, IsError: true))
                : NavigatorRuntime.InvokeAsync(
                    executions,
                    mount,
                    surface,
                    invocationScope,
                    tool,
                    arguments,
                    negotiatedProtocolRevision,
                    cancellationToken,
                    callerPartition);
        }

        if (!ExposureGate.Permits(mount, surface, advertised.Operation, InvocationPath.Direct))
        {
            // The advertised listing said yes and the exposure table said no. On a started
            // mount the two agree, because a Manifest whose declared tool set disagrees with
            // the set its exposure produces is refused before anything listens. This arm is
            // therefore unreachable today and is still the authority: the listing is derived,
            // the table is authored, and when they disagree the authored one decides. The
            // Navigator reaches the catalogue by the other path with no listing behind it.
            return Task.FromResult(new ToolOutcome(UnknownTool(tool), IsError: true));
        }

        return RunAsync(
            executions,
            mount,
            surface,
            invocationScope,
            advertised,
            arguments,
            negotiatedProtocolRevision,
            cancellationToken,
            callerPartition);
    }

    /// <summary>
    /// Validates, executes and renders one already-permitted operation.
    /// </summary>
    /// <remarks>
    /// The half of the pipeline both entrances share. Exposure is settled before a caller
    /// arrives here — by the surface listing on the direct path and by the Navigator's own
    /// resolution on the other — so that everything after it is decided once. A second
    /// validation rule or a second shaping rule for the Navigator would be a second contract
    /// for the same operation, and the two would diverge the first time either changed.
    /// </remarks>
    internal static async Task<ToolOutcome> RunAsync(
        ExecutionService executions,
        MountedManifest mount,
        MountedSurface surface,
        string invocationScope,
        CatalogueTool operation,
        JsonObject arguments,
        string? negotiatedProtocolRevision,
        CancellationToken cancellationToken,
        CallerPartition? callerPartition = null)
    {
        ArgumentNullException.ThrowIfNull(executions);
        ArgumentNullException.ThrowIfNull(mount);
        ArgumentNullException.ThrowIfNull(surface);
        ArgumentException.ThrowIfNullOrEmpty(invocationScope);
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(arguments);

        if (operation.Operation is not { } slug)
        {
            throw new ArgumentException("A Navigator tool backs no operation and cannot be run.", nameof(operation));
        }

        if (Validate(operation, arguments) is { } rejected)
        {
            // Before anything is compiled, before a credential is read, before a socket. An
            // argument that cannot satisfy the advertised contract must not cost an upstream
            // request, and "no request was sent" has to be an assertion rather than a hope.
            return new ToolOutcome(rejected, IsError: true);
        }

        var result = await executions
            .ExecuteAsync(
                new ExecutionRequest(mount.Document, slug, arguments, mount.Policy)
                {
                    // The exact resource context that admitted this invocation. On HTTP the
                    // host supplies the canonical protected-resource identity, so the bare
                    // default route and the slug-qualified route do not share capabilities.
                    Scope = invocationScope,

                    // Continuation resolution is bound to the surface that admitted this call,
                    // because "can the caller reach this target next" is a fact about that
                    // surface and not about the Manifest as a whole.
                    Continuations = new SurfaceContinuationResolver(mount.Document, mount, surface, slug),

                    // The caller identity the host proved for this request, if any. Carried
                    // through unchanged: the execution layer decides what it means, and a
                    // component on this path that substituted a value would silently merge
                    // callers the host kept apart.
                    CallerPartition = callerPartition,
                },
                cancellationToken)
            .ConfigureAwait(false);

        return Shape(result, mount, surface, operation, negotiatedProtocolRevision);
    }

    /// <summary>
    /// Renders an execution outcome as what a caller is told.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A classified failure is a tool error. An unsuccessful upstream status is not: an
    /// upstream that answers 404 answered, and reporting that as a tool error would tell a
    /// caller its request was malformed when the request was fine and the resource was not
    /// there. The status and the body are the result.
    /// </para>
    /// <para>
    /// The unexplained arm is a floor rather than an expected answer. Every failure this
    /// library produces carries a reason, so the arm exists to keep the mapping total over the
    /// closed classification instead of depending on an invariant held elsewhere.
    /// </para>
    /// </remarks>
    internal static ToolOutcome Shape(EngineExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (!result.Succeeded)
        {
            // A structured description wins where there is one. A workflow's failure has parts
            // a caller has to react to — which step, how far it got — and a sentence carrying
            // them would be a contract written as prose, which is a contract nobody can rely on
            // and everybody breaks by rewording.
            ToolOutcome failed = result.FailureDetail is { } detail
                ? new ToolOutcome(detail.ToJsonString(), IsError: true)
                : new ToolOutcome(result.FailureReason ?? Unexplained(result.Failure), IsError: true);

            return failed with { ErrorCode = result.Failure.ToString() };
        }

        if (result.ResponseFile is { } stored)
        {
            return HandleCodec.IsWireForm(result.ResponseFileHandle)
                ? new ToolOutcome(StoredResponse(stored, result.ResponseFileHandle!), IsError: false)
                : new ToolOutcome("The stored binary response has no transferable file capability.", IsError: true);
        }

        return new ToolOutcome(
            result.ResponseBody is null ? NoBody : Encoding.UTF8.GetString(result.ResponseBody),
            IsError: false);
    }

    /// <summary>
    /// Adds structured content only when this session was advertised a schema and the payload
    /// satisfies that exact schema.
    /// </summary>
    private static ToolOutcome Shape(
        EngineExecutionResult result,
        MountedManifest mount,
        MountedSurface surface,
        CatalogueTool operation,
        string? negotiatedProtocolRevision)
    {
        ToolOutcome plain = Shape(result);

        // A projection finding is an operational fact about a served call, so it is reported
        // whether or not this session was promised structured content. Reporting it only on the
        // structured path would hide every refusal from an operator on a text-only session.
        if (result.Diagnostics.Count > 0)
        {
            plain = plain with
            {
                Diagnostic = ProjectionDiagnostic(result, mount, surface, operation.Operation!),
            };
        }

        if (plain.IsError
            || result.ResponseBody is null
            || result.ResponseFile is not null
            || operation.ResolveOutputSchemaJson(negotiatedProtocolRevision) is not { } advertisedSchema
            || !AdvertisementResolver.ProtocolDefinesStructuredContent(negotiatedProtocolRevision))
        {
            return plain;
        }

        JsonDocument payload;

        try
        {
            payload = JsonDocument.Parse(result.ResponseBody);
        }
        catch (JsonException)
        {
            // There is no structured JSON value to advertise. The text carrier remains intact.
            return plain;
        }

        using (payload)
        {
            JsonElement structured = OutputSchemaEnvelope.Mirror(
                payload.RootElement,
                operation.OutputSchemaWrapped);
            string? schemaLocation = StructuredContentValidator.Validate(structured, advertisedSchema);

            if (schemaLocation is null)
            {
                return plain with { StructuredContentJson = structured.GetRawText() };
            }

            return plain with
            {
                Diagnostic = new RuntimeDiagnostic(
                    StructuredContentValidator.DiagnosticCode,
                    StructuredContentValidator.DiagnosticMessage,
                    mount.Path,
                    surface.Slug,
                    operation.Operation!,
                    schemaLocation),
            };
        }
    }

    /// <summary>
    /// Turns one execution's bounded metadata findings into operator diagnostics.
    /// </summary>
    /// <remarks>
    /// Attribution belongs here: the execution knows what it refused and why, and the mount and
    /// surface are facts the invocation owns. Only the first finding is reported, because a
    /// diagnostic sink is an operational channel rather than a report of everything withheld,
    /// and every finding's code is already stable.
    /// </remarks>
    private static RuntimeDiagnostic? ProjectionDiagnostic(
        EngineExecutionResult result,
        MountedManifest mount,
        MountedSurface surface,
        string slug)
        => result.Diagnostics.Count > 0
            ? new RuntimeDiagnostic(
                result.Diagnostics[0].Code,
                "Response projection or pagination withheld a declared value; see the code for the reason.",
                mount.Path,
                surface.Slug,
                slug,
                result.Diagnostics[0].Pointer ?? string.Empty)
            : null;

    /// <summary>
    /// Measures the arguments against the schema that was advertised for this tool.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Against the advertised bytes, not against a schema derived a second time. A caller that
    /// validates locally and a caller that does not therefore get the same answer, and the
    /// contract a listing published is the contract a call is held to.
    /// </para>
    /// <para>
    /// Fail-closed. A schema that cannot be interpreted refuses the call rather than skipping
    /// the check: the hardest contract to satisfy would otherwise be the one nothing measures.
    /// </para>
    /// <para>
    /// The refusal names a location and nothing else. Echoing the offending value would put a
    /// caller's argument, which may be credential material, into a message.
    /// </para>
    /// </remarks>
    internal static string? Validate(CatalogueTool tool, JsonObject arguments)
    {
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(arguments);

        JsonSchema schema;

        try
        {
            schema = JsonSchema.FromText(tool.InputSchemaJson, AdvertisedDialect);
        }
        catch (Exception failure) when (failure is JsonException or JsonSchemaException or NotSupportedException)
        {
            return UninterpretableSchema;
        }

        // Parsed from the argument object's own bytes rather than handed through a serializer,
        // so what is measured is what a caller sent and not what a writer chose to emit.
        using var instance = JsonDocument.Parse(arguments.ToJsonString());

        EvaluationResults evaluation;

        try
        {
            evaluation = schema.Evaluate(
                instance.RootElement,
                new EvaluationOptions { OutputFormat = OutputFormat.Hierarchical });
        }
        catch (Exception failure) when (failure is JsonSchemaException or NotSupportedException)
        {
            return UninterpretableSchema;
        }

        return evaluation.IsValid ? null : Rejected(Location(evaluation));
    }

    /// <summary>
    /// The dialect an advertised schema is interpreted under.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Stated rather than defaulted, and the difference is not cosmetic. The evaluator's own
    /// default is a later draft that refuses a keyword it does not recognise, and a manifest
    /// schema legitimately carries keywords this dialect treats as annotations: the file-slot
    /// marker, and the format's documented <c>nullable</c> deviation. Evaluated under the
    /// default, every operation carrying either would have been refused as uninterpretable.
    /// </para>
    /// <para>
    /// 2020-12 because that is the dialect a tool input schema is written in and the one the
    /// producing side advertises. A schema declaring its own <c>$schema</c> still wins, which
    /// is what makes this a default rather than an override.
    /// </para>
    /// </remarks>
    private static readonly BuildOptions AdvertisedDialect = new() { Dialect = Dialect.Draft202012 };

    /// <summary>
    /// The instance location of the most specific failure.
    /// </summary>
    /// <remarks>
    /// The deepest failing node, not the first. An applicator reports that "some properties
    /// did not match" at the root, and a caller told only that has been told nothing it did
    /// not already know.
    /// </remarks>
    private static string? Location(EvaluationResults evaluation)
    {
        var specific = (evaluation.Details ?? [])
            .Where(static detail => !detail.IsValid)
            .OrderBy(static detail => detail.InstanceLocation.ToString(), StringComparer.Ordinal)
            .ThenBy(static detail => detail.EvaluationPath.ToString(), StringComparer.Ordinal)
            .Select(Location)
            .FirstOrDefault(static location => location is not null);

        if (specific is not null)
        {
            return specific;
        }

        var location = evaluation.InstanceLocation.ToString();

        return string.IsNullOrEmpty(location) ? null : location;
    }

    private static string Rejected(string? location)
        => location is null
            ? "The arguments do not satisfy the tool's advertised input schema."
            : string.Create(
                CultureInfo.InvariantCulture,
                $"The arguments do not satisfy the tool's advertised input schema at '{location}'.");

    private const string UninterpretableSchema =
        "The tool's advertised input schema could not be interpreted, so the call was refused "
        + "before any request was made.";

    private static string Unexplained(ExecutionFailureKind failure)
        => string.Create(
            CultureInfo.InvariantCulture,
            $"The call failed ({failure}) and the failure carried no explanation.");

    /// <summary>
    /// The text a stored binary response is handed to the caller as, with the handle in its
    /// wire form.
    /// </summary>
    /// <remarks>
    /// This is the issuance side: the handle is the capability the caller is being given, so the
    /// wire form — unrelated to the storage location by construction — is what travels.
    /// </remarks>
    private static string StoredResponse(FileHandleReference stored, string wireHandle)
        => string.Create(
            CultureInfo.InvariantCulture,
            $"Binary response stored as a file reference (handle '{wireHandle}', media type "
            + $"{stored.MediaType}, {stored.Length} bytes). The handle expires automatically.");
}
