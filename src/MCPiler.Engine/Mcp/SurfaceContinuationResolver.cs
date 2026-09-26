using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Projection;
using MCPiler.Engine.Manifest.Derivation;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Transform;

namespace MCPiler.Engine.Mcp;

/// <summary>
/// Resolves a projected continuation against the surface that admitted the call.
/// </summary>
/// <remarks>
/// <para>
/// Reachability and callable names come from the same derived sets the surface advertises and
/// the Navigator resolves against, so a continuation names a target exactly as a caller could:
/// a Direct tool by its allocated name, or a Navigator-only operation by the advertised
/// <c>catalogue.invoke</c> wrapper. Nothing is guessed from the slug.
/// </para>
/// <para>
/// A target the surface cannot call — absent, hidden, excluded, navigator-disabled on a surface
/// whose Navigator is off, or not HTTP-backed — is refused here rather than emitted and refused
/// later, because a continuation an agent cannot follow is worse than no continuation: it turns
/// a recoverable page into a dead end at the model's next call.
/// </para>
/// <para>
/// URL representability is checked by compiling the target's ordinary request for the mapped
/// arguments and comparing the path and query to the resolved URL. The check compiles and
/// compares and never sends, and it never substitutes the response URL for the binding: the URL
/// is data whose only role is to be verified against the request the reviewed binding would
/// build.
/// </para>
/// </remarks>
internal sealed class SurfaceContinuationResolver : IContinuationResolver
{
    private readonly ManifestDocument _manifest;
    private readonly MountedManifest _mount;
    private readonly MountedSurface _surface;
    private readonly PolicySection _policy;
    private readonly SchemaReferenceResolver? _schemaResolver;
    private readonly string _sourceSlug;

    internal SurfaceContinuationResolver(
        ManifestDocument manifest,
        MountedManifest mount,
        MountedSurface surface,
        string sourceSlug)
    {
        _manifest = manifest;
        _mount = mount;
        _surface = surface;

        // The policy that governs this mount after narrowing, not the policy as authored. A
        // continuation is a promise about arguments a later call will compile and run, so it
        // must be measured with the same effective policy that call will execute under. Using
        // the authored document policy could accept an input program the real invocation then
        // refuses, and a promised continuation that always fails is a broken promise.
        _policy = mount.Policy;
        _schemaResolver = manifest.AgentSurfaceDocument is { } document
            ? new SchemaReferenceResolver(document, _policy.EffectiveSchemaBounds)
            : null;
        _sourceSlug = sourceSlug;
    }

    /// <inheritdoc />
    public ContinuationTarget? Resolve(string slug, ICollection<ExecutionDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);

        string targetSlug = string.IsNullOrEmpty(slug) ? _sourceSlug : slug;

        if (_manifest.AgentSurface.Operation(targetSlug) is not { } entry)
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.ArgumentUnmappable, targetSlug));

            return null;
        }

        if (ManifestBindingDispatcher.TryResolveCompound(entry.Binding) is not null
            || ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding) is null)
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.ArgumentUnmappable, targetSlug));

            return null;
        }

        // The target's own template travels with the resolution because a reviewed
        // `urlPathParameter(name)` mapping names a path variable, and only the template says
        // which URL segment carries it.
        string? pathTemplate = ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding) is { } key
            && _manifest.Operations.Operation(key) is { } operation
                ? operation.Path
                : null;

        // The surface's own exposure table decides, through the same gate an invocation passes:
        // Direct answers on both paths, Navigator answers only where the trio is advertised.
        if (ExposureGate.Permits(_mount, _surface, targetSlug, InvocationPath.Direct)
            && _surface.Tools.FirstOrDefault(tool =>
                string.Equals(tool.Operation, targetSlug, StringComparison.Ordinal)) is { } direct)
        {
            return new ContinuationTarget(
                targetSlug,
                direct.Name,
                NavigatorOnly: false,
                pathTemplate,
                RuntimeSchema(entry.InputSchema));
        }

        if (_mount.Document.Server.Surface(_surface.Slug) is { } declared
            && declared.EffectiveNavigator.Enabled
            && ExposureGate.Permits(_mount, _surface, targetSlug, InvocationPath.Navigator))
        {
            return new ContinuationTarget(
                targetSlug,
                ManifestTool.NavigatorInvoke,
                NavigatorOnly: true,
                pathTemplate,
                RuntimeSchema(entry.InputSchema));
        }

        diagnostics.Add(new ExecutionDiagnostic(
            ResponseProjectionCodes.ArgumentUnmappable, targetSlug));

        return null;
    }

    private JsonNode? RuntimeSchema(ManifestSchema? schema)
    {
        if (schema is null)
        {
            return null;
        }

        return (_schemaResolver is null
            ? schema
            : _schemaResolver.SelfContain(schema)).Node.DeepClone();
    }

    /// <inheritdoc />
    public bool ValidateArguments(
        ContinuationTarget target,
        JsonObject arguments,
        ICollection<ExecutionDiagnostic> diagnostics,
        IReadOnlySet<string>? sensitiveHeaderNames = null,
        IReadOnlySet<string>? sensitiveQueryNames = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(diagnostics);

        if (_manifest.AgentSurface.Operation(target.Slug) is not { } entry
            || ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding) is not { } operationKey
            || _manifest.Operations.Operation(operationKey) is not { } operation)
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.ArgumentUnmappable, target.Slug));
            return false;
        }

        if (!TransformStage.TryInput(
                _manifest,
                _policy,
                entry,
                operation,
                arguments,
                out JsonObject effectiveArguments,
                out _))
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.ArgumentUnmappable, target.Slug));
            return false;
        }

        var effective = SensitiveHeaderNames.ForBinding(_manifest, entry.Binding);
        var headers = effective.Headers.ToHashSet(StringComparer.Ordinal);
        var queries = effective.Queries.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (sensitiveHeaderNames is not null)
        {
            headers.UnionWith(sensitiveHeaderNames);
        }

        if (sensitiveQueryNames is not null)
        {
            queries.UnionWith(sensitiveQueryNames);
        }

        if (operation.Parameters.Any(parameter =>
            effectiveArguments.ContainsKey(parameter.Name)
            && SensitiveHeaderNames.IsSensitiveParameter(parameter, headers, queries)))
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.ValueSensitive, target.Slug));
            return false;
        }

        if (Advertised(target) is not { } tool)
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.ArgumentUnmappable, target.Slug));

            return false;
        }

        // The same validator a caller's own call passes, against the same advertised schema. A
        // continuation is an invocation this surface claims the agent can make, so it is held to
        // the contract that invocation would be held to — including the fail-closed behaviour for
        // a schema that cannot be interpreted.
        if (ToolInvocation.Validate(tool, arguments) is null)
        {
            return true;
        }

        diagnostics.Add(new ExecutionDiagnostic(
            ResponseProjectionCodes.ArgumentUnmappable, target.Slug));

        return false;
    }

    /// <summary>The advertised tool the resolved target names, or null when it is not reachable.</summary>
    /// <remarks>
    /// Looked up through the same two derived sets <see cref="Resolve"/> used, so the schema
    /// measured here is the schema that resolution advertised. Asking the Manifest for an
    /// authored schema instead would measure a contract no listing published.
    /// </remarks>
    private CatalogueTool? Advertised(ContinuationTarget target)
        => target.NavigatorOnly
            ? _surface.FindNavigable(target.Slug)
            : _surface.Find(target.Tool);

    /// <inheritdoc />
    public bool ValidateUrl(
        ContinuationTarget target,
        JsonObject arguments,
        string url,
        ICollection<ExecutionDiagnostic> diagnostics,
        Uri? effectiveUri = null,
        IReadOnlySet<string>? sensitiveQueryNames = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(diagnostics);

        if (_manifest.AgentSurface.Operation(target.Slug) is not { } entry
            || ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding) is not { } operationKey
            || _manifest.Operations.Operation(operationKey) is not { } operation)
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.UrlUnrepresentable, target.Slug));
            return false;
        }

        if (!TransformStage.TryInput(
                _manifest,
                _policy,
                entry,
                operation,
                arguments,
                out JsonObject input,
                out _))
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.UrlUnrepresentable, target.Slug));
            return false;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed)
            || !parsed.IsAbsoluteUri
            || parsed.Scheme is not ("http" or "https"))
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.UrlUnrepresentable, target.Slug));
            return false;
        }

        if (!string.IsNullOrEmpty(parsed.UserInfo))
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.LinkCredentialsRefused, target.Slug));
            return false;
        }

        if (effectiveUri is not null && !SameOrigin(parsed, effectiveUri))
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.LinkCrossOrigin, target.Slug));
            return false;
        }

        if (HasSensitiveQuery(parsed, sensitiveQueryNames ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase)))
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.ValueSensitive, target.Slug));
            return false;
        }

        var baseUrl = _manifest.Policy.BaseUrl;

        if (ManifestBindingDispatcher.TryResolveServerUrl(entry.Binding) is { } serverUrl
            && Uri.TryCreate(serverUrl, UriKind.Absolute, out Uri? declaredServer))
        {
            baseUrl = declaredServer;
        }

        CompiledRequest compiled;

        try
        {
            compiled = RequestCompiler.Compile(operation, baseUrl, input);
        }
        catch (Exception failure) when (failure is ArgumentValidationException
            or InvalidBaseUrlException
            or UnsupportedSerializationException
            or UnsupportedBodyMediaTypeException)
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.UrlUnrepresentable, target.Slug));

            return false;
        }

        // Path and query only. The reviewed arguments are bound into the target's own declared
        // parameters, so a continuation URL that changed anything else — a different path
        // template instance, an unmapped query parameter, a different origin — no longer
        // describes the request the binding would build.
        if (SameOrigin(parsed, compiled.Uri)
            && string.Equals(parsed.AbsolutePath, compiled.Uri.AbsolutePath, StringComparison.Ordinal)
            && string.Equals(parsed.Query, compiled.Uri.Query, StringComparison.Ordinal))
        {
            return true;
        }

        diagnostics.Add(new ExecutionDiagnostic(
            ResponseProjectionCodes.UrlUnrepresentable, target.Slug));

        return false;
    }

    private static bool SameOrigin(Uri left, Uri right)
        => string.Equals(Origin(left), Origin(right), StringComparison.OrdinalIgnoreCase);

    private static string Origin(Uri uri)
        => $"{uri.Scheme.ToLowerInvariant()}://{uri.IdnHost.ToLowerInvariant()}"
            + (uri.IsDefaultPort ? string.Empty : $":{uri.Port}");

    private static bool HasSensitiveQuery(Uri uri, IReadOnlySet<string> names)
    {
        foreach (string pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = pair.IndexOf('=', StringComparison.Ordinal);
            string rawName = separator < 0 ? pair : pair[..separator];
            string name;
            try
            {
                name = Uri.UnescapeDataString(rawName);
            }
            catch (UriFormatException)
            {
                return true;
            }

            if (names.Contains(name))
            {
                return true;
            }
        }

        return false;
    }
}
