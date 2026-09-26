using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution.Projection;

/// <summary>The normalized pagination state.</summary>
internal enum PaginationState
{
    /// <summary>A reviewed continuation was produced.</summary>
    Next,

    /// <summary>The configured source was evaluated and declared no continuation.</summary>
    End,

    /// <summary>Continuation state could not be established safely.</summary>
    Unavailable,
}

/// <summary>A continuation target the addressed surface can actually call.</summary>
/// <param name="Slug">The resolved manifest-local operation slug.</param>
/// <param name="Tool">The name the caller would invoke.</param>
/// <param name="NavigatorOnly">
/// True when the target is reachable only through the Navigator, so the emitted arguments are
/// the Navigator wrapper rather than the target's own input.
/// </param>
/// <param name="PathTemplate">
/// The target operation's declared path template, when it has one. A reviewed
/// <c>urlPathParameter(name)</c> mapping names a path variable, so reproducing it requires the
/// template: taking the last URL segment instead would silently bind whichever value happened to
/// sit at the end rather than the variable the operator reviewed.
/// </param>
public sealed record ContinuationTarget(
    string Slug,
    string Tool,
    bool NavigatorOnly,
    string? PathTemplate = null,
    JsonNode? InputSchema = null);

/// <summary>
/// The serving layer's continuation resolution over one addressed surface.
/// </summary>
/// <remarks>
/// <para>
/// Three questions with three answers, all owned where the surface and its operations are known.
/// <see cref="Resolve"/> decides whether the addressed surface can call a target at all and by
/// which name; <see cref="ValidateArguments"/> measures the mapped runtime values against the
/// target's advertised input schema; <see cref="ValidateUrl"/> decides whether a resolved
/// continuation URL reproduces the target's ordinary compiled request for the mapped arguments.
/// </para>
/// <para>
/// All three are side-effect-free. The URL check compiles and compares and never sends, which is
/// what keeps "a continuation is data, never an alternate execution path" an assertion rather
/// than a promise.
/// </para>
/// </remarks>
public interface IContinuationResolver
{
    /// <summary>
    /// Resolves the declared target slug, or returns null after adding a diagnostic when the
    /// addressed surface cannot call it. An empty slug means the current operation.
    /// </summary>
    ContinuationTarget? Resolve(string slug, ICollection<ExecutionDiagnostic> diagnostics);

    /// <summary>
    /// Checks the mapped arguments against the callable target's advertised input schema, or
    /// returns true when the target declares nothing to check.
    /// </summary>
    /// <remarks>
    /// The static Manifest check proves the target exists, is HTTP-backed and has every required
    /// input mapped. It cannot prove the runtime values satisfy the target's schema, so the same
    /// contract a caller's next invocation is measured against is applied here, before a
    /// continuation is emitted. A schema that cannot be interpreted refuses rather than skips.
    /// </remarks>
    bool ValidateArguments(
        ContinuationTarget target,
        JsonObject arguments,
        ICollection<ExecutionDiagnostic> diagnostics,
        IReadOnlySet<string>? sensitiveHeaderNames = null,
        IReadOnlySet<string>? sensitiveQueryNames = null);

    /// <summary>
    /// Checks a resolved continuation URL against the target's ordinary compiled request, or
    /// returns true when there is nothing to compare.
    /// </summary>
    bool ValidateUrl(
        ContinuationTarget target,
        JsonObject arguments,
        string url,
        ICollection<ExecutionDiagnostic> diagnostics,
        Uri? effectiveUri = null,
        IReadOnlySet<string>? sensitiveQueryNames = null);
}

/// <summary>What projection produced for one response.</summary>
/// <param name="Value">The final agent-facing value, or null when nothing was projected.</param>
/// <param name="Diagnostics">Bounded diagnostics, in the order they were produced.</param>
internal sealed record ResponseProjectionOutcome(JsonNode? Value, IReadOnlyList<ExecutionDiagnostic> Diagnostics);

/// <summary>
/// Builds the agent-facing projection envelope and the normalized pagination object.
/// </summary>
/// <remarks>
/// <para>
/// One evaluation, no network. Every value here comes from the bounded response the execution
/// already captured: status, the complete multi-value header map, the final effective URI and
/// the bounded raw body. Nothing re-reads the exchange, and nothing reaches an upstream, so a
/// refusal costs exactly zero requests — which is what makes "no request was sent" an assertion
/// rather than an inference.
/// </para>
/// <para>
/// Generic metadata and pagination share the response context and the safety policy but stay
/// separate semantics, including their ceilings. A header-aggregate breach drops the
/// header-derived mappings while a status mapping and an independent pagination result survive;
/// a pagination-object breach is a pagination refusal that leaves the generic metadata alone.
/// </para>
/// <para>
/// Absence is not failure. A missing selected header omits its target, a valid source with no
/// continuation is <c>end</c>, and only an ambiguous, unsafe, malformed or unrepresentable
/// source becomes <c>unavailable</c>. None of them turns a valid upstream body into a tool
/// error.
/// </para>
/// </remarks>
internal static class ResponseProjectionEvaluator
{
    /// <summary>Evaluates the declared policy over one bounded response.</summary>
    /// <param name="projection">The reviewed projection of the executed operation.</param>
    /// <param name="statusCode">The observed upstream status.</param>
    /// <param name="headers">The complete ordered multi-value response header map.</param>
    /// <param name="effectiveUri">The final effective response URI after redirects.</param>
    /// <param name="finalBody">
    /// The final body value after any accepted output transformation, written to the envelope's
    /// body target.
    /// </param>
    /// <param name="rawBody">
    /// The bounded raw upstream body, read only by a declared <c>jsonPointer</c> extraction. A
    /// presentation transform may remove a field from the agent body without removing the
    /// continuation the upstream sent.
    /// </param>
    /// <param name="currentArguments">The executed operation's own evaluated arguments.</param>
    /// <param name="sensitiveHeaderNames">
    /// The connector-specific sensitive names, in addition to the unconditional hard-denied set.
    /// </param>
    /// <param name="resolveTarget">
    /// Resolves a continuation target, or null when the caller has no continuation resolution to
    /// offer.
    /// </param>
    internal static ResponseProjectionOutcome Evaluate(
        AgentOutputProjection projection,
        int statusCode,
        IReadOnlyDictionary<string, string[]> headers,
        Uri? effectiveUri,
        JsonNode? finalBody,
        JsonNode? rawBody,
        JsonObject currentArguments,
        IReadOnlySet<string> sensitiveHeaderNames,
        IContinuationResolver? resolveTarget,
        bool? hasFinalBody = null,
        IReadOnlySet<string>? sensitiveQueryNames = null)
    {
        ArgumentNullException.ThrowIfNull(projection);
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(currentArguments);
        ArgumentNullException.ThrowIfNull(sensitiveHeaderNames);

        var diagnostics = new List<ExecutionDiagnostic>();
        var rawHeaderBytes = 0;
        var metadata = BuildMetadata(projection, statusCode, headers, sensitiveHeaderNames, diagnostics, ref rawHeaderBytes);

        JsonObject? pagination = null;

        if (projection.Pagination is { } policy)
        {
            pagination = BuildPagination(
                policy,
                statusCode,
                headers,
                effectiveUri,
                rawBody,
                currentArguments,
                sensitiveHeaderNames,
                resolveTarget,
                diagnostics,
                sensitiveQueryNames ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                ref rawHeaderBytes);
        }

        if (pagination is not null
            && projection.Pagination is { } budgetPolicy
            && SerializedMetadataPlusPaginationBytes(metadata, budgetPolicy.Target, pagination)
                > ResponseProjectionLimits.MaxSerializedMetadataBytes)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.MetadataOversized, budgetPolicy.Target));
            pagination = Unavailable();
        }

        var envelope = new JsonObject();
        if ((hasFinalBody ?? (finalBody is not null))
            && !TryAssign(envelope, projection.BodyTarget, finalBody?.DeepClone()))
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ArgumentUnmappable, projection.BodyTarget));
        }

        if (metadata is { Count: > 0 })
        {
            foreach ((string target, JsonNode? value) in metadata)
            {
                if (!TryAssign(envelope, target, value))
                {
                    diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ArgumentUnmappable, target));
                }
            }
        }

        if (pagination is not null && projection.Pagination is { } paginationPolicy)
        {
            if (!TryAssign(envelope, paginationPolicy.Target, pagination))
            {
                diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ArgumentUnmappable, paginationPolicy.Target));
            }
        }

        return new ResponseProjectionOutcome(envelope, diagnostics);
    }

    /// <summary>
    /// Builds the selected generic metadata members, or drops the header-derived ones when a
    /// budget was breached.
    /// </summary>
    /// <remarks>
    /// A breach drops every header-derived mapping rather than trimming the list, because a
    /// partially projected envelope would make which fields survive depend on mapping order.
    /// A <c>statusCode</c> mapping is not a header and survives both header budgets, which is
    /// what keeps a 429's status visible while an oversized header is withheld.
    /// </remarks>
    private static List<(string Target, JsonNode? Value)> BuildMetadata(
        AgentOutputProjection projection,
        int statusCode,
        IReadOnlyDictionary<string, string[]> headers,
        IReadOnlySet<string> sensitiveHeaderNames,
        List<ExecutionDiagnostic> diagnostics,
        ref int rawHeaderBytes)
    {
        // The origin is tracked rather than inferred from a target, because a drop must remove
        // exactly the header-derived members and nothing else. Inferring it from a target name
        // would make the budget depend on where an operator chose to write a status value.
        var produced = new List<(string Target, JsonNode? Value, bool HeaderDerived)>(projection.Metadata.Count);
        var headersDropped = false;

        foreach (ResponseMetadataMapping mapping in projection.Metadata)
        {
            if (mapping.Source is StatusCodeMetadataSource)
            {
                produced.Add((mapping.Target, JsonValue.Create(statusCode), HeaderDerived: false));
                continue;
            }

            if (headersDropped || mapping.Source is not ResponseHeaderMetadataSource header)
            {
                continue;
            }

            string name = header.Name;

            if (AgentOutputProjectionSafety.IsHardDenied(name)
                || sensitiveHeaderNames.Contains(name.ToLowerInvariant()))
            {
                diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.HeaderSensitive, mapping.Target));
                continue;
            }

            IReadOnlyList<string> values = Lookup(headers, name);

            if (values.Count == 0)
            {
                // A missing optional header omits its target and is not a failure.
                continue;
            }

            if (!TryConsumeHeader(values, mapping.Target, diagnostics, ref rawHeaderBytes, out bool aggregateExceeded))
            {
                if (aggregateExceeded)
                {
                    produced.RemoveAll(static entry => entry.HeaderDerived);
                    headersDropped = true;
                }

                continue;
            }

            produced.Add((
                mapping.Target,
                header.ValueMode == HeaderValueMode.First
                    ? JsonValue.Create(values[0])
                    : new JsonArray([.. values.Select(static value => JsonValue.Create(value))]),
                HeaderDerived: true));
        }

        if (!headersDropped
            && SerializedBytes([.. produced.Select(static entry => (entry.Target, entry.Value))])
                > ResponseProjectionLimits.MaxSerializedMetadataBytes)
        {
            // The serialized budget covers what the envelope actually gains, so a value that is
            // small on the wire but expensive once escaped is bounded here rather than only by
            // the raw byte count.
            ResponseMetadataMapping? first = projection.Metadata
                .FirstOrDefault(static mapping => mapping.Source is ResponseHeaderMetadataSource);

            produced.RemoveAll(static entry => entry.HeaderDerived);
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.HeaderOversized,
                first?.Target));
        }

        return [.. produced.Select(static entry => (entry.Target, entry.Value))];
    }

    /// <summary>
    /// Builds the normalized pagination object, or an <c>unavailable</c> state.
    /// </summary>
    private static JsonObject BuildPagination(
        PaginationPolicy policy,
        int statusCode,
        IReadOnlyDictionary<string, string[]> headers,
        Uri? effectiveUri,
        JsonNode? body,
        JsonObject currentArguments,
        IReadOnlySet<string> sensitiveHeaderNames,
        IContinuationResolver? resolveTarget,
        List<ExecutionDiagnostic> diagnostics,
        IReadOnlySet<string> sensitiveQueryNames,
        ref int rawHeaderBytes)
    {
        if (statusCode is < 200 or >= 300)
        {
            // Error and challenge pages are not navigable collections, and treating their
            // recovery links as continuation instructions is how an agent ends up replaying a
            // challenge into the wrong endpoint.
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.NonSuccessStatus, policy.Target));
            return Unavailable();
        }

        if (IsSensitiveSource(policy.Source, sensitiveHeaderNames))
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ValueSensitive, policy.Target));
            return Unavailable();
        }

        ExtractedValue extracted = Extract(
            policy.Source,
            headers,
            effectiveUri,
            body,
            currentArguments,
            diagnostics,
            policy.Target,
            sensitiveQueryNames,
            ref rawHeaderBytes);

        if (extracted.Kind == ExtractionKind.None)
        {
            // A valid, evaluated source with no continuation is the end of the collection.
            return End();
        }

        if (extracted.Kind == ExtractionKind.Refused)
        {
            // The refusal already reported its reason, and carries no value to leak.
            return Unavailable();
        }

        if (resolveTarget is null)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ArgumentUnmappable, policy.Target));
            return Unavailable();
        }

        if (resolveTarget.Resolve(policy.NextOperation ?? string.Empty, diagnostics) is not { } target)
        {
            return Unavailable();
        }

        var arguments = new JsonObject();

        foreach (PaginationArgumentMapping mapping in policy.NextArguments)
        {
            if (!MapArgument(mapping, extracted, currentArguments, arguments, diagnostics, policy.Target, target))
            {
                return Unavailable();
            }
        }

        if (!resolveTarget.ValidateArguments(
                target,
                arguments,
                diagnostics,
                sensitiveHeaderNames,
                sensitiveQueryNames))
        {
            // The static Manifest check proved the target declares the mapped inputs; this
            // measures the values that were actually produced. Emitting arguments the target
            // itself would reject hands the agent a continuation that fails on arrival.
            return Unavailable();
        }

        if (extracted.Url is { } url
            && !resolveTarget.ValidateUrl(
                target,
                arguments,
                url,
                diagnostics,
                effectiveUri,
                sensitiveQueryNames))
        {
            // A URL that does not reproduce the target's ordinary compiled request would make
            // the emitted arguments a different request than the one the URL names. The check
            // compiles and compares; it never sends.
            return Unavailable();
        }

        var payload = target.NavigatorOnly
            ? new JsonObject
            {
                [NavigatorOperationArgument] = target.Slug,
                [NavigatorArgumentsArgument] = arguments,
            }
            : arguments;

        var next = new JsonObject
        {
            ["operation"] = target.Slug,
            ["tool"] = target.Tool,
            ["arguments"] = payload,
        };
        if (policy.ExposeUrl && extracted.Url is { } exposedUrl)
        {
            next["url"] = exposedUrl;
        }

        var pagination = new JsonObject
        {
            ["state"] = "next",
            ["hasNext"] = true,
            ["next"] = next,
        };

        if (SerializedBytes(pagination) > ResponseProjectionLimits.MaxPaginationObjectBytes)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.MetadataOversized, policy.Target));
            return Unavailable();
        }

        return pagination;
    }

    /// <summary>The Navigator wrapper members a Navigator-only target is invoked with.</summary>
    internal const string NavigatorOperationArgument = "operationKey";

    /// <summary>The Navigator wrapper member carrying the target's own arguments.</summary>
    internal const string NavigatorArgumentsArgument = "arguments";

    private static JsonObject End() => new()
    {
        ["state"] = "end",
        ["hasNext"] = false,
    };

    /// <summary>
    /// The unavailable state, without a <c>hasNext</c> member: claiming <c>false</c> would tell
    /// an agent the collection ended when MCPiler could not establish that at all.
    /// </summary>
    private static JsonObject Unavailable() => new() { ["state"] = "unavailable" };

    /// <summary>Whether the source itself is classified sensitive.</summary>
    private static bool IsSensitiveSource(PaginationSource source, IReadOnlySet<string> sensitiveHeaderNames)
        => source switch
        {
            LinkHeaderPaginationSource link =>
                AgentOutputProjectionSafety.IsHardDenied(link.Header) || sensitiveHeaderNames.Contains(link.Header.ToLowerInvariant()),
            ResponseHeaderPaginationSource header =>
                AgentOutputProjectionSafety.IsHardDenied(header.Name) || sensitiveHeaderNames.Contains(header.Name.ToLowerInvariant()),
            _ => false,
        };

    /// <summary>
    /// Extracts the raw continuation value, or null when the evaluated source declared none.
    /// </summary>
    /// <remarks>
    /// The null-versus-refusal distinction is the whole meaning of <c>end</c> versus
    /// <c>unavailable</c>. A refusal is reported through <paramref name="diagnostics"/>, carries
    /// no value, and never guesses one.
    /// </remarks>
    private static ExtractedValue Extract(
        PaginationSource source,
        IReadOnlyDictionary<string, string[]> headers,
        Uri? effectiveUri,
        JsonNode? body,
        JsonObject currentArguments,
        List<ExecutionDiagnostic> diagnostics,
        string target,
        IReadOnlySet<string> sensitiveQueryNames,
        ref int rawHeaderBytes)
    {
        switch (source)
        {
            case ResponseHeaderPaginationSource header:
            {
                IReadOnlyList<string> values = Lookup(headers, header.Name);

                if (values.Count == 0)
                {
                    return ExtractedValue.Absent;
                }

                if (!TryConsumeHeader(values, target, diagnostics, ref rawHeaderBytes, out _))
                {
                    return ExtractedValue.Refused;
                }

                if (values.Count > 1)
                {
                    diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ArgumentUnmappable, target));
                    return ExtractedValue.Refused;
                }

                return Coerce(values[0], header.ScalarType, diagnostics, target);
            }

            case JsonPointerPaginationSource pointer:
            {
                if (body is null || !TryResolve(body, pointer.Pointer, out JsonNode? node) || node is null)
                {
                    return ExtractedValue.Absent;
                }

                if (pointer.Interpretation == JsonPointerInterpretation.Url)
                {
                    if (node is not JsonValue value || !value.TryGetValue(out string? url) || url is null)
                    {
                        diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.UrlUnrepresentable, target));
                        return ExtractedValue.Refused;
                    }

                    return Url(
                        url,
                        effectiveUri,
                        sensitiveQueryNames,
                        currentArguments,
                        diagnostics,
                        target);
                }

                return ExtractedValue.Of(node.DeepClone(), url: null, currentArguments);
            }

            case LinkHeaderPaginationSource link:
                return ExtractLink(
                    link,
                    headers,
                    effectiveUri,
                    currentArguments,
                    diagnostics,
                    target,
                    sensitiveQueryNames,
                    ref rawHeaderBytes);

            default:
                return ExtractedValue.Refused;
        }
    }

    /// <summary>
    /// Extracts the unique usable relation candidate and resolves it against the final response
    /// URI.
    /// </summary>
    /// <remarks>
    /// A relative target is resolved against the representation's own URL after redirects, which
    /// is the only base RFC 8288 defines. An <c>anchor</c> changes the link context, so a
    /// candidate carrying one that resolves elsewhere is refused rather than reinterpreted: a
    /// relation about a different context is not continuation of this collection.
    /// </remarks>
    private static ExtractedValue ExtractLink(
        LinkHeaderPaginationSource link,
        IReadOnlyDictionary<string, string[]> headers,
        Uri? effectiveUri,
        JsonObject currentArguments,
        List<ExecutionDiagnostic> diagnostics,
        string target,
        IReadOnlySet<string> sensitiveQueryNames,
        ref int rawHeaderBytes)
    {
        IReadOnlyList<string> fieldValues = Lookup(headers, link.Header);

        if (fieldValues.Count == 0)
        {
            return ExtractedValue.Absent;
        }

        if (!TryConsumeLinkField(fieldValues, target, diagnostics))
        {
            return ExtractedValue.Refused;
        }

        LinkParseResult parsed = LinkFieldParser.Parse(fieldValues);

        if (parsed.Outcome == LinkParseOutcome.OverLimit)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.MetadataOversized, target));
            return ExtractedValue.Refused;
        }

        if (parsed.Outcome == LinkParseOutcome.Malformed)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.LinkMalformed, target));
            return ExtractedValue.Refused;
        }

        string relation = RelationName(link.Relation);
        List<ParsedLinkValue> candidates =
            [.. parsed.Values.Where(value => value.Relations.Contains(relation, StringComparer.Ordinal))];

        if (candidates.Count == 0)
        {
            return ExtractedValue.Absent;
        }

        if (candidates.Count > 1)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.LinkAmbiguousNext, target));
            return ExtractedValue.Refused;
        }

        ParsedLinkValue candidate = candidates[0];

        if (candidate.Anchor is { } anchor
            && !ContextMatches(candidate.Target, anchor, effectiveUri))
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.LinkContextMismatch, target));
            return ExtractedValue.Refused;
        }

        return Url(
            candidate.Target,
            effectiveUri,
            sensitiveQueryNames,
            currentArguments,
            diagnostics,
            target);
    }

    private static ExtractedValue Url(
        string url,
        Uri? effectiveUri,
        IReadOnlySet<string> sensitiveQueryNames,
        JsonObject currentArguments,
        List<ExecutionDiagnostic> diagnostics,
        string target)
    {
        Uri? resolved = null;
        if (effectiveUri is not null)
        {
            Uri.TryCreate(effectiveUri, url, out resolved);
        }
        else
        {
            Uri.TryCreate(url, UriKind.Absolute, out resolved);
        }

        if (resolved is null
            || !resolved.IsAbsoluteUri
            || resolved.Scheme is not ("http" or "https"))
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.UrlUnrepresentable, target));
            return ExtractedValue.Refused;
        }

        if (!string.IsNullOrEmpty(resolved.UserInfo))
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.LinkCredentialsRefused, target));
            return ExtractedValue.Refused;
        }

        if (effectiveUri is null || !SameOrigin(resolved, effectiveUri))
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.LinkCrossOrigin, target));
            return ExtractedValue.Refused;
        }

        if (HasSensitiveQuery(resolved, sensitiveQueryNames))
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ValueSensitive, target));
            return ExtractedValue.Refused;
        }

        string normalized = resolved.ToString();
        if (Encoding.UTF8.GetByteCount(normalized) > ResponseProjectionLimits.MaxContinuationUrlBytes)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.MetadataOversized, target));
            return ExtractedValue.Refused;
        }

        return ExtractedValue.Of(JsonValue.Create(normalized), normalized, currentArguments);
    }

    private static bool SameOrigin(Uri left, Uri right)
        => string.Equals(Origin(left), Origin(right), StringComparison.OrdinalIgnoreCase);

    private static string Origin(Uri uri)
        => $"{uri.Scheme.ToLowerInvariant()}://{uri.IdnHost.ToLowerInvariant()}"
            + (uri.IsDefaultPort ? string.Empty : $":{uri.Port}");

    private static bool HasSensitiveQuery(Uri uri, IReadOnlySet<string> sensitiveQueryNames)
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

            if (sensitiveQueryNames.Contains(name))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when a candidate's anchor keeps it in the current response's link context.
    /// </summary>
    private static bool ContextMatches(string target, string anchor, Uri? effectiveUri)
    {
        if (effectiveUri is null)
        {
            return false;
        }

        _ = target;
        return Uri.TryCreate(effectiveUri, anchor, out Uri? anchorUri)
            && SameContext(anchorUri, effectiveUri);
    }

    private static bool SameContext(Uri left, Uri right)
        => SameOrigin(left, right)
            && string.Equals(left.AbsolutePath, right.AbsolutePath, StringComparison.Ordinal)
            && string.Equals(left.Query, right.Query, StringComparison.Ordinal)
            && string.Equals(left.Fragment, right.Fragment, StringComparison.Ordinal);

    /// <summary>Maps one reviewed argument source into the target input object.</summary>
    private static bool MapArgument(
        PaginationArgumentMapping mapping,
        ExtractedValue extracted,
        JsonObject currentArguments,
        JsonObject arguments,
        List<ExecutionDiagnostic> diagnostics,
        string paginationTarget,
        ContinuationTarget target)
    {
        JsonNode? value;
        var urlDerived = false;

        switch (mapping.From)
        {
            case ExtractedPaginationArgument:
                value = extracted.Value;
                break;
            case LiteralPaginationArgument literal:
                value = literal.Value?.DeepClone();
                break;
            case CurrentArgumentPaginationArgument current:
                value = LookupCurrent(currentArguments, current.Pointer);
                break;
            case UrlQueryPaginationArgument query:
                value = QueryComponent(extracted.Url, query.Name);
                urlDerived = true;
                break;
            case UrlPathPaginationArgument path:
                value = PathComponent(extracted.Url, path.Name, target);
                urlDerived = true;
                break;
            default:
                value = null;
                break;
        }

        if (value is null || Convert(value, mapping.As) is not { } converted)
        {
            // A URL-derived mapping that cannot read its component did not fail because an
            // argument was unmappable in the abstract: the supplied URL is not representable by
            // the reviewed target binding, which is the refusal an operator needs to see.
            diagnostics.Add(new ExecutionDiagnostic(
                urlDerived && value is null
                    ? ResponseProjectionCodes.UrlUnrepresentable
                    : ResponseProjectionCodes.ArgumentUnmappable,
                paginationTarget));

            return false;
        }

        if (!TryAssign(arguments, mapping.Target, converted, target.InputSchema, target.InputSchema))
        {
            diagnostics.Add(new ExecutionDiagnostic(
                ResponseProjectionCodes.ArgumentUnmappable,
                paginationTarget));
            return false;
        }

        return true;
    }

    private static JsonNode? LookupCurrent(JsonObject currentArguments, string pointer)
        => TryResolve(currentArguments, pointer, out JsonNode? node) ? node?.DeepClone() : null;

    private static JsonNode? QueryComponent(string? url, string name)
    {
        if (url is null || !Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed))
        {
            return null;
        }

        foreach (string pair in parsed.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = pair.IndexOf('=', StringComparison.Ordinal);

            if (separator <= 0)
            {
                continue;
            }

            if (string.Equals(Uri.UnescapeDataString(pair[..separator]), name, StringComparison.Ordinal))
            {
                return JsonValue.Create(Uri.UnescapeDataString(pair[(separator + 1)..]));
            }
        }

        return null;
    }

    /// <summary>
    /// Reads the URL segment that the target's path template binds <paramref name="name"/> to.
    /// </summary>
    /// <remarks>
    /// The reviewed mapping names a path variable, and the template is what says which segment
    /// carries it. A template segment list and the URL's own segments must line up; a URL whose
    /// shape does not match the template has no trustworthy binding for that variable, so the
    /// mapping refuses rather than picking a segment by position.
    /// </remarks>
    private static JsonNode? PathComponent(string? url, string name, ContinuationTarget target)
    {
        if (url is null
            || target.PathTemplate is null
            || !Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed))
        {
            return null;
        }

        string[] templateSegments = target.PathTemplate.Split('/', StringSplitOptions.RemoveEmptyEntries);
        string[] urlSegments = parsed.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (templateSegments.Length != urlSegments.Length)
        {
            return null;
        }

        for (var index = 0; index < templateSegments.Length; index++)
        {
            string segment = templateSegments[index];

            if (segment.Length < 3
                || segment[0] != '{'
                || segment[^1] != '}'
                || !string.Equals(segment[1..^1], name, StringComparison.Ordinal))
            {
                continue;
            }

            return JsonValue.Create(Uri.UnescapeDataString(urlSegments[index]));
        }

        return null;
    }

    /// <summary>
    /// Applies the closed lossless conversion, or refuses rather than rounding or guessing.
    /// </summary>
    private static JsonNode? Convert(JsonNode value, PaginationConversion conversion)
    {
        if (conversion == PaginationConversion.PreserveJson)
        {
            return value.DeepClone();
        }

        if (value is not JsonValue scalar)
        {
            return null;
        }

        switch (conversion)
        {
            case PaginationConversion.String:
                return scalar.TryGetValue(out string? text)
                    ? JsonValue.Create(text)
                    : JsonNumberConversion.TryGetLexeme(scalar, out var numberText)
                        ? JsonValue.Create(numberText)
                        : null;

            case PaginationConversion.Integer:
                return JsonNumberConversion.TryGetLexeme(scalar, out var integerLexeme)
                    ? JsonNumberConversion.ParseInteger(integerLexeme)
                    : scalar.TryGetValue(out string? integerText)
                        ? JsonNumberConversion.ParseInteger(integerText)
                        : null;

            case PaginationConversion.Number:
                return JsonNumberConversion.TryGetLexeme(scalar, out var numberLexeme)
                    ? JsonNumberConversion.ParseNumber(numberLexeme)
                    : scalar.TryGetValue(out string? numberString)
                        ? JsonNumberConversion.ParseNumber(numberString)
                        : null;

            case PaginationConversion.Boolean:
                return scalar.TryGetValue(out bool boolean) ? JsonValue.Create(boolean)
                    : scalar.TryGetValue(out string? booleanLexeme)
                        && bool.TryParse(booleanLexeme, out bool parsedBoolean)
                            ? JsonValue.Create(parsedBoolean)
                            : null;

            default:
                return null;
        }
    }

    private static ExtractedValue Coerce(
        string value,
        PaginationScalarType scalarType,
        List<ExecutionDiagnostic> diagnostics,
        string target)
    {
        switch (scalarType)
        {
            case PaginationScalarType.String:
                return ExtractedValue.Of(JsonValue.Create(value), url: null, currentArguments: null);

            case PaginationScalarType.Integer when JsonNumberConversion.ParseInteger(value) is { } integer:
                return ExtractedValue.Of(integer, url: null, currentArguments: null);

            case PaginationScalarType.Number when JsonNumberConversion.ParseNumber(value) is { } number:
                return ExtractedValue.Of(number, url: null, currentArguments: null);

            case PaginationScalarType.Boolean when bool.TryParse(value, out bool boolean):
                return ExtractedValue.Of(JsonValue.Create(boolean), url: null, currentArguments: null);

            default:
                diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ArgumentUnmappable, target));
                return ExtractedValue.Refused;
        }
    }

    /// <summary>How one source evaluation ended.</summary>
    private enum ExtractionKind
    {
        /// <summary>The source was valid and declared no continuation.</summary>
        None,

        /// <summary>A continuation value was produced.</summary>
        Value,

        /// <summary>The source was malformed, unsafe or unrepresentable.</summary>
        Refused,
    }

    /// <summary>
    /// The value extracted from one source, with its resolved URL when it is one.
    /// </summary>
    /// <param name="Kind">How the evaluation ended.</param>
    /// <param name="Value">The extracted value, present only for <see cref="ExtractionKind.Value"/>.</param>
    /// <param name="Url">The resolved URL, or null for a value-only source.</param>
    /// <param name="CurrentArguments">The executed operation's own evaluated arguments.</param>
    private sealed record ExtractedValue(
        ExtractionKind Kind,
        JsonNode? Value,
        string? Url,
        JsonObject? CurrentArguments)
    {
        /// <summary>A valid source with no continuation.</summary>
        internal static ExtractedValue Absent { get; } =
            new(ExtractionKind.None, Value: null, Url: null, CurrentArguments: null);

        /// <summary>A marker carrying no value: the refusal path must not echo one.</summary>
        internal static ExtractedValue Refused { get; } =
            new(ExtractionKind.Refused, Value: null, Url: null, CurrentArguments: null);

        /// <summary>A produced value.</summary>
        internal static ExtractedValue Of(JsonNode value, string? url, JsonObject? currentArguments) =>
            new(ExtractionKind.Value, value, url, currentArguments);
    }

    private static bool TryConsumeLinkField(
        IReadOnlyList<string> values,
        string target,
        List<ExecutionDiagnostic> diagnostics)
    {
        foreach (string value in values)
        {
            if (HasInvalidControl(value))
            {
                diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.HeaderInvalidValue, target));
                return false;
            }

            if (Encoding.UTF8.GetByteCount(value) > ResponseProjectionLimits.MaxHeaderValueBytes)
            {
                diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.HeaderOversized, target));
                return false;
            }
        }

        return true;
    }

    private static bool TryConsumeHeader(
        IReadOnlyList<string> values,
        string target,
        List<ExecutionDiagnostic> diagnostics,
        ref int rawHeaderBytes,
        out bool aggregateExceeded)
    {
        aggregateExceeded = false;
        if (values.Count > ResponseProjectionLimits.MaxHeaderValues)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.HeaderOversized, target));
            return false;
        }

        foreach (string value in values)
        {
            if (HasInvalidControl(value))
            {
                diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.HeaderInvalidValue, target));
                return false;
            }

            int bytes = Encoding.UTF8.GetByteCount(value);
            if (bytes > ResponseProjectionLimits.MaxHeaderValueBytes)
            {
                diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.HeaderOversized, target));
                return false;
            }

            if (rawHeaderBytes > ResponseProjectionLimits.MaxRawHeaderBytes - bytes)
            {
                rawHeaderBytes = ResponseProjectionLimits.MaxRawHeaderBytes + 1;
                aggregateExceeded = true;
                diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.HeaderOversized, target));
                return false;
            }

            rawHeaderBytes += bytes;
        }

        return true;
    }

    private static int SerializedMetadataPlusPaginationBytes(
        IReadOnlyList<(string Target, JsonNode? Value)> metadata,
        string paginationTarget,
        JsonNode pagination)
    {
        var holder = new JsonObject();
        foreach ((string target, JsonNode? value) in metadata)
        {
            _ = TryAssign(holder, target, value?.DeepClone());
        }

        _ = TryAssign(holder, paginationTarget, pagination.DeepClone());
        return Encoding.UTF8.GetByteCount(holder.ToJsonString());
    }

    private static bool HasInvalidControl(string value)
        => value.Any(static character => character is '\r' or '\n' or '\0');

    private static IReadOnlyList<string> Lookup(
        IReadOnlyDictionary<string, string[]> headers,
        string name)
    {
        foreach ((string key, string[] values) in headers)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
            {
                return values;
            }
        }

        return [];
    }

    private static string RelationName(PaginationRelation relation) => relation switch
    {
        PaginationRelation.Next => "next",
        PaginationRelation.Prev => "prev",
        PaginationRelation.First => "first",
        PaginationRelation.Last => "last",
        _ => string.Empty,
    };

    /// <summary>
    /// Resolves one reviewed RFC 6901 pointer against a JSON document.
    /// </summary>
    /// <remarks>
    /// A local walker rather than the manifest loader's resolver: this pointer addresses runtime
    /// response data, where the loader's pointer addresses manifest documents and is charged
    /// against the declared schema-depth bounds. Sharing them would apply a document-size budget
    /// to a response body it was never meant to bound. The pointer itself was syntax-validated
    /// when the Manifest loaded, so this walker only has to resolve, not to validate.
    /// </remarks>
    private static bool TryResolve(JsonNode document, string pointer, out JsonNode? target)
    {
        target = document;

        if (pointer.Length == 0)
        {
            return true;
        }

        foreach (string raw in pointer.Split('/').Skip(1))
        {
            string token = JsonPointer.Unescape(raw);

            target = target switch
            {
                JsonObject obj when obj.TryGetPropertyValue(token, out JsonNode? member) && member is not null => member,
                JsonArray array when int.TryParse(token, out int index)
                    && index >= 0 && index < array.Count => array[index],
                _ => null,
            };

            if (target is null)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The serialized size of the metadata this projection adds, excluding the body.</summary>
    private static int SerializedBytes(List<(string Target, JsonNode? Value)> produced)
    {
        var holder = new JsonObject();

        foreach ((string target, JsonNode? value) in produced)
        {
            _ = TryAssign(holder, target, value?.DeepClone());
        }

        return Encoding.UTF8.GetByteCount(holder.ToJsonString());
    }

    private static int SerializedBytes(JsonNode node)
        => Encoding.UTF8.GetByteCount(node.ToJsonString());

    private static bool TryAssign(
        JsonObject root,
        string pointer,
        JsonNode? value,
        JsonNode? inputSchema = null,
        JsonNode? inputSchemaRoot = null)
    {
        inputSchemaRoot ??= inputSchema;
        string[] tokens = [.. pointer.Split('/').Skip(1).Select(JsonPointer.Unescape)];
        if (tokens.Length == 0)
        {
            return false;
        }

        JsonNode current = root;
        JsonNode? currentSchema = inputSchema;
        for (var index = 0; index < tokens.Length - 1; index++)
        {
            string token = tokens[index];
            if (current is JsonObject currentObject)
            {
                if (currentObject.TryGetPropertyValue(token, out var existing) && existing is not null)
                {
                    current = existing;
                    if (!TryGetChildSchema(currentSchema, token, isArrayToken: false, inputSchemaRoot, out currentSchema))
                    {
                        return false;
                    }

                    continue;
                }

                if (!TryGetChildSchema(currentSchema, token, isArrayToken: false, inputSchemaRoot, out var childSchema))
                {
                    return false;
                }

                JsonNode created = IsArraySchema(childSchema, inputSchemaRoot)
                    || childSchema is null && IsArrayIndex(tokens[index + 1])
                        ? new JsonArray()
                        : new JsonObject();
                currentObject[token] = created;
                current = created;
                currentSchema = childSchema;
                continue;
            }

            if (current is JsonArray currentArray
                && TryArrayIndex(token, out var arrayIndex))
            {
                while (currentArray.Count <= arrayIndex)
                {
                    currentArray.Add(null);
                }

                if (currentArray[arrayIndex] is not null and not JsonObject and not JsonArray)
                {
                    return false;
                }

                if (!TryGetChildSchema(currentSchema, token, isArrayToken: true, inputSchemaRoot, out var itemSchema))
                {
                    return false;
                }

                if (currentArray[arrayIndex] is null)
                {
                    currentArray[arrayIndex] = IsArraySchema(itemSchema, inputSchemaRoot)
                        || itemSchema is null && IsArrayIndex(tokens[index + 1])
                            ? (JsonNode)new JsonArray()
                            : new JsonObject();
                }

                current = currentArray[arrayIndex] ?? throw new InvalidOperationException();
                currentSchema = itemSchema;
                continue;
            }

            return false;
        }

        if (current is JsonObject finalObject)
        {
            finalObject[tokens[^1]] = value;
            return true;
        }

        if (current is JsonArray finalArray && TryArrayIndex(tokens[^1], out var finalIndex))
        {
            while (finalArray.Count <= finalIndex)
            {
                finalArray.Add(null);
            }

            finalArray[finalIndex] = value;
            return true;
        }

        return false;
    }

    private static bool TryGetChildSchema(
        JsonNode? schema,
        string token,
        bool isArrayToken,
        JsonNode? schemaRoot,
        out JsonNode? childSchema)
    {
        childSchema = null;
        schema = ResolveLocalReference(schema, schemaRoot);
        if (schema is JsonValue booleanSchema)
        {
            return !booleanSchema.TryGetValue<bool>(out var accepts) || accepts;
        }

        if (schema is not JsonObject schemaObject)
        {
            return true;
        }

        if (isArrayToken)
        {
            if (!TryArrayIndex(token, out var index))
            {
                return false;
            }

            if (schemaObject["prefixItems"] is JsonArray prefixItems && index < prefixItems.Count)
            {
                childSchema = prefixItems[index];
            }
            else if (schemaObject["items"] is JsonValue itemBoolean)
            {
                return !itemBoolean.TryGetValue<bool>(out var acceptsItems) || acceptsItems;
            }
            else if (schemaObject["items"] is { } items)
            {
                childSchema = items;
            }

            return true;
        }

        if (schemaObject["properties"] is JsonObject properties
            && properties.TryGetPropertyValue(token, out var declared))
        {
            childSchema = declared;
            return childSchema is not JsonValue value || !value.TryGetValue<bool>(out var accepts) || accepts;
        }

        if (schemaObject["additionalProperties"] is JsonValue additional)
        {
            return !additional.TryGetValue<bool>(out var allowed) || allowed;
        }

        if (schemaObject["additionalProperties"] is { } additionalSchema)
        {
            childSchema = additionalSchema;
        }

        return true;
    }

    private static JsonNode? ResolveLocalReference(JsonNode? schema, JsonNode? schemaRoot)
    {
        if (schemaRoot is null)
        {
            return schema;
        }

        var resolver = new SchemaReferenceResolver(schemaRoot, SchemaBounds.Default);
        return resolver.TryResolveNode(schema, out var resolved, out _)
            ? resolved
            : schema;
    }

    private static bool IsArraySchema(JsonNode? schema, JsonNode? schemaRoot)
    {
        schema = ResolveLocalReference(schema, schemaRoot);
        if (schema is not JsonObject schemaObject)
        {
            return false;
        }

        if (schemaObject["type"] is JsonValue typeValue
            && typeValue.TryGetValue<string>(out var type))
        {
            return string.Equals(type, "array", StringComparison.Ordinal)
                && !string.Equals(type, "object", StringComparison.Ordinal);
        }

        if (schemaObject["type"] is JsonArray types)
        {
            bool acceptsArray = types.OfType<JsonValue>()
                .Any(value => value.TryGetValue<string>(out var type)
                    && string.Equals(type, "array", StringComparison.Ordinal));
            bool acceptsObject = types.OfType<JsonValue>()
                .Any(value => value.TryGetValue<string>(out var type)
                    && string.Equals(type, "object", StringComparison.Ordinal));
            if (acceptsArray || acceptsObject)
            {
                return acceptsArray && !acceptsObject;
            }
        }

        return schemaObject["items"] is not null || schemaObject["prefixItems"] is JsonArray;
    }

    private static bool IsArrayIndex(string token)
        => TryArrayIndex(token, out _);

    private static bool TryArrayIndex(string token, out int index)
        => int.TryParse(token, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out index)
            && index >= 0
            && index.ToString(System.Globalization.CultureInfo.InvariantCulture) == token;
}
