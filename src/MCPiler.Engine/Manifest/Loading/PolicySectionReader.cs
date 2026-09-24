using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads the <c>policy</c> section: the outbound perimeter and every evaluation bound.
/// </summary>
/// <remarks>
/// Every numeric member is optional and falls back to the compiled Platform default, so the
/// whole object is omittable except <c>baseUrl</c>. A malformed origin rejects the section
/// rather than being skipped: silently dropping one entry of an allow-list would leave the
/// operator believing a perimeter they do not have.
/// </remarks>
internal static class PolicySectionReader
{
    internal static readonly string[] SectionMembers =
    [
        "formatVersion",
        "baseUrl",
        "allowedOrigins",
        "limits",
        "transformCeiling",
        "jmesPathCeiling",
        "compound",
        "schemaBounds",
        "files",
    ];

    internal static readonly string[] LimitMembers =
    [
        "upstreamConnectTimeoutSeconds",
        "upstreamRequestTimeoutSeconds",
        "upstreamResponseSizeLimitBytes",
        "redirectHopLimit",
        "concurrency",
        "mcpRequestSizeLimitBytes",
    ];

    internal static readonly string[] CeilingMembers =
        ["maxSteps", "maxDepth", "maxNodes", "maxOutputBytes", "maxArrayFanout"];

    internal static readonly string[] JmesPathCeilingMembers =
    [
        "maxExpressionBytes",
        "maxInputNodes",
        "maxInputDepth",
        "maxResultNodes",
        "maxResultDepth",
        "maxOutputBytes",
        "maxEvaluationMilliseconds",
    ];

    internal static readonly string[] CompoundMembers =
        ["maxTotalResponseBytes", "workflowTimeoutSeconds"];

    internal static readonly string[] SchemaBoundMembers =
        ["maxDepth", "maxNodes", "maxPropertiesPerLevel"];

    internal static readonly string[] FileMembers =
        ["handleLifetimeSeconds", "uploadSizeLimitBytes", "rejectMagicMismatch"];

    internal static PolicySection? Read(JsonNode? document, SectionReadContext context)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, SectionMembers, string.Empty);
        context.VerifySectionFormatVersion(root, PolicySection.FormatVersion);

        var baseUrl = ReadBaseUrl(root, context);
        var origins = ReadAllowedOrigins(root, context);
        var limits = ReadLimits(root, context);
        var ceiling = ReadCeiling(root, context);
        var jmesPathCeiling = ReadJmesPathCeiling(root, context);
        var compound = ReadCompound(root, context);
        var schemaBounds = ReadSchemaBounds(root, context);
        var files = ReadFiles(root, context);

        if (baseUrl is null)
        {
            return null;
        }

        return new PolicySection(
            baseUrl,
            origins,
            limits,
            ceiling,
            jmesPathCeiling,
            compound,
            schemaBounds,
            files);
    }

    private static Uri? ReadBaseUrl(JsonObject root, SectionReadContext context)
    {
        if (root["baseUrl"] is null)
        {
            context.Error(
                ManifestDiagnosticCodes.BaseUrlInvalid,
                "'baseUrl' is required. Engine has no upstream address to execute against without it.",
                "/baseUrl");
            return null;
        }

        var text = context.Text(root, "baseUrl", string.Empty);

        if (text is null)
        {
            return null;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            context.Error(
                ManifestDiagnosticCodes.BaseUrlInvalid,
                $"'baseUrl' must be an absolute http or https URL, but '{DiagnosticText.Echo(text)}' was declared.",
                "/baseUrl");
            return null;
        }

        return uri;
    }

    private static IReadOnlyList<string> ReadAllowedOrigins(JsonObject root, SectionReadContext context)
    {
        if (root["allowedOrigins"] is null)
        {
            return [];
        }

        var declared = context.TextArray(root, "allowedOrigins", string.Empty);
        var origins = new List<string>(declared.Count);

        for (var index = 0; index < declared.Count; index++)
        {
            var entry = declared[index];
            var pointer = "/allowedOrigins/" + index.ToString(System.Globalization.CultureInfo.InvariantCulture);

            if (!Uri.TryCreate(entry, UriKind.Absolute, out var uri)
                || (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                    && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
            {
                context.Error(
                    ManifestDiagnosticCodes.OriginInvalid,
                    $"'{DiagnosticText.Echo(entry)}' is not an absolute http or https origin.",
                    pointer);
                continue;
            }

            // An origin is scheme, host and port and nothing else. Accepting a path here would
            // read as a narrower permission than the comparison actually applies.
            if (uri.AbsolutePath is not "/" || uri.Query.Length > 0 || uri.Fragment.Length > 0)
            {
                context.Error(
                    ManifestDiagnosticCodes.OriginInvalid,
                    $"'{DiagnosticText.Echo(entry)}' carries a path, query or fragment. An origin is scheme, host and port only.",
                    pointer);
                continue;
            }

            origins.Add(PolicySection.OriginOf(uri));
        }

        return origins;
    }

    private static ExecutionLimits? ReadLimits(JsonObject root, SectionReadContext context)
    {
        var limits = context.Object(root, "limits", string.Empty);

        if (limits is null)
        {
            return null;
        }

        const string pointer = "/limits";
        var defaults = ExecutionLimits.Default;

        context.RejectUnknownMembers(limits, LimitMembers, pointer);

        var redirectHops = context.Integer(limits, "redirectHopLimit", pointer);

        if (redirectHops is { } hops && !context.RequireAtLeast(hops, 0, "redirectHopLimit", pointer))
        {
            redirectHops = null;
        }

        var concurrency = context.Integer(limits, "concurrency", pointer);

        if (concurrency is { } lanes && !context.RequireAtLeast(lanes, 1, "concurrency", pointer))
        {
            concurrency = null;
        }

        return new ExecutionLimits(
            context.Seconds(limits, "upstreamConnectTimeoutSeconds", pointer) ?? defaults.UpstreamConnectTimeout,
            context.Seconds(limits, "upstreamRequestTimeoutSeconds", pointer) ?? defaults.UpstreamRequestTimeout,
            PositiveBytes(limits, "upstreamResponseSizeLimitBytes", pointer, defaults.UpstreamResponseSizeLimitBytes, context),
            redirectHops ?? defaults.RedirectHopLimit,
            concurrency ?? defaults.Concurrency,
            PositiveBytes(limits, "mcpRequestSizeLimitBytes", pointer, defaults.McpRequestSizeLimitBytes, context));
    }

    private static TransformCeiling? ReadCeiling(JsonObject root, SectionReadContext context)
    {
        var ceiling = context.Object(root, "transformCeiling", string.Empty);

        if (ceiling is null)
        {
            return null;
        }

        const string pointer = "/transformCeiling";
        var defaults = TransformCeiling.Default;

        context.RejectUnknownMembers(ceiling, CeilingMembers, pointer);

        return new TransformCeiling(
            PositiveCount(ceiling, "maxSteps", pointer, defaults.MaxSteps, context),
            PositiveCount(ceiling, "maxDepth", pointer, defaults.MaxDepth, context),
            PositiveCount(ceiling, "maxNodes", pointer, defaults.MaxNodes, context),
            PositiveBytes(ceiling, "maxOutputBytes", pointer, defaults.MaxOutputBytes, context),
            PositiveCount(ceiling, "maxArrayFanout", pointer, defaults.MaxArrayFanout, context));
    }

    private static JmesPathCeiling? ReadJmesPathCeiling(JsonObject root, SectionReadContext context)
    {
        var ceiling = context.Object(root, "jmesPathCeiling", string.Empty);

        if (ceiling is null)
        {
            return null;
        }

        const string pointer = "/jmesPathCeiling";
        var defaults = JmesPathCeiling.Default;

        context.RejectUnknownMembers(ceiling, JmesPathCeilingMembers, pointer);

        return new JmesPathCeiling(
            PositiveCount(ceiling, "maxExpressionBytes", pointer, defaults.MaxExpressionBytes, context),
            PositiveBytes(ceiling, "maxInputNodes", pointer, defaults.MaxInputNodes, context),
            PositiveCount(ceiling, "maxInputDepth", pointer, defaults.MaxInputDepth, context),
            PositiveBytes(ceiling, "maxResultNodes", pointer, defaults.MaxResultNodes, context),
            PositiveCount(ceiling, "maxResultDepth", pointer, defaults.MaxResultDepth, context),
            PositiveBytes(ceiling, "maxOutputBytes", pointer, defaults.MaxOutputBytes, context),
            PositiveCount(ceiling, "maxEvaluationMilliseconds", pointer, defaults.MaxEvaluationMilliseconds, context));
    }

    private static CompoundBounds? ReadCompound(JsonObject root, SectionReadContext context)
    {
        var compound = context.Object(root, "compound", string.Empty);

        if (compound is null)
        {
            return null;
        }

        const string pointer = "/compound";
        var defaults = CompoundBounds.Default;

        context.RejectUnknownMembers(compound, CompoundMembers, pointer);

        return new CompoundBounds(
            PositiveBytes(compound, "maxTotalResponseBytes", pointer, defaults.MaxTotalResponseBytes, context),
            context.Seconds(compound, "workflowTimeoutSeconds", pointer) ?? defaults.WorkflowTimeout);
    }

    private static SchemaBounds? ReadSchemaBounds(JsonObject root, SectionReadContext context)
    {
        var bounds = context.Object(root, "schemaBounds", string.Empty);

        if (bounds is null)
        {
            return null;
        }

        const string pointer = "/schemaBounds";
        var defaults = SchemaBounds.Default;

        context.RejectUnknownMembers(bounds, SchemaBoundMembers, pointer);

        return new SchemaBounds(
            PositiveCount(bounds, "maxDepth", pointer, defaults.MaxDepth, context),
            PositiveCount(bounds, "maxNodes", pointer, defaults.MaxNodes, context),
            PositiveCount(bounds, "maxPropertiesPerLevel", pointer, defaults.MaxPropertiesPerLevel, context));
    }

    private static FilePolicy? ReadFiles(JsonObject root, SectionReadContext context)
    {
        var files = context.Object(root, "files", string.Empty);

        if (files is null)
        {
            return null;
        }

        const string pointer = "/files";
        var defaults = FilePolicy.Default;

        context.RejectUnknownMembers(files, FileMembers, pointer);

        return new FilePolicy(
            context.Seconds(files, "handleLifetimeSeconds", pointer) ?? defaults.HandleLifetime,
            PositiveBytes(files, "uploadSizeLimitBytes", pointer, defaults.UploadSizeLimitBytes, context),
            context.Flag(files, "rejectMagicMismatch", pointer, fallback: defaults.RejectMagicMismatch));
    }

    private static int PositiveCount(
        JsonObject parent,
        string member,
        string pointer,
        int fallback,
        SectionReadContext context)
    {
        var declared = context.Integer(parent, member, pointer);

        return declared is { } value && context.RequireAtLeast(value, 1, member, pointer)
            ? value
            : fallback;
    }

    private static long PositiveBytes(
        JsonObject parent,
        string member,
        string pointer,
        long fallback,
        SectionReadContext context)
    {
        var declared = context.Integer64(parent, member, pointer);

        return declared is { } value && context.RequireAtLeast(value, 1, member, pointer)
            ? value
            : fallback;
    }
}
