using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads the optional <c>outputProjection</c> member of one agent operation.
/// </summary>
/// <remarks>
/// <para>
/// The vocabulary is closed, so an unknown member or value is a diagnostic rather than a
/// silently ignored policy: a hand-authored manifest that misspells a source kind must learn
/// about it instead of serving a projection nobody configured. Canonicalization happens on the
/// producer side; the reader lower-cases header names anyway so a hand-authored <c>ETag</c>
/// resolves the same way a compiled one does.
/// </para>
/// <para>
/// Structural and safety checks that need only the projection live here (pointer syntax,
/// overlap, hard-denied headers, source coherence). Cross-operation reachability and input-schema
/// mapping checks live in the validator, which can see the whole surface.
/// </para>
/// </remarks>
internal static class AgentOutputProjectionReader
{
    private static readonly string[] ProjectionMembers = ["bodyTarget", "metadata", "pagination"];

    private static readonly string[] MappingMembers = ["source", "target"];

    private static readonly string[] HeaderSourceMembers = ["kind", "name", "valueMode"];

    private static readonly string[] StatusSourceMembers = ["kind"];

    private static readonly string[] PaginationMembers =
        ["target", "source", "nextOperation", "nextArguments", "exposeUrl", "linkRelations"];

    private static readonly string[] LinkSourceMembers = ["kind", "header", "relation"];

    private static readonly string[] HeaderPaginationMembers = ["kind", "name", "scalarType"];

    private static readonly string[] JsonPointerSourceMembers = ["kind", "pointer", "interpretation"];

    private static readonly string[] ArgumentMappingMembers = ["target", "from", "as"];

    private static readonly string[] ArgumentSourceMembers = ["kind", "name", "pointer", "value"];

    internal static Model.AgentOutputProjection? Read(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        var projection = context.Object(element, "outputProjection", pointer);

        if (projection is null)
        {
            return null;
        }

        var projectionPointer = SectionReadContext.Child(pointer, "outputProjection");

        context.RejectUnknownMembers(projection, ProjectionMembers, projectionPointer);

        var bodyTarget = ReadPointer(projection, "bodyTarget", projectionPointer, context);

        if (bodyTarget is null)
        {
            return null;
        }

        var metadata = ReadMetadata(projection, projectionPointer, context);
        var pagination = ReadPagination(projection, projectionPointer, context);

        ValidateTargets(bodyTarget, metadata, pagination, projectionPointer, context);

        return new Model.AgentOutputProjection(bodyTarget, metadata, pagination);
    }

    private static IReadOnlyList<Model.ResponseMetadataMapping> ReadMetadata(
        JsonObject projection,
        string projectionPointer,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(projection, "metadata", projectionPointer);
        var metadataPointer = SectionReadContext.Child(projectionPointer, "metadata");
        var mappings = new List<Model.ResponseMetadataMapping>(elements.Count);

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, MappingMembers, pointer);

            var source = ReadSource(element, pointer, context);
            var target = ReadPointer(element, "target", pointer, context);

            if (source is null || target is null)
            {
                continue;
            }

            if (source is Model.ResponseHeaderMetadataSource header
                && Model.AgentOutputProjectionSafety.IsHardDenied(header.Name))
            {
                context.Error(
                    ManifestDiagnosticCodes.ProjectionHeaderSensitive,
                    $"Response header '{DiagnosticText.Echo(header.Name)}' is classified sensitive and cannot be projected.",
                    SectionReadContext.Child(pointer, "source"));
            }

            mappings.Add(new Model.ResponseMetadataMapping(source, target));
        }

        return mappings;
    }

    private static Model.ResponseMetadataSource? ReadSource(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        var source = context.Object(element, "source", pointer);

        if (source is null)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionShapeInvalid,
                "A metadata mapping requires a source.",
                SectionReadContext.Child(pointer, "source"));
            return null;
        }

        var sourcePointer = SectionReadContext.Child(pointer, "source");
        var kind = context.Text(source, "kind", sourcePointer);

        switch (kind)
        {
            case "responseHeader":
                context.RejectUnknownMembers(source, HeaderSourceMembers, sourcePointer);
                var name = ReadHeaderName(source, "name", sourcePointer, context);
                var mode = ReadValueMode(source, sourcePointer, context);
                return name is null || mode is null
                    ? null
                    : new Model.ResponseHeaderMetadataSource(name, mode.Value);
            case "statusCode":
                context.RejectUnknownMembers(source, StatusSourceMembers, sourcePointer);
                return new Model.StatusCodeMetadataSource();
            default:
                context.Error(
                    ManifestDiagnosticCodes.ProjectionUnknownValue,
                    $"'{DiagnosticText.Echo(kind ?? string.Empty)}' is not a response-metadata source kind. Expected one of: responseHeader, statusCode.",
                    SectionReadContext.Child(sourcePointer, "kind"));
                return null;
        }
    }

    private static Model.PaginationPolicy? ReadPagination(
        JsonObject projection,
        string projectionPointer,
        SectionReadContext context)
    {
        var pagination = context.Object(projection, "pagination", projectionPointer);

        if (pagination is null)
        {
            return null;
        }

        var paginationPointer = SectionReadContext.Child(projectionPointer, "pagination");

        context.RejectUnknownMembers(pagination, PaginationMembers, paginationPointer);

        var target = ReadPointer(pagination, "target", paginationPointer, context);
        var source = ReadPaginationSource(pagination, paginationPointer, context);
        var nextOperation = context.Text(pagination, "nextOperation", paginationPointer);

        if (nextOperation is { Length: 0 })
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionShapeInvalid,
                "'nextOperation' must be a non-empty operation slug when present.",
                SectionReadContext.Child(paginationPointer, "nextOperation"));
            nextOperation = null;
        }

        var arguments = ReadArgumentMappings(pagination, paginationPointer, source, context);
        var relations = ReadRelations(pagination, paginationPointer, context);

        if (target is null || source is null)
        {
            return null;
        }

        return new Model.PaginationPolicy(
            target,
            source,
            nextOperation,
            arguments,
            context.Flag(pagination, "exposeUrl", paginationPointer),
            relations);
    }

    private static IReadOnlyList<Model.PaginationArgumentMapping> ReadArgumentMappings(
        JsonObject pagination,
        string paginationPointer,
        Model.PaginationSource? source,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(pagination, "nextArguments", paginationPointer);
        var argumentsPointer = SectionReadContext.Child(paginationPointer, "nextArguments");
        var mappings = new List<Model.PaginationArgumentMapping>(elements.Count);
        var isUrlSource = source is Model.LinkHeaderPaginationSource
            or Model.JsonPointerPaginationSource { Interpretation: Model.JsonPointerInterpretation.Url };

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, ArgumentMappingMembers, pointer);

            var target = ReadPointer(element, "target", pointer, context);
            var from = ReadArgumentSource(element, pointer, context, isUrlSource);
            var conversion = ReadConversion(element, pointer, context);

            if (target is null || from is null || conversion is null)
            {
                continue;
            }

            if (conversion == Model.PaginationConversion.PreserveJson
                && !AllowsPreserveJson(source, from))
            {
                context.Error(
                    ManifestDiagnosticCodes.ProjectionUnknownValue,
                    "'preserveJson' requires a JSON-valued source: a JSON-pointer extraction, a current-argument pointer or a reviewed literal.",
                    SectionReadContext.Child(pointer, "as"));
            }

            mappings.Add(new Model.PaginationArgumentMapping(target, from, conversion.Value));
        }

        return mappings;
    }

    private static Model.PaginationArgumentSource? ReadArgumentSource(
        JsonObject element,
        string pointer,
        SectionReadContext context,
        bool isUrlSource)
    {
        var source = context.Object(element, "from", pointer);

        if (source is null)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionShapeInvalid,
                "A next-argument mapping requires a source.",
                SectionReadContext.Child(pointer, "from"));
            return null;
        }

        var sourcePointer = SectionReadContext.Child(pointer, "from");
        var kind = context.Text(source, "kind", sourcePointer);

        switch (kind)
        {
            case "extractedValue":
                context.RejectUnknownMembers(source, ["kind"], sourcePointer);
                return new Model.ExtractedPaginationArgument();
            case "urlQuery":
                context.RejectUnknownMembers(source, ["kind", "name"], sourcePointer);
                RequireUrlSource(sourcePointer, context, isUrlSource);
                var queryName = context.RequiredText(source, "name", sourcePointer);
                return queryName is null ? null : new Model.UrlQueryPaginationArgument(queryName);
            case "urlPathParameter":
                context.RejectUnknownMembers(source, ["kind", "name"], sourcePointer);
                RequireUrlSource(sourcePointer, context, isUrlSource);
                var pathName = context.RequiredText(source, "name", sourcePointer);
                return pathName is null ? null : new Model.UrlPathPaginationArgument(pathName);
            case "currentArgument":
                context.RejectUnknownMembers(source, ["kind", "pointer"], sourcePointer);
                var currentPointer = ReadPointer(source, "pointer", sourcePointer, context);
                return currentPointer is null ? null : new Model.CurrentArgumentPaginationArgument(currentPointer);
            case "literal":
                context.RejectUnknownMembers(source, ["kind", "value"], sourcePointer);
                return source.ContainsKey("value")
                    ? new Model.LiteralPaginationArgument(source["value"]?.DeepClone())
                    : MissingLiteral(sourcePointer, context);
            default:
                context.Error(
                    ManifestDiagnosticCodes.ProjectionUnknownValue,
                    $"'{DiagnosticText.Echo(kind ?? string.Empty)}' is not a next-argument source kind. Expected one of: extractedValue, urlQuery, urlPathParameter, currentArgument, literal.",
                    SectionReadContext.Child(sourcePointer, "kind"));
                return null;
        }

        static Model.PaginationArgumentSource? MissingLiteral(string pointer, SectionReadContext context)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionShapeInvalid,
                "A literal next-argument source requires a 'value'.",
                SectionReadContext.Child(pointer, "value"));
            return null;
        }
    }

    private static void RequireUrlSource(string pointer, SectionReadContext context, bool isUrlSource)
    {
        if (!isUrlSource)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionUrlSourceRequired,
                "URL components require a URL-valued pagination source: a Link source or a JSON-pointer source interpreted as a URL.",
                pointer);
        }
    }

    private static IReadOnlyList<Model.PaginationRelation> ReadRelations(
        JsonObject pagination,
        string paginationPointer,
        SectionReadContext context)
    {
        var array = context.Array(pagination, "linkRelations", paginationPointer);

        if (array is null)
        {
            return [];
        }

        var relations = new List<Model.PaginationRelation>(array.Count);
        var index = 0;

        foreach (var element in array)
        {
            var value = element is JsonValue json && json.TryGetValue<string>(out var text) ? text : null;
            var relation = ReadRelationValue(value);

            if (relation is null)
            {
                context.Error(
                    ManifestDiagnosticCodes.ProjectionUnknownValue,
                    $"'{DiagnosticText.Echo(value ?? string.Empty)}' is not a link relation. Expected one of: next, prev, first, last.",
                    SectionReadContext.Child(paginationPointer, "linkRelations") + "/" + index.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            else
            {
                relations.Add(relation.Value);
            }

            index++;
        }

        return relations;
    }

    private static Model.PaginationSource? ReadPaginationSource(
        JsonObject pagination,
        string paginationPointer,
        SectionReadContext context)
    {
        var source = context.Object(pagination, "source", paginationPointer);

        if (source is null)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionShapeInvalid,
                "A pagination policy requires a source.",
                SectionReadContext.Child(paginationPointer, "source"));
            return null;
        }

        var sourcePointer = SectionReadContext.Child(paginationPointer, "source");
        var kind = context.Text(source, "kind", sourcePointer);

        switch (kind)
        {
            case "linkHeader":
                context.RejectUnknownMembers(source, LinkSourceMembers, sourcePointer);
                var header = ReadHeaderName(source, "header", sourcePointer, context);
                var relation = ReadRelationValue(context.Text(source, "relation", sourcePointer));

                if (relation is null)
                {
                    context.Error(
                        ManifestDiagnosticCodes.ProjectionUnknownValue,
                        "A link source requires a relation from: next, prev, first, last.",
                        SectionReadContext.Child(sourcePointer, "relation"));
                    return null;
                }

                if (relation != Model.PaginationRelation.Next)
                {
                    context.Error(
                        ManifestDiagnosticCodes.ProjectionShapeInvalid,
                        "Version 1 continuation requires the 'next' relation. Other relations are operator inspection only.",
                        SectionReadContext.Child(sourcePointer, "relation"));
                    return null;
                }

                if (header is not null && Model.AgentOutputProjectionSafety.IsHardDenied(header))
                {
                    context.Error(
                        ManifestDiagnosticCodes.ProjectionHeaderSensitive,
                        $"Response header '{DiagnosticText.Echo(header)}' is classified sensitive and cannot be used for pagination.",
                        SectionReadContext.Child(sourcePointer, "header"));
                }

                return header is null ? null : new Model.LinkHeaderPaginationSource(header, relation.Value);
            case "responseHeader":
                context.RejectUnknownMembers(source, HeaderPaginationMembers, sourcePointer);
                var name = ReadHeaderName(source, "name", sourcePointer, context);
                var scalarType = ReadScalarType(context.Text(source, "scalarType", sourcePointer));

                if (scalarType is null)
                {
                    context.Error(
                        ManifestDiagnosticCodes.ProjectionUnknownValue,
                        "A header pagination source requires a scalarType from: string, integer, number, boolean.",
                        SectionReadContext.Child(sourcePointer, "scalarType"));
                    return null;
                }

                if (name is not null && Model.AgentOutputProjectionSafety.IsHardDenied(name))
                {
                    context.Error(
                        ManifestDiagnosticCodes.ProjectionHeaderSensitive,
                        $"Response header '{DiagnosticText.Echo(name)}' is classified sensitive and cannot be used for pagination.",
                        SectionReadContext.Child(sourcePointer, "name"));
                }

                return name is null ? null : new Model.ResponseHeaderPaginationSource(name, scalarType.Value);
            case "jsonPointer":
                context.RejectUnknownMembers(source, JsonPointerSourceMembers, sourcePointer);
                var jsonPointer = ReadPointer(source, "pointer", sourcePointer, context);
                var interpretation = ReadInterpretation(context.Text(source, "interpretation", sourcePointer));

                if (interpretation is null)
                {
                    context.Error(
                        ManifestDiagnosticCodes.ProjectionUnknownValue,
                        "A JSON-pointer pagination source requires an interpretation of 'value' or 'url'.",
                        SectionReadContext.Child(sourcePointer, "interpretation"));
                    return null;
                }

                return jsonPointer is null
                    ? null
                    : new Model.JsonPointerPaginationSource(jsonPointer, interpretation.Value);
            default:
                context.Error(
                    ManifestDiagnosticCodes.ProjectionUnknownValue,
                    $"'{DiagnosticText.Echo(kind ?? string.Empty)}' is not a pagination source kind. Expected one of: linkHeader, responseHeader, jsonPointer.",
                    SectionReadContext.Child(sourcePointer, "kind"));
                return null;
        }
    }

    /// <summary>
    /// Refuses overlapping targets. Body target, metadata targets and the pagination target are
    /// one namespace: two writers at the same node would make the result depend on application
    /// order, which no requirement defines.
    /// </summary>
    private static void ValidateTargets(
        string bodyTarget,
        IReadOnlyList<Model.ResponseMetadataMapping> metadata,
        Model.PaginationPolicy? pagination,
        string projectionPointer,
        SectionReadContext context)
    {
        var declared = new List<(string Pointer, string Where)> { (bodyTarget, "bodyTarget") };

        foreach (var mapping in metadata)
        {
            RefuseOverlap(declared, mapping.Target, mapping.Target, projectionPointer, context);
            declared.Add((mapping.Target, mapping.Target));
        }

        if (pagination is not null)
        {
            RefuseOverlap(declared, pagination.Target, "pagination", projectionPointer, context);
        }

        static void RefuseOverlap(
            List<(string Pointer, string Where)> declared,
            string candidate,
            string where,
            string projectionPointer,
            SectionReadContext context)
        {
            foreach (var (pointer, existing) in declared)
            {
                if (Overlaps(pointer, candidate))
                {
                    context.Error(
                        ManifestDiagnosticCodes.ProjectionTargetOverlap,
                        $"'{where}' overlaps '{existing}'. One projection value would overwrite the other.",
                        projectionPointer);
                    return;
                }
            }
        }
    }

    /// <summary>
    /// True when two pointers address the same node or one contains the other.
    /// </summary>
    /// <remarks>
    /// Comparison is segment-wise after unescaping, so <c>/a~1b</c> and <c>/a/b</c> are distinct
    /// while <c>/metadata</c> contains <c>/metadata/etag</c>.
    /// </remarks>
    internal static bool Overlaps(string left, string right)
    {
        var leftSegments = Segments(left);
        var rightSegments = Segments(right);
        var shared = Math.Min(leftSegments.Count, rightSegments.Count);

        for (var index = 0; index < shared; index++)
        {
            if (!string.Equals(leftSegments[index], rightSegments[index], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static IReadOnlyList<string> Segments(string pointer)
    {
        if (pointer.Length == 0)
        {
            return [];
        }

        return [.. pointer[1..].Split('/').Select(JsonPointer.Unescape)];
    }

    private static string? ReadPointer(
        JsonObject parent,
        string member,
        string pointer,
        SectionReadContext context)
    {
        var value = context.Text(parent, member, pointer);

        if (value is null || !JsonPointer.IsSyntacticallyValid(value) || value.Length == 0)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionPointerInvalid,
                $"'{member}' requires a non-root RFC 6901 pointer.",
                SectionReadContext.Child(pointer, member));
            return null;
        }

        return value;
    }

    /// <summary>
    /// Reads a header name, canonicalizing ASCII case. A non-ASCII character is refused rather
    /// than folded, because HTTP field names are ASCII tokens.
    /// </summary>
    private static string? ReadHeaderName(
        JsonObject parent,
        string member,
        string pointer,
        SectionReadContext context)
    {
        var value = context.Text(parent, member, pointer);

        if (string.IsNullOrWhiteSpace(value))
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionHeaderNameInvalid,
                $"'{member}' requires a non-empty header name.",
                SectionReadContext.Child(pointer, member));
            return null;
        }

        var trimmed = value.Trim();

        if (trimmed.Any(static character => character > 0x7F))
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionHeaderNameInvalid,
                $"Response header name '{DiagnosticText.Echo(value)}' contains a non-ASCII character.",
                SectionReadContext.Child(pointer, member));
            return null;
        }

        return trimmed.ToLowerInvariant();
    }

    private static Model.HeaderValueMode? ReadValueMode(
        JsonObject source,
        string pointer,
        SectionReadContext context)
    {
        var value = context.Text(source, "valueMode", pointer);

        if (value is null)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionShapeInvalid,
                "A response header source requires a valueMode of 'first' or 'all'.",
                SectionReadContext.Child(pointer, "valueMode"));
            return null;
        }

        return value switch
        {
            "first" => Model.HeaderValueMode.First,
            "all" => Model.HeaderValueMode.All,
            _ => Unknown(pointer, context),
        };

        static Model.HeaderValueMode? Unknown(string pointer, SectionReadContext context)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionUnknownValue,
                "A header value mode must be 'first' or 'all'.",
                SectionReadContext.Child(pointer, "valueMode"));
            return null;
        }
    }

    private static Model.PaginationRelation? ReadRelationValue(string? value) => value switch
    {
        "next" => Model.PaginationRelation.Next,
        "prev" => Model.PaginationRelation.Prev,
        "first" => Model.PaginationRelation.First,
        "last" => Model.PaginationRelation.Last,
        _ => null,
    };

    private static Model.PaginationScalarType? ReadScalarType(string? value) => value switch
    {
        "string" => Model.PaginationScalarType.String,
        "integer" => Model.PaginationScalarType.Integer,
        "number" => Model.PaginationScalarType.Number,
        "boolean" => Model.PaginationScalarType.Boolean,
        _ => null,
    };

    private static Model.JsonPointerInterpretation? ReadInterpretation(string? value) => value switch
    {
        "value" => Model.JsonPointerInterpretation.Value,
        "url" => Model.JsonPointerInterpretation.Url,
        _ => null,
    };

    private static Model.PaginationConversion? ReadConversion(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        var value = context.Text(element, "as", pointer);

        if (value is null)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionShapeInvalid,
                "A next-argument mapping requires a conversion in 'as'.",
                SectionReadContext.Child(pointer, "as"));
            return null;
        }

        return value switch
        {
            "string" => Model.PaginationConversion.String,
            "integer" => Model.PaginationConversion.Integer,
            "number" => Model.PaginationConversion.Number,
            "boolean" => Model.PaginationConversion.Boolean,
            "preserveJson" => Model.PaginationConversion.PreserveJson,
            _ => Unknown(pointer, context),
        };

        static Model.PaginationConversion? Unknown(string pointer, SectionReadContext context)
        {
            context.Error(
                ManifestDiagnosticCodes.ProjectionUnknownValue,
                "A conversion must be one of: string, integer, number, boolean, preserveJson.",
                SectionReadContext.Child(pointer, "as"));
            return null;
        }
    }

    private static bool AllowsPreserveJson(
        Model.PaginationSource? source,
        Model.PaginationArgumentSource argument)
        => argument switch
        {
            Model.CurrentArgumentPaginationArgument or Model.LiteralPaginationArgument => true,
            Model.ExtractedPaginationArgument => source is Model.JsonPointerPaginationSource,
            _ => false,
        };
}
