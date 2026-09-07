using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads the <c>operations</c> section: the effective HTTP operation model.
/// </summary>
internal static class OperationsSectionReader
{
    private static readonly string[] SectionMembers =
        ["formatVersion", "servers", "securitySchemes", "security", "components", "operations"];

    private static readonly string[] OperationMembers =
    [
        "key",
        "method",
        "path",
        "upstreamId",
        "summary",
        "description",
        "deprecated",
        "tags",
        "parameters",
        "requestBody",
        "responses",
        "security",
        "servers",
    ];

    private static readonly string[] ParameterMembers =
    [
        "name",
        "in",
        "required",
        "description",
        "style",
        "explode",
        "allowReserved",
        "allowEmptyValue",
        "deprecated",
        "schema",
        "content",
    ];

    private static readonly string[] RequestBodyMembers = ["content", "required", "description"];

    private static readonly string[] ResponseMembers = ["content", "description"];

    private static readonly string[] MediaTypeMembers =
        ["schema", "itemSchema", "encoding", "itemEncoding", "prefixEncoding"];

    private static readonly string[] EncodingMembers =
        ["propertyName", "contentType", "headers", "style", "explode", "allowReserved"];

    private static readonly string[] SecuritySchemeMembers =
        ["scheme", "bearerFormat", "in", "description"];

    /// <summary>
    /// The parameter location the intermediate model has but the request compiler refuses.
    /// </summary>
    private const string ExcludedLocation = "querystring";

    internal static OperationsSection? Read(JsonNode? document, SectionReadContext context)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, SectionMembers, string.Empty);
        context.VerifySectionFormatVersion(root, OperationsSection.FormatVersion);

        return new OperationsSection(
            ReadOperations(root, context),
            context.TextArray(root, "servers", string.Empty),
            ReadSecuritySchemes(root, context),
            ReadSecurity(root, "security", string.Empty, context) ?? [],
            context.Object(root, "components", string.Empty));
    }

    private static IReadOnlyList<ManifestOperation> ReadOperations(
        JsonObject root,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(root, "operations", string.Empty);
        var operations = new List<ManifestOperation>(elements.Count);
        var keys = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, OperationMembers, pointer);

            var method = context.RequiredText(element, "method", pointer);
            var path = context.RequiredText(element, "path", pointer);

            if (method is null || path is null)
            {
                continue;
            }

            // The key is derivable, so a hand-authored operation may omit it. When it is
            // present it must agree, because a disagreeing key is what every binding resolves
            // through.
            var derived = ManifestOperation.BuildKey(method, path);
            var declaredKey = context.Text(element, "key", pointer);

            if (declaredKey is not null && !string.Equals(declaredKey, derived, StringComparison.Ordinal))
            {
                context.Error(
                    ManifestDiagnosticCodes.KeyDisagreesWithMethodPath,
                    $"Key '{DiagnosticText.Echo(declaredKey)}' disagrees with the declared method and path, which produce '{DiagnosticText.Echo(derived)}'.",
                    SectionReadContext.Child(pointer, "key"));
                continue;
            }

            if (!keys.Add(derived))
            {
                context.Error(
                    ManifestDiagnosticCodes.DuplicateOperationKey,
                    $"Execution key '{DiagnosticText.Echo(derived)}' is declared more than once.",
                    pointer);
                continue;
            }

            var responses = ReadResponses(element, pointer, context);

            if (responses.Count == 0)
            {
                context.Warning(
                    ManifestDiagnosticCodes.NoResponsesDeclared,
                    $"Operation '{DiagnosticText.Echo(derived)}' declares no response. Binary response classification and structured-content validation both read the response contract, so omitting it changes runtime behavior.",
                    pointer);
            }

            operations.Add(new ManifestOperation(
                derived,
                method.ToUpperInvariant(),
                path,
                context.Text(element, "upstreamId", pointer),
                context.Text(element, "summary", pointer),
                context.Text(element, "description", pointer),
                context.Flag(element, "deprecated", pointer),
                context.TextArray(element, "tags", pointer),
                ReadParameters(element, pointer, context),
                ReadRequestBody(element, pointer, context),
                responses,
                ReadSecurity(element, "security", pointer, context),
                element["servers"] is null ? null : context.TextArray(element, "servers", pointer)));
        }

        return operations;
    }

    private static IReadOnlyList<ManifestParameter> ReadParameters(
        JsonObject operation,
        string pointer,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(operation, "parameters", pointer);
        var parameters = new List<ManifestParameter>(elements.Count);

        foreach (var (element, elementPointer) in elements)
        {
            context.RejectUnknownMembers(element, ParameterMembers, elementPointer);

            var name = context.RequiredText(element, "name", elementPointer);
            var declaredLocation = context.RequiredText(element, "in", elementPointer);

            if (name is null || declaredLocation is null)
            {
                continue;
            }

            if (!Vocabulary.TryReadParameterLocation(declaredLocation, out var location))
            {
                context.Error(
                    ManifestDiagnosticCodes.UnsupportedParameterLocation,
                    string.Equals(declaredLocation, ExcludedLocation, StringComparison.OrdinalIgnoreCase)
                        ? $"The '{ExcludedLocation}' location is not part of this manifest format version, because request compilation cannot serialize it. Model the value as individual query parameters instead."
                        : $"'{DiagnosticText.Echo(declaredLocation)}' is not a parameter location. Expected one of: {DiagnosticText.List(Vocabulary.ParameterLocationNames)}.",
                    SectionReadContext.Child(elementPointer, "in"));
                continue;
            }

            var style = ReadStyle(element, "style", elementPointer, context);

            if (style is { Valid: false })
            {
                continue;
            }

            parameters.Add(new ManifestParameter(
                name,
                location,
                context.Flag(element, "required", elementPointer),
                context.Text(element, "description", elementPointer),
                style?.Value,
                NullableFlag(element, "explode", elementPointer, context),
                context.Flag(element, "allowReserved", elementPointer),
                context.Flag(element, "allowEmptyValue", elementPointer),
                context.Flag(element, "deprecated", elementPointer),
                ManifestSchema.FromOrNull(element["schema"]),
                ReadContent(element, "content", elementPointer, context)));
        }

        return parameters;
    }

    private static ManifestRequestBody? ReadRequestBody(
        JsonObject operation,
        string pointer,
        SectionReadContext context)
    {
        var body = context.Object(operation, "requestBody", pointer);

        if (body is null)
        {
            return null;
        }

        var bodyPointer = SectionReadContext.Child(pointer, "requestBody");

        context.RejectUnknownMembers(body, RequestBodyMembers, bodyPointer);

        return new ManifestRequestBody(
            ReadContent(body, "content", bodyPointer, context)
                ?? new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal),
            context.Flag(body, "required", bodyPointer),
            context.Text(body, "description", bodyPointer));
    }

    private static IReadOnlyDictionary<string, ManifestResponse> ReadResponses(
        JsonObject operation,
        string pointer,
        SectionReadContext context)
    {
        var responses = context.Object(operation, "responses", pointer);
        var parsed = new Dictionary<string, ManifestResponse>(StringComparer.Ordinal);

        if (responses is null)
        {
            return parsed;
        }

        var responsesPointer = SectionReadContext.Child(pointer, "responses");

        foreach (var (status, value) in responses)
        {
            var statusPointer = SectionReadContext.Child(responsesPointer, status);

            if (value is not JsonObject response)
            {
                context.Error(
                    ManifestDiagnosticCodes.MemberTypeInvalid,
                    $"Response '{DiagnosticText.Echo(status)}' must be an object.",
                    statusPointer);
                continue;
            }

            context.RejectUnknownMembers(response, ResponseMembers, statusPointer);

            parsed[status] = new ManifestResponse(
                ReadContent(response, "content", statusPointer, context),
                context.Text(response, "description", statusPointer));
        }

        return parsed;
    }

    private static IReadOnlyDictionary<string, ManifestMediaType>? ReadContent(
        JsonObject parent,
        string member,
        string pointer,
        SectionReadContext context)
    {
        var content = context.Object(parent, member, pointer);

        if (content is null)
        {
            return null;
        }

        var contentPointer = SectionReadContext.Child(pointer, member);
        var parsed = new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal);

        foreach (var (mediaType, value) in content)
        {
            var mediaTypePointer = SectionReadContext.Child(contentPointer, mediaType);

            if (value is not JsonObject representation)
            {
                context.Error(
                    ManifestDiagnosticCodes.MemberTypeInvalid,
                    $"Representation '{DiagnosticText.Echo(mediaType)}' must be an object.",
                    mediaTypePointer);
                continue;
            }

            context.RejectUnknownMembers(representation, MediaTypeMembers, mediaTypePointer);

            parsed[mediaType] = new ManifestMediaType(
                mediaType,
                ManifestSchema.FromOrNull(representation["schema"]),
                ManifestSchema.FromOrNull(representation["itemSchema"]),
                ReadEncodingMap(representation, mediaTypePointer, context),
                ReadEncoding(representation, "itemEncoding", mediaTypePointer, propertyNameFallback: null, context),
                ReadPrefixEncoding(representation, mediaTypePointer, context));
        }

        return parsed;
    }

    private static IReadOnlyDictionary<string, ManifestEncoding>? ReadEncodingMap(
        JsonObject representation,
        string pointer,
        SectionReadContext context)
    {
        var encoding = context.Object(representation, "encoding", pointer);

        if (encoding is null)
        {
            return null;
        }

        var encodingPointer = SectionReadContext.Child(pointer, "encoding");
        var parsed = new Dictionary<string, ManifestEncoding>(StringComparer.Ordinal);

        foreach (var (property, value) in encoding)
        {
            var propertyPointer = SectionReadContext.Child(encodingPointer, property);

            if (value is not JsonObject entry)
            {
                context.Error(
                    ManifestDiagnosticCodes.MemberTypeInvalid,
                    $"Encoding for '{DiagnosticText.Echo(property)}' must be an object.",
                    propertyPointer);
                continue;
            }

            if (ReadEncodingEntry(entry, propertyPointer, property, context) is { } read)
            {
                parsed[property] = read;
            }
        }

        return parsed;
    }

    private static IReadOnlyList<ManifestEncoding>? ReadPrefixEncoding(
        JsonObject representation,
        string pointer,
        SectionReadContext context)
    {
        if (representation["prefixEncoding"] is null)
        {
            return null;
        }

        var elements = context.ObjectArray(representation, "prefixEncoding", pointer);
        var parsed = new List<ManifestEncoding>(elements.Count);

        foreach (var (element, elementPointer) in elements)
        {
            if (ReadEncodingEntry(element, elementPointer, propertyNameFallback: null, context) is { } read)
            {
                parsed.Add(read);
            }
        }

        return parsed;
    }

    private static ManifestEncoding? ReadEncoding(
        JsonObject representation,
        string member,
        string pointer,
        string? propertyNameFallback,
        SectionReadContext context)
    {
        var encoding = context.Object(representation, member, pointer);

        return encoding is null
            ? null
            : ReadEncodingEntry(
                encoding,
                SectionReadContext.Child(pointer, member),
                propertyNameFallback,
                context);
    }

    private static ManifestEncoding? ReadEncodingEntry(
        JsonObject entry,
        string pointer,
        string? propertyNameFallback,
        SectionReadContext context)
    {
        context.RejectUnknownMembers(entry, EncodingMembers, pointer);

        // In the map form the key already names the property, so repeating it is optional.
        var propertyName = context.Text(entry, "propertyName", pointer) ?? propertyNameFallback;

        if (propertyName is null)
        {
            context.Error(
                ManifestDiagnosticCodes.MemberRequired,
                "'propertyName' is required for an encoding that is not keyed by property name.",
                SectionReadContext.Child(pointer, "propertyName"));
            return null;
        }

        var style = ReadStyle(entry, "style", pointer, context);

        if (style is { Valid: false })
        {
            return null;
        }

        return new ManifestEncoding(
            propertyName,
            context.Text(entry, "contentType", pointer),
            ReadHeaderSchemas(entry, pointer, context),
            style?.Value,
            NullableFlag(entry, "explode", pointer, context),
            context.Flag(entry, "allowReserved", pointer));
    }

    private static IReadOnlyDictionary<string, ManifestSchema>? ReadHeaderSchemas(
        JsonObject entry,
        string pointer,
        SectionReadContext context)
    {
        var headers = context.Object(entry, "headers", pointer);

        if (headers is null)
        {
            return null;
        }

        var parsed = new Dictionary<string, ManifestSchema>(StringComparer.Ordinal);

        foreach (var (header, value) in headers)
        {
            if (ManifestSchema.FromOrNull(value) is { } schema)
            {
                parsed[header] = schema;
            }
        }

        return parsed;
    }

    private static IReadOnlyDictionary<string, ManifestSecurityScheme> ReadSecuritySchemes(
        JsonObject root,
        SectionReadContext context)
    {
        var schemes = context.Object(root, "securitySchemes", string.Empty);
        var parsed = new Dictionary<string, ManifestSecurityScheme>(StringComparer.Ordinal);

        if (schemes is null)
        {
            return parsed;
        }

        foreach (var (name, value) in schemes)
        {
            var pointer = "/securitySchemes/" + JsonPointer.Escape(name);

            if (value is not JsonObject scheme)
            {
                context.Error(
                    ManifestDiagnosticCodes.MemberTypeInvalid,
                    $"Security scheme '{DiagnosticText.Echo(name)}' must be an object.",
                    pointer);
                continue;
            }

            context.RejectUnknownMembers(scheme, SecuritySchemeMembers, pointer);

            parsed[name] = new ManifestSecurityScheme(
                context.Text(scheme, "scheme", pointer),
                context.Text(scheme, "bearerFormat", pointer),
                context.Text(scheme, "in", pointer),
                context.Text(scheme, "description", pointer));
        }

        return parsed;
    }

    private static IReadOnlyList<IReadOnlyDictionary<string, IReadOnlyList<string>>>? ReadSecurity(
        JsonObject parent,
        string member,
        string pointer,
        SectionReadContext context)
    {
        if (parent[member] is null)
        {
            return null;
        }

        var elements = context.ObjectArray(parent, member, pointer);
        var parsed = new List<IReadOnlyDictionary<string, IReadOnlyList<string>>>(elements.Count);

        foreach (var (element, elementPointer) in elements)
        {
            var requirement = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);

            foreach (var (scheme, _) in element)
            {
                requirement[scheme] = context.TextArray(element, scheme, elementPointer);
            }

            parsed.Add(requirement);
        }

        return parsed;
    }

    private static (ParameterStyle Value, bool Valid)? ReadStyle(
        JsonObject parent,
        string member,
        string pointer,
        SectionReadContext context)
    {
        if (parent[member] is null)
        {
            return null;
        }

        var declared = context.Text(parent, member, pointer);

        if (declared is null)
        {
            return (default, false);
        }

        if (!Vocabulary.TryReadParameterStyle(declared, out var style))
        {
            context.Error(
                ManifestDiagnosticCodes.UnknownParameterStyle,
                $"'{DiagnosticText.Echo(declared)}' is not a serialization style. Expected one of: {DiagnosticText.List(Vocabulary.ParameterStyleNames)}.",
                SectionReadContext.Child(pointer, member));
            return (default, false);
        }

        return (style, true);
    }

    private static bool? NullableFlag(
        JsonObject parent,
        string member,
        string pointer,
        SectionReadContext context)
        => parent[member] is null ? null : context.Flag(parent, member, pointer);
}
