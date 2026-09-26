using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Manifest.Validation;

/// <summary>
/// Engine-side counterpart to Platform's projection/output-schema contract check. Keeps
/// hand-authored manifests from serving an envelope that their declared schema excludes.
/// </summary>
internal static class ProjectionOutputSchemaValidator
{
    private static readonly string[] PaginationStates = ["next", "end", "unavailable"];

    public static IReadOnlyList<string> Validate(
        AgentOutputProjection projection,
        AgentOperationEntry operation,
        SchemaReferenceResolver? resolver)
    {
        ArgumentNullException.ThrowIfNull(projection);
        ArgumentNullException.ThrowIfNull(operation);

        OutputSchemaPolicySettings outputPolicy = operation.EffectiveOutputSchemaPolicy;
        if (!outputPolicy.Generate
            || (outputPolicy.Advertise == OutputSchemaAdvertisement.No && !outputPolicy.UseInternally))
        {
            return [];
        }

        ManifestSchema? outputSchema = operation.OutputSchema;
        if (outputSchema is null)
        {
            return [];
        }

        ManifestSchema root = Resolve(outputSchema, resolver) ?? outputSchema;
        if (root.IsBoolean)
        {
            return root.Node is JsonValue value
                && value.TryGetValue<bool>(out bool allowsAny)
                && allowsAny
                ? []
                : ["OutputSchema explicitly rejects every projected output."];
        }

        if (root.Object is not { } rootObject)
        {
            return ["OutputSchema must accept the JSON object envelope produced by output projection."];
        }

        List<string> errors = [];
        HashSet<string> guaranteedTargets = [projection.BodyTarget];
        foreach (ResponseMetadataMapping mapping in projection.Metadata)
        {
            if (mapping.Source is StatusCodeMetadataSource)
            {
                guaranteedTargets.Add(mapping.Target);
            }
        }
        if (projection.Pagination is { } policy)
        {
            guaranteedTargets.Add(policy.Target);
        }

        ValidateTarget(
            projection.BodyTarget,
            "outputProjection.bodyTarget",
            required: true,
            expectedType: null,
            rootObject,
            resolver,
            guaranteedTargets,
            errors);

        foreach (ResponseMetadataMapping mapping in projection.Metadata)
        {
            string label = $"outputProjection.metadata[{mapping.Target}]";
            string? expectedType = mapping.Source switch
            {
                StatusCodeMetadataSource => "integer",
                ResponseHeaderMetadataSource { ValueMode: HeaderValueMode.First } => "string",
                ResponseHeaderMetadataSource { ValueMode: HeaderValueMode.All } => "array-of-string",
                _ => null,
            };

            ValidateTarget(
                mapping.Target,
                label,
                mapping.Source is not ResponseHeaderMetadataSource,
                expectedType,
                rootObject,
                resolver,
                guaranteedTargets,
                errors);
        }

        if (projection.Pagination is { } pagination)
        {
            JsonObject? paginationSchema = ValidateTarget(
                pagination.Target,
                "outputProjection.pagination",
                required: true,
                expectedType: "object",
                rootObject,
                resolver,
                guaranteedTargets,
                errors);
            if (paginationSchema is not null)
            {
                ValidatePaginationShape(paginationSchema, resolver, pagination.ExposeUrl, errors);
            }
        }

        ValidateRequiredProperties(
            rootObject,
            string.Empty,
            guaranteedTargets,
            resolver,
            errors,
            new HashSet<JsonObject>(ReferenceEqualityComparer.Instance),
            depth: 0);

        return errors;
    }

    private static JsonObject? ValidateTarget(
        string pointer,
        string label,
        bool required,
        string? expectedType,
        JsonObject root,
        SchemaReferenceResolver? resolver,
        IReadOnlySet<string> guaranteedTargets,
        List<string> errors)
    {
        JsonObject? current = root;
        List<string> path = [];
        List<string> requiredPrefixes = [];
        foreach (string token in Segments(pointer))
        {
            if (current is null)
            {
                path.Add(token);
                continue;
            }

            if (DefinitelyNotObject(current))
            {
                errors.Add($"{label}: OutputSchema path '{pointer}' traverses a schema that is not an object.");
                return null;
            }

            path.Add(token);
            if (IsRequired(current, token))
            {
                requiredPrefixes.Add(BuildPointer(path));
            }

            if (current["properties"] is JsonObject properties
                && properties.TryGetPropertyValue(token, out JsonNode? child))
            {
                ManifestSchema childSchema = ManifestSchema.From(child ?? JsonValue.Create(true)!);
                ManifestSchema? resolvedChild = Resolve(childSchema, resolver);
                if (resolvedChild?.IsBoolean == true)
                {
                    if (resolvedChild.Node is JsonValue boolNode
                        && boolNode.TryGetValue<bool>(out bool allowed)
                        && !allowed)
                    {
                        errors.Add($"{label}: OutputSchema explicitly rejects target '{pointer}'.");
                        return null;
                    }
                    current = null;
                }
                else
                {
                    current = resolvedChild?.Object;
                }
                continue;
            }

            if (current["additionalProperties"] is JsonValue extra
                && extra.TryGetValue<bool>(out bool extraAllowed)
                && !extraAllowed)
            {
                errors.Add($"{label}: OutputSchema disallows undeclared target '{pointer}'.");
                return null;
            }

            current = ResolveObject(current["additionalProperties"], resolver);
        }

        foreach (string requiredPrefix in requiredPrefixes)
        {
            if (!required && !guaranteedTargets.Any(target =>
                string.Equals(target, requiredPrefix, StringComparison.Ordinal)
                || target.StartsWith(requiredPrefix + "/", StringComparison.Ordinal)))
            {
                errors.Add($"{label}: OutputSchema requires '{requiredPrefix}', but an upstream header-derived target may be absent.");
            }
            else if (!guaranteedTargets.Any(target =>
                string.Equals(target, requiredPrefix, StringComparison.Ordinal)
                || target.StartsWith(requiredPrefix + "/", StringComparison.Ordinal)))
            {
                errors.Add($"{label}: OutputSchema requires parent path '{requiredPrefix}', but projected children may be omitted.");
            }
        }

        ValidateType(current, expectedType, pointer, label, resolver, errors);
        return current;
    }

    private static void ValidatePaginationShape(
        JsonObject schema,
        SchemaReferenceResolver? resolver,
        bool exposeUrl,
        List<string> errors)
    {
        if (IsRequired(schema, "next") || IsRequired(schema, "hasNext"))
        {
            errors.Add("outputProjection.pagination: OutputSchema cannot require 'next' or 'hasNext'; end/unavailable states omit them.");
        }

        if (schema["properties"] is not JsonObject properties)
        {
            if (schema["additionalProperties"] is JsonValue additional
                && additional.TryGetValue<bool>(out var allowed)
                && !allowed)
            {
                errors.Add("outputProjection.pagination: OutputSchema closes the object without allowing required 'state'.");
            }
            return;
        }

        if (properties.TryGetPropertyValue("state", out JsonNode? stateNode))
        {
            if (ResolveObject(stateNode, resolver) is { } stateSchema)
            {
                ValidateType(stateSchema, "string", "outputProjection.pagination", "/state", resolver, errors);
                if (stateSchema["enum"] is JsonArray values)
                {
                    HashSet<string> declared = values.OfType<JsonValue>()
                        .Select(value => value.TryGetValue<string>(out string? state) ? state : null)
                        .Where(static state => state is not null)
                        .Select(static state => state!)
                        .ToHashSet(StringComparer.Ordinal);
                    foreach (string state in PaginationStates)
                    {
                        if (!declared.Contains(state))
                        {
                            errors.Add($"outputProjection.pagination: OutputSchema 'state' enum must include '{state}'.");
                        }
                    }
                }
            }
            else
            {
                errors.Add("outputProjection.pagination: OutputSchema 'state' must accept strings.");
            }
        }
        else if (schema["additionalProperties"] is JsonValue closedState
            && closedState.TryGetValue<bool>(out var stateClosed)
            && stateClosed)
        {
            errors.Add("outputProjection.pagination: OutputSchema must declare 'state' when the object is closed.");
        }

        if (properties.TryGetPropertyValue("hasNext", out JsonNode? hasNextNode))
        {
            if (ResolveObject(hasNextNode, resolver) is { } hasNextSchema)
            {
                ValidateType(hasNextSchema, "boolean", "outputProjection.pagination", "/hasNext", resolver, errors);
            }
            else
            {
                errors.Add("outputProjection.pagination: OutputSchema 'hasNext' must accept booleans.");
            }
        }
        else if (schema["additionalProperties"] is JsonValue closedHasNext
            && closedHasNext.TryGetValue<bool>(out var hasNextClosed)
            && hasNextClosed)
        {
            errors.Add("outputProjection.pagination: OutputSchema must declare 'hasNext' when the object is closed.");
        }

        if (properties.TryGetPropertyValue("next", out JsonNode? nextNode))
        {
            if (ResolveObject(nextNode, resolver) is { } nextSchema)
            {
                ValidateNextShape(nextSchema, resolver, exposeUrl, errors);
            }
            else
            {
                errors.Add("outputProjection.pagination.next: OutputSchema must accept an object.");
            }
        }
        else if (schema["additionalProperties"] is JsonValue closedNext
            && closedNext.TryGetValue<bool>(out var nextClosed)
            && nextClosed)
        {
            errors.Add("outputProjection.pagination: OutputSchema must declare 'next' when the object is closed.");
        }
    }

    private static void ValidateNextShape(
        JsonObject schema,
        SchemaReferenceResolver? resolver,
        bool exposeUrl,
        List<string> errors)
    {
        if (DefinitelyNotObject(schema))
        {
            errors.Add("outputProjection.pagination.next: OutputSchema must accept an object.");
            return;
        }

        if (schema["required"] is JsonArray required)
        {
            foreach (JsonValue value in required.OfType<JsonValue>())
            {
                if (!value.TryGetValue<string>(out var property))
                {
                    continue;
                }

                if (property == "url" && !exposeUrl)
                {
                    errors.Add("outputProjection.pagination.next: OutputSchema cannot require optional 'url' when ExposeUrl is disabled.");
                }
                else if (property is not ("operation" or "tool" or "arguments" or "url"))
                {
                    errors.Add($"outputProjection.pagination.next: OutputSchema requires unsupported member '{property}'.");
                }
            }
        }

        if (schema["properties"] is not JsonObject properties)
        {
            if (schema["additionalProperties"] is JsonValue additional
                && additional.TryGetValue<bool>(out var allowed)
                && !allowed)
            {
                errors.Add("outputProjection.pagination.next: OutputSchema closes the object without allowing continuation members.");
            }
            return;
        }

        foreach ((string property, string expectedType) in new[]
        {
            ("operation", "string"),
            ("tool", "string"),
            ("arguments", "object"),
            ("url", "string"),
        })
        {
            if (property == "url" && exposeUrl
                && schema["additionalProperties"] is JsonValue closedUrl
                && closedUrl.TryGetValue<bool>(out var urlClosed)
                && urlClosed
                && !properties.ContainsKey("url"))
            {
                errors.Add("outputProjection.pagination.next: OutputSchema must declare 'url' when ExposeUrl is enabled and the object is closed.");
            }

            if (properties.TryGetPropertyValue(property, out JsonNode? propertyNode))
            {
                if (ResolveObject(propertyNode, resolver) is { } propertySchema)
                {
                    ValidateType(
                        propertySchema,
                        expectedType,
                        "outputProjection.pagination.next",
                        $"/{property}",
                        resolver,
                        errors);
                }
            }
            else if (schema["additionalProperties"] is JsonValue closed
                && closed.TryGetValue<bool>(out var isClosed)
                && isClosed
                && property is "operation" or "tool" or "arguments")
            {
                errors.Add($"outputProjection.pagination.next: OutputSchema must declare '{property}' when the object is closed.");
            }
        }
    }

    private static void ValidateRequiredProperties(
        JsonObject schema,
        string parentPointer,
        IReadOnlySet<string> guaranteedTargets,
        SchemaReferenceResolver? resolver,
        List<string> errors,
        HashSet<JsonObject> ancestry,
        int depth)
    {
        if (depth > 64 || !ancestry.Add(schema))
        {
            return;
        }

        try
        {
            if (schema["required"] is not JsonArray required)
            {
                return;
            }

            foreach (JsonValue value in required.OfType<JsonValue>())
            {
                if (!value.TryGetValue<string>(out string? property) || property is null)
                {
                    continue;
                }

                string propertyPointer = parentPointer + "/" + JsonPointer.Escape(property);
                if (!IsGuaranteed(propertyPointer, guaranteedTargets))
                {
                    errors.Add($"OutputSchema requires '{propertyPointer}', but the projection does not always write it.");
                }

                if (schema["properties"] is JsonObject properties
                    && ResolveObject(properties[property], resolver) is { } childSchema)
                {
                    ValidateRequiredProperties(
                        childSchema,
                        propertyPointer,
                        guaranteedTargets,
                        resolver,
                        errors,
                        ancestry,
                        depth + 1);
                }
            }
        }
        finally
        {
            ancestry.Remove(schema);
        }
    }

    private static bool IsGuaranteed(string requiredPointer, IReadOnlySet<string> targets)
        => targets.Any(target =>
            string.Equals(target, requiredPointer, StringComparison.Ordinal)
            || target.StartsWith(requiredPointer + "/", StringComparison.Ordinal)
            || requiredPointer.StartsWith(target + "/", StringComparison.Ordinal));

    private static void ValidateType(
        JsonObject? schema,
        string? expectedType,
        string pointer,
        string label,
        SchemaReferenceResolver? resolver,
        List<string> errors)
    {
        if (schema is null || expectedType is null)
        {
            return;
        }

        IReadOnlyList<string>? types = DeclaredTypes(schema);
        if (types is not { Count: > 0 })
        {
            return;
        }

        if (expectedType == "array-of-string")
        {
            if (!types.Contains("array", StringComparer.Ordinal)
                || schema["items"] is JsonObject items
                && DeclaredTypes(ResolveObject(items, resolver) ?? items) is { Count: > 0 } itemTypes
                && !itemTypes.Contains("string", StringComparer.Ordinal))
            {
                errors.Add($"{label}: OutputSchema target '{pointer}' must accept an ordered array of strings.");
            }
            return;
        }

        if (!types.Contains(expectedType, StringComparer.Ordinal)
            && !(expectedType == "integer" && types.Contains("number", StringComparer.Ordinal)))
        {
            errors.Add($"{label}: OutputSchema target '{pointer}' does not accept '{expectedType}'.");
        }
    }

    private static ManifestSchema? Resolve(ManifestSchema schema, SchemaReferenceResolver? resolver)
    {
        if (resolver is null)
        {
            return schema;
        }
        return resolver.TryResolve(schema, out ManifestSchema resolved, out _)
            ? resolved
            : null;
    }

    private static JsonObject? ResolveObject(JsonNode? node, SchemaReferenceResolver? resolver)
        => node is null ? null : Resolve(ManifestSchema.From(node), resolver)?.Object;

    private static IReadOnlyList<string> Segments(string pointer)
        => pointer.Split('/').Skip(1)
            .Select(static token => JsonPointer.Unescape(token))
            .ToArray();

    private static string BuildPointer(IEnumerable<string> segments)
        => "/" + string.Join("/", segments.Select(JsonPointer.Escape));

    private static bool IsRequired(JsonObject schema, string name)
        => schema["required"] is JsonArray required
            && required.OfType<JsonValue>().Any(value =>
                value.TryGetValue<string>(out string? item) && string.Equals(item, name, StringComparison.Ordinal));

    private static bool DefinitelyNotObject(JsonObject schema)
        => DeclaredTypes(schema) is { Count: > 0 } types
            && !types.Contains("object", StringComparer.Ordinal);

    private static bool DefinitelyNotString(JsonObject schema)
        => DeclaredTypes(schema) is { Count: > 0 } types
            && !types.Contains("string", StringComparer.Ordinal);

    private static IReadOnlyList<string>? DeclaredTypes(JsonObject schema)
    {
        if (schema["type"] is JsonValue type && type.TryGetValue<string>(out string? name))
        {
            return [name];
        }
        return schema["type"] is JsonArray union
            ? union.OfType<JsonValue>()
                .Select(value => value.TryGetValue<string>(out string? item) ? item : null)
                .Where(static item => item is not null)
                .Select(static item => item!)
                .ToArray()
            : null;
    }
}
