using System.Text.Json;

using Json.Schema;

namespace MCPiler.Engine.Mcp;

/// <summary>Validates a structured result against the exact schema advertised for its session.</summary>
internal static class StructuredContentValidator
{
    internal const string DiagnosticCode = "mcp/structured-content-invalid";

    internal const string DiagnosticMessage =
        "The payload did not conform to the advertised output schema; structuredContent was omitted.";

    private static readonly BuildOptions AdvertisedDialect = new() { Dialect = Dialect.Draft202012 };

    /// <summary>Returns no location on success and the failing schema location on failure.</summary>
    internal static string? Validate(JsonElement payload, string advertisedSchemaJson)
    {
        ArgumentException.ThrowIfNullOrEmpty(advertisedSchemaJson);

        try
        {
            JsonSchema schema = JsonSchema.FromText(advertisedSchemaJson, AdvertisedDialect);
            EvaluationResults evaluation = schema.Evaluate(
                payload,
                new EvaluationOptions { OutputFormat = OutputFormat.Hierarchical });

            return evaluation.IsValid ? null : Location(evaluation) ?? "#";
        }
        catch (Exception failure) when (failure is JsonException
            or JsonSchemaException
            or NotSupportedException
            or ArgumentException
            or FormatException
            or System.Text.RegularExpressions.RegexMatchTimeoutException)
        {
            // Advertised schemas pass the load-time schema gate. This remains fail-closed for a
            // directly constructed catalogue value and names the root without leaking schema text.
            return "#";
        }
    }

    private static string? Location(EvaluationResults evaluation)
    {
        string? specific = (evaluation.Details ?? [])
            .Where(static detail => !detail.IsValid)
            .OrderBy(static detail => detail.EvaluationPath.ToString(), StringComparer.Ordinal)
            .Select(Location)
            .FirstOrDefault(static location => location is not null);

        if (specific is not null)
        {
            return specific;
        }

        string location = evaluation.EvaluationPath.ToString();
        return string.IsNullOrEmpty(location) ? null : location;
    }
}
