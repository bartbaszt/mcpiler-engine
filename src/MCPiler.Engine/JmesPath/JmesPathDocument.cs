using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.JmesPath;

/// <summary>
/// Parses JSON text for the projection pipeline.
/// </summary>
/// <remarks>
/// <para>
/// Parsing keeps duplicate member names. It cannot express them in a <c>JsonObject</c> —
/// enumeration of a collapsed object throws in this runtime — so it stays on
/// <see cref="JsonDocument"/>, where the member sequence survives exactly as it was written.
/// Reordering members for determinism is a separate transformation performed over that
/// representation, and it is stable, so duplicates keep their relative order.
/// </para>
/// <para>
/// Comments and trailing commas are refused rather than tolerated. A body that is almost JSON
/// is not JSON, and accepting it would make the projection's behavior depend on which lenient
/// reader happened to be in front of it.
/// </para>
/// </remarks>
internal static class JmesPathDocument
{
    /// <summary>Parses UTF-8 JSON, classifying a parse failure as an ineligible body.</summary>
    internal static bool TryParse(
        ReadOnlyMemory<byte> json,
        [NotNullWhen(true)] out JsonDocument? document,
        [NotNullWhen(false)] out JmesPathFailure? failure)
    {
        document = null;
        failure = null;

        try
        {
            document = JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,

                    // The declared depth bounds are enforced by the measuring walk, which needs
                    // the document back to report the boundary as a measured value. The parser
                    // therefore gets generous headroom and a depth failure below is always the
                    // declared one, never an opaque parser message.
                    MaxDepth = 1000,
                });

            return true;
        }
        catch (JsonException parseFailure)
        {
            failure = new JmesPathFailure(
                JmesPathFailureClass.InputNotJson,
                $"The value is not valid JSON: {JmesPathFailureClassifier.Sanitize(parseFailure.Message)}");

            return false;
        }
    }
}
