using System.Globalization;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Mcp;

/// <summary>Resolves output-schema advertisement from session and Manifest facts.</summary>
internal static class AdvertisementResolver
{
    internal const string StructuredContentRevision = "2025-06-18";

    /// <summary>
    /// <c>no</c> never advertises; <c>auto</c> follows the negotiated revision; <c>yes</c>
    /// ignores the revision. The Manifest capability is a hard ceiling over both affirmative modes.
    /// </summary>
    internal static bool Resolve(
        OutputSchemaAdvertisement mode,
        bool schemaIsModelled,
        bool manifestAllowsOutputSchemas,
        string? negotiatedRevision)
    {
        if (!schemaIsModelled || !manifestAllowsOutputSchemas)
        {
            return false;
        }

        return mode switch
        {
            OutputSchemaAdvertisement.No => false,
            OutputSchemaAdvertisement.Auto => ProtocolDefinesStructuredContent(negotiatedRevision),
            OutputSchemaAdvertisement.Yes => true,
            _ => false,
        };
    }

    /// <summary>Whether the negotiated protocol revision defines output schemas and structured content.</summary>
    internal static bool ProtocolDefinesStructuredContent(string? negotiatedRevision)
    {
        if (negotiatedRevision is null
            || !DateOnly.TryParseExact(
                negotiatedRevision,
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out DateOnly revision)
            || !DateOnly.TryParseExact(
                StructuredContentRevision,
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out DateOnly first))
        {
            return false;
        }

        return revision >= first;
    }
}
