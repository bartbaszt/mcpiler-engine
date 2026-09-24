namespace MCPiler.Engine.Execution.Projection;

/// <summary>
/// The stable diagnostic vocabulary of response projection and pagination.
/// </summary>
/// <remarks>
/// A code is a contract an operator branches on; the accompanying message is prose and may be
/// reworded. Nothing here includes a refused value, and the refusal paths are the whole point:
/// what a caller is told about a header or a continuation URL must never be the value that was
/// withheld.
/// </remarks>
internal static class ResponseProjectionCodes
{
    /// <summary>A selected header was classified sensitive.</summary>
    internal const string HeaderSensitive = "response-metadata/header-sensitive";

    /// <summary>A selected header value or the consumed header bytes breached a ceiling.</summary>
    internal const string HeaderOversized = "response-metadata/header-oversized";

    /// <summary>A selected header value carried CR, LF or NUL.</summary>
    internal const string HeaderInvalidValue = "response-metadata/header-invalid-value";

    /// <summary>Pagination was configured but the upstream status is not a success.</summary>
    internal const string NonSuccessStatus = "pagination/non-success-status";

    /// <summary>The configured Link field did not follow the link grammar.</summary>
    internal const string LinkMalformed = "pagination/link-malformed";

    /// <summary>More than one usable relation candidate was present.</summary>
    internal const string LinkAmbiguousNext = "pagination/link-ambiguous-next";

    /// <summary>A candidate's anchor resolved to a different link context.</summary>
    internal const string LinkContextMismatch = "pagination/link-context-mismatch";

    /// <summary>A continuation URL pointed outside the final response origin.</summary>
    internal const string LinkCrossOrigin = "pagination/link-cross-origin";

    /// <summary>A continuation URL carried URI user-info.</summary>
    internal const string LinkCredentialsRefused = "pagination/link-credentials-refused";

    /// <summary>A continuation URL could not be resolved or represented as a request.</summary>
    internal const string UrlUnrepresentable = "pagination/url-unrepresentable";

    /// <summary>A continuation value could not be mapped into a target input argument.</summary>
    internal const string ArgumentUnmappable = "pagination/argument-unmappable";

    /// <summary>A continuation value's source is classified sensitive.</summary>
    internal const string ValueSensitive = "pagination/value-sensitive";

    /// <summary>A continuation URL or the normalized pagination object breached a ceiling.</summary>
    internal const string MetadataOversized = "pagination/metadata-oversized";
}
