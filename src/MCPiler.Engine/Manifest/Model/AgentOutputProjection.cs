using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The reviewed output policy of one agent operation: the final agent-facing
/// envelope target, explicitly selected response metadata, and an optional dedicated
/// pagination policy.
/// </summary>
/// <remarks>
/// <para>
/// This is a mirrored model rather than shared code: Engine is a separate, future-public
/// repository and must build from a standalone checkout, so the type is declared here rather
/// than referenced from the Platform. The section reader is the only producer, so the
/// vocabulary is closed here and an unknown value refuses the load instead of being ignored.
/// </para>
/// <para>
/// Absence is the legacy contract: an operation without a projection keeps its pre-change
/// bytes and result shape.
/// </para>
/// </remarks>
/// <param name="BodyTarget">Non-root RFC 6901 pointer receiving the final upstream body.</param>
/// <param name="Metadata">Explicitly selected metadata mappings.</param>
/// <param name="Pagination">The dedicated pagination policy, when one is configured.</param>
public sealed record AgentOutputProjection(
    string BodyTarget,
    IReadOnlyList<ResponseMetadataMapping> Metadata,
    PaginationPolicy? Pagination = null);

/// <summary>How many captured field values a selected response header contributes.</summary>
public enum HeaderValueMode
{
    /// <summary>The first captured value in transport order.</summary>
    First,

    /// <summary>Every captured value as an ordered array.</summary>
    All,
}

/// <summary>A selected response-metadata source.</summary>
public abstract record ResponseMetadataSource;

/// <summary>One response header selected by name.</summary>
/// <param name="Name">Canonical lower-case ASCII header name.</param>
/// <param name="ValueMode">First value or all values.</param>
public sealed record ResponseHeaderMetadataSource(string Name, HeaderValueMode ValueMode)
    : ResponseMetadataSource;

/// <summary>The numeric upstream status code.</summary>
public sealed record StatusCodeMetadataSource : ResponseMetadataSource;

/// <summary>Writes one selected source to one output pointer.</summary>
/// <param name="Source">The selected source.</param>
/// <param name="Target">RFC 6901 output pointer.</param>
public sealed record ResponseMetadataMapping(ResponseMetadataSource Source, string Target);

/// <summary>The declared scalar shape of a header-carried continuation value.</summary>
public enum PaginationScalarType
{
    /// <summary>A string cursor or token.</summary>
    String,

    /// <summary>A whole-number page or offset.</summary>
    Integer,

    /// <summary>A numeric page or offset.</summary>
    Number,

    /// <summary>A boolean continuation flag.</summary>
    Boolean,
}

/// <summary>How a JSON-pointer continuation value is interpreted.</summary>
public enum JsonPointerInterpretation
{
    /// <summary>A plain value.</summary>
    Value,

    /// <summary>A URL to resolve against the final effective response URI.</summary>
    Url,
}

/// <summary>A recognized relation in a configured Link source.</summary>
public enum PaginationRelation
{
    /// <summary>The continuation relation.</summary>
    Next,

    /// <summary>The previous-page relation.</summary>
    Prev,

    /// <summary>The first-page relation.</summary>
    First,

    /// <summary>The last-page relation.</summary>
    Last,
}

/// <summary>A pagination source from the closed vocabulary.</summary>
public abstract record PaginationSource;

/// <summary>A standards-compatible Link header source.</summary>
/// <param name="Header">Canonical lower-case ASCII header name.</param>
/// <param name="Relation">The relation inspected for continuation.</param>
public sealed record LinkHeaderPaginationSource(string Header, PaginationRelation Relation)
    : PaginationSource;

/// <summary>A continuation value carried directly in a response header.</summary>
/// <param name="Name">Canonical lower-case ASCII header name.</param>
/// <param name="ScalarType">Declared scalar shape.</param>
public sealed record ResponseHeaderPaginationSource(string Name, PaginationScalarType ScalarType)
    : PaginationSource;

/// <summary>A continuation value read from the bounded upstream JSON body.</summary>
/// <param name="Pointer">RFC 6901 pointer into the bounded upstream body.</param>
/// <param name="Interpretation">Plain value or URL.</param>
public sealed record JsonPointerPaginationSource(string Pointer, JsonPointerInterpretation Interpretation)
    : PaginationSource;

/// <summary>A closed lossless conversion into the target input argument.</summary>
public enum PaginationConversion
{
    /// <summary>A string value.</summary>
    String,

    /// <summary>A whole number.</summary>
    Integer,

    /// <summary>A number.</summary>
    Number,

    /// <summary>A boolean.</summary>
    Boolean,

    /// <summary>The JSON value unchanged; valid only for JSON-pointer sources.</summary>
    PreserveJson,
}

/// <summary>Where one next argument value comes from.</summary>
public abstract record PaginationArgumentSource;

/// <summary>The extracted continuation value itself.</summary>
public sealed record ExtractedPaginationArgument : PaginationArgumentSource;

/// <summary>A named query component of the resolved continuation URL.</summary>
/// <param name="Name">Query parameter name.</param>
public sealed record UrlQueryPaginationArgument(string Name) : PaginationArgumentSource;

/// <summary>A named path component of the resolved continuation URL.</summary>
/// <param name="Name">Path parameter name.</param>
public sealed record UrlPathPaginationArgument(string Name) : PaginationArgumentSource;

/// <summary>A reviewed value copied from the current invocation's own arguments.</summary>
/// <param name="Pointer">RFC 6901 pointer into the current input schema.</param>
public sealed record CurrentArgumentPaginationArgument(string Pointer) : PaginationArgumentSource;

/// <summary>A reviewed non-sensitive literal value.</summary>
/// <param name="Value">The constant to send, copied verbatim.</param>
public sealed record LiteralPaginationArgument(JsonNode? Value) : PaginationArgumentSource;

/// <summary>Maps one next-argument target to its reviewed source and conversion.</summary>
/// <param name="Target">RFC 6901 pointer into the target operation's input schema.</param>
/// <param name="From">Where the value comes from.</param>
/// <param name="As">The conversion applied.</param>
public sealed record PaginationArgumentMapping(
    string Target,
    PaginationArgumentSource From,
    PaginationConversion As);

/// <summary>
/// The dedicated pagination contract of one operation. It shares the response context and
/// safety policy with generic projection but remains a separate semantic object.
/// </summary>
/// <param name="Target">RFC 6901 pointer receiving the normalized pagination object.</param>
/// <param name="Source">The configured extraction source.</param>
/// <param name="NextOperation">
/// The manifest-local slug of the operation a continuation invokes, or <c>null</c> for the
/// current operation.
/// </param>
/// <param name="NextArguments">Reviewed mappings into the target operation's input schema.</param>
/// <param name="ExposeUrl">Whether the safe resolved continuation URL may be agent-visible.</param>
/// <param name="LinkRelations">Additional relations the Link source may inspect for operators.</param>
public sealed record PaginationPolicy(
    string Target,
    PaginationSource Source,
    string? NextOperation,
    IReadOnlyList<PaginationArgumentMapping> NextArguments,
    bool ExposeUrl,
    IReadOnlyList<PaginationRelation> LinkRelations);
