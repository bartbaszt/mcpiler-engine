namespace MCPiler.Engine.Execution;

/// <summary>One serialization choice, recorded so a compiled request can explain itself.</summary>
/// <remarks>
/// A request is compiled before it is sent, and the interesting failures are the ones where the bytes
/// are legal but wrong. Recording the style and explode that were actually applied — including the
/// ones resolved from a default rather than declared — is what lets a reader see why a value took the
/// shape it did.
/// </remarks>
public sealed record SerializationDecision
{
    /// <summary>The parameter this choice was made for, or <c>body</c>.</summary>
    public required string ParameterName { get; init; }

    /// <summary>Where the value was placed: <c>path</c>, <c>query</c>, <c>header</c>, <c>cookie</c>, or <c>body</c>.</summary>
    public required string Location { get; init; }

    /// <summary>The style applied, or null when the concept does not apply.</summary>
    public string? Style { get; init; }

    /// <summary>The explode flag applied, or null when the concept does not apply.</summary>
    public bool? Explode { get; init; }

    /// <summary>The value as it was written.</summary>
    public required string EncodedValue { get; init; }
}

/// <summary>A fully materialized request, inspectable before anything is sent.</summary>
public sealed record CompiledRequest
{
    /// <summary>The upper-case HTTP method.</summary>
    public required string Method { get; init; }

    /// <summary>The parsed destination.</summary>
    public required Uri Uri { get; init; }

    /// <summary>
    /// The assembled URL exactly as built.
    /// </summary>
    /// <remarks>
    /// <see cref="System.Uri.ToString"/> normalizes some escape sequences, so a byte-exact comparison
    /// has to read this rather than the parsed value. The two can disagree, and when they do the
    /// string is what the request was built to say.
    /// </remarks>
    public required string ExactUrl { get; init; }

    /// <summary>Headers to send, compared case-insensitively by name.</summary>
    public IReadOnlyDictionary<string, string[]> Headers { get; init; } = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The body bytes, or null when the request carries none.</summary>
    public byte[]? Body { get; init; }

    /// <summary>The complete media type of the body, parameters included, or null when there is no body.</summary>
    public string? BodyMediaType { get; init; }

    /// <summary>Every serialization choice made while compiling.</summary>
    public IReadOnlyList<SerializationDecision> Decisions { get; init; } = [];
}
