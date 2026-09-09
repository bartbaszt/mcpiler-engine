namespace MCPiler.Engine.Execution;

/// <summary>Raised when an argument set violates the operation's contract. Nothing is sent.</summary>
public sealed class ArgumentValidationException(string parameterName, string message)
    : Exception($"Argument '{parameterName}': {message}")
{
    /// <summary>The first offending argument. Further ones are named in the message.</summary>
    public string ParameterName { get; } = parameterName;
}

/// <summary>Raised when the governing base URL cannot be composed safely. Nothing is sent.</summary>
public sealed class InvalidBaseUrlException(string message) : Exception(message);

/// <summary>
/// Raised when a parameter declares a serialization construct this compiler does not implement.
/// </summary>
/// <remarks>
/// Compilation fails instead of degrading to a nearby shape. A silently substituted style produces a
/// legal request that means something the contract did not ask for, which is worse than a refusal
/// because nothing downstream can detect it.
/// </remarks>
public sealed class UnsupportedSerializationException(string message, string? parameterName = null)
    : Exception(message)
{
    /// <summary>The parameter that could not be serialized, when the failure names one.</summary>
    public string? ParameterName { get; } = parameterName;
}

/// <summary>Raised when a body media type cannot be compiled.</summary>
public sealed class UnsupportedBodyMediaTypeException(string mediaType, string? detail = null)
    : Exception($"Request body media type '{mediaType}' is not supported{(detail is null ? "." : $": {detail}")}")
{
    /// <summary>The media type that was selected and could not be written.</summary>
    public string MediaType { get; } = mediaType;
}
