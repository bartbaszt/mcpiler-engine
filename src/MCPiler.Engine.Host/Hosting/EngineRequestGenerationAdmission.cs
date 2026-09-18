using MCPiler.Engine.Host.Mcp;

using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// The non-owning generation view made available to one admitted HTTP request.
/// </summary>
/// <remarks>
/// The middleware that created this view owns the corresponding
/// <see cref="EngineGenerationLease"/>. Consumers receive the immutable generation and resolved
/// surface they are allowed to use, but never the lease itself, so a downstream handler cannot
/// release the generation before streaming and response processing finish.
/// </remarks>
internal sealed class EngineRequestGenerationAdmission
{
    internal EngineRequestGenerationAdmission(
        string address,
        string resourceIdentity,
        EngineGeneration generation,
        SurfaceResolution resolution)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceIdentity);
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(resolution);

        Address = address;
        ResourceIdentity = resourceIdentity;
        Generation = generation;
        Resolution = resolution;
    }

    /// <summary>The canonical surface address this request reached.</summary>
    internal string Address { get; }

    /// <summary>The canonical protected-resource identity of this request's admitted address.</summary>
    internal string ResourceIdentity { get; }

    /// <summary>The immutable generation admitted for the whole request.</summary>
    internal EngineGeneration Generation { get; }

    /// <summary>The address resolution performed against <see cref="Generation"/>.</summary>
    internal SurfaceResolution Resolution { get; }

    /// <summary>
    /// Whether a stateful session configured for one HTTP resource still belongs to this request.
    /// </summary>
    internal bool MatchesSession(string address, string resourceIdentity)
        => string.Equals(Address, address, StringComparison.Ordinal)
            && string.Equals(ResourceIdentity, resourceIdentity, StringComparison.Ordinal);
}

/// <summary>Retrieves the current request's non-owning generation admission.</summary>
/// <remarks>
/// The MCP SDK invokes stateful HTTP handlers on the current request execution context when
/// per-session execution context is disabled. Looking up the feature here at invocation time
/// therefore preserves request-level admission without capturing the initialize request's
/// generation in a long-lived session handler.
/// </remarks>
internal sealed class EngineRequestGenerationAdmissionAccessor
{
    private readonly IHttpContextAccessor _httpContext;

    public EngineRequestGenerationAdmissionAccessor(IHttpContextAccessor httpContext)
    {
        _httpContext = httpContext;
    }

    /// <summary>The admission for the active HTTP request, or null outside an admitted request.</summary>
    internal EngineRequestGenerationAdmission? Current
        => _httpContext.HttpContext?.Features.Get<EngineRequestGenerationAdmission>();
}
