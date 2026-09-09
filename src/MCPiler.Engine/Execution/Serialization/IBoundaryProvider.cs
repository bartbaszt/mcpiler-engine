namespace MCPiler.Engine.Execution.Serialization;

/// <summary>
/// Supplies the delimiter that separates the parts of a multipart body.
/// </summary>
/// <remarks>
/// A multipart body is only comparable byte-for-byte if its delimiter is predictable, so the
/// delimiter is injected rather than generated in place. Serving supplies a fresh random delimiter
/// per request; a recorded-request comparison supplies a fixed one.
/// </remarks>
public interface IBoundaryProvider
{
    /// <summary>Returns the delimiter to use for one body.</summary>
    string GetBoundary();
}

/// <summary>A delimiter that never changes, so a recorded body compares as stable bytes.</summary>
public sealed class FixedBoundaryProvider(string boundary) : IBoundaryProvider
{
    /// <inheritdoc />
    public string GetBoundary() => boundary;
}

/// <summary>
/// A fresh delimiter per body, which is what serving uses.
/// </summary>
/// <remarks>
/// The delimiter must not appear inside any part payload. A random suffix makes that collision
/// negligible without inspecting the payload, which is the same trade every multipart writer makes.
/// </remarks>
public sealed class RandomBoundaryProvider : IBoundaryProvider
{
    /// <inheritdoc />
    public string GetBoundary() => $"MCPiler-{Guid.NewGuid():N}";
}
