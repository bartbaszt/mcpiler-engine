namespace MCPiler.Engine.Authentication.Signing;

/// <summary>
/// A shared empty sensitive-name set.
/// </summary>
/// <remarks>
/// Two of the reviewed signers write a single sensitive header and no sensitive query parameter.
/// Expressing that as a shared immutable instance keeps a caller from mutating one signer's set
/// through another's property, which a per-instance collection would allow.
/// </remarks>
internal sealed class EmptySensitiveSet : IReadOnlySet<string>
{
    /// <summary>The shared instance.</summary>
    public static EmptySensitiveSet Instance { get; } = new();

    private EmptySensitiveSet()
    {
    }

    /// <inheritdoc />
    public int Count => 0;

    /// <inheritdoc />
    public bool Contains(string item) => false;

    /// <inheritdoc />
    public IEnumerator<string> GetEnumerator() => Enumerable.Empty<string>().GetEnumerator();

    /// <inheritdoc />
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

    /// <inheritdoc />
    public bool IsProperSubsetOf(IEnumerable<string> other) => other.Any();

    /// <inheritdoc />
    public bool IsProperSupersetOf(IEnumerable<string> other) => false;

    /// <inheritdoc />
    public bool IsSubsetOf(IEnumerable<string> other) => true;

    /// <inheritdoc />
    public bool IsSupersetOf(IEnumerable<string> other) => !other.Any();

    /// <inheritdoc />
    public bool Overlaps(IEnumerable<string> other) => false;

    /// <inheritdoc />
    public bool SetEquals(IEnumerable<string> other) => !other.Any();
}
