namespace MCPiler.Engine.Execution;

/// <summary>
/// A normalized origin entry: scheme, punycode host, and port. A wildcard entry matches
/// only whole additional labels beneath a named parent domain — never the parent apex, and
/// never a different registrable domain that merely ends with the same characters.
/// </summary>
public sealed record NormalizedOrigin
{
    public required string Scheme { get; init; }

    public required string Host { get; init; }

    public required int Port { get; init; }

    public bool IsWildcard { get; init; }

    public override string ToString()
        => $"{Scheme}://{Host}:{Port}{(IsWildcard ? " (wildcard)" : string.Empty)}";
}

/// <summary>
/// The set of origins an execution may address, compiled from a manifest policy's
/// allowed-origin list. Entries are normalized to (scheme, ASCII host, port) triples at
/// construction: trailing root dots stripped, internationalized names converted to ASCII,
/// casing lowered, default ports resolved, embedded user information refused, and
/// host-form traps rejected.
/// </summary>
/// <remarks>
/// What defends against an alternative encoding of a host is not refusing the entry but
/// canonicalizing both sides. <see cref="Uri"/> rewrites every IPv4 notation and compresses
/// every IPv6 form, on the entry at construction and on the candidate in
/// <see cref="IsAllowed"/>, so an encoded spelling matches only the entry that means the
/// same address. Note that a zero-padded octet is octal, so <c>192.000.002.010</c> denotes
/// <c>192.0.2.8</c> rather than <c>192.0.2.10</c>; both spellings are addresses and neither
/// is refused, but they are not the same origin.
/// </remarks>
/// <remarks>
/// This type decides which origins may be addressed. It does not decide which resolved
/// addresses may be connected to — that is the outbound address policy, which refuses
/// private and link-local ranges regardless of what this list permits. Admitting an
/// address literal here therefore authorizes nothing on its own.
/// </remarks>
/// <remarks>
/// Behaviour is pinned by <c>tests/fixtures/http/origins.json</c>, an authored corpus the
/// Platform carries byte-identically and replays against its own implementation. The
/// corpus is the contract; neither implementation is the reference for the other.
/// </remarks>
public sealed class OriginAllowList
{
    private readonly List<NormalizedOrigin> _entries;

    public OriginAllowList(IEnumerable<string> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        _entries = entries.Select(Normalize).ToList();
    }

    public IReadOnlyList<NormalizedOrigin> Entries => _entries;

    /// <summary>
    /// True when no origin is permitted. An empty perimeter is closed: a caller that wants
    /// no restriction has to say so somewhere else rather than by supplying nothing.
    /// </summary>
    public bool IsEmpty => _entries.Count == 0;

    /// <summary>True when the absolute URI's origin matches an entry.</summary>
    public bool IsAllowed(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (!uri.IsAbsoluteUri || uri.Scheme is not ("https" or "http"))
        {
            return false;
        }

        // Embedded credentials are refused rather than ignored: ignoring them would let a
        // secret ride along to an origin that was approved without one.
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            return false;
        }

        var host = NormalizeHost(uri);
        if (host is null)
        {
            // An unusable candidate host does not match anything. It is not an error here,
            // because a target that cannot be addressed is simply outside the perimeter.
            return false;
        }

        var port = uri.IsDefaultPort ? DefaultPortFor(uri.Scheme) : uri.Port;

        foreach (var entry in _entries)
        {
            if (!string.Equals(uri.Scheme, entry.Scheme, StringComparison.OrdinalIgnoreCase)
                || port != entry.Port)
            {
                continue;
            }

            if (!entry.IsWildcard)
            {
                if (string.Equals(host, entry.Host, StringComparison.Ordinal))
                {
                    return true;
                }

                continue;
            }

            // Wildcard "*.parent": the candidate must end with ".parent" and carry at least
            // one whole label before it. The leading dot supplies the label boundary, so a
            // suffix lookalike cannot match; the length comparison excludes the apex.
            var parent = entry.Host[1..];
            if (host.Length > parent.Length && host.EndsWith(parent, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static NormalizedOrigin Normalize(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry))
        {
            throw new ArgumentException("An allowed-origin entry must not be empty.", nameof(entry));
        }

        // A wildcard host is not a parseable URI, so a synthetic label stands in for
        // parsing and the marker is restored on the normalized host afterwards.
        var isWildcard = entry.Contains("://*.", StringComparison.Ordinal);
        var parseEntry = isWildcard
            ? entry.Replace("://*.", "://wildcard.", StringComparison.Ordinal)
            : entry;

        if (!Uri.TryCreate(parseEntry, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException(
                $"Allowed-origin entry '{entry}' is not an absolute URI.", nameof(entry));
        }

        if (uri.Scheme is not ("https" or "http"))
        {
            throw new ArgumentException(
                $"Allowed-origin entry '{entry}' must use http or https.", nameof(entry));
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException(
                $"Allowed-origin entry '{entry}' must not embed user information.", nameof(entry));
        }

        var host = NormalizeHost(uri)
            ?? throw new ArgumentException(
                $"Allowed-origin entry '{entry}' has no usable host.", nameof(entry));

        if (isWildcard)
        {
            var dotIndex = host.IndexOf('.', StringComparison.Ordinal);
            if (dotIndex < 0)
            {
                throw new ArgumentException(
                    $"Allowed-origin entry '{entry}' must not place a wildcard on the apex.", nameof(entry));
            }

            var parent = host[(dotIndex + 1)..];
            if (string.IsNullOrEmpty(parent) || !parent.Contains('.', StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"Allowed-origin entry '{entry}' must not place a wildcard on the apex.", nameof(entry));
            }

            // A wildcard over an address literal would grant a range rather than a set of
            // names: "*.0.0.1" matches 1.0.0.1 through 254.0.0.1, because suffix matching
            // cannot tell a numeric label from a domain label.
            if (Uri.CheckHostName(parent) is UriHostNameType.IPv4 or UriHostNameType.IPv6)
            {
                throw new ArgumentException(
                    $"Allowed-origin entry '{entry}' must not place a wildcard over an address literal.",
                    nameof(entry));
            }

            host = "*." + parent;
        }
        else if (uri.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6))
        {
            throw new ArgumentException(
                $"Allowed-origin entry '{entry}' has no usable host.", nameof(entry));
        }

        return new NormalizedOrigin
        {
            Scheme = uri.Scheme,
            Host = host,
            Port = uri.IsDefaultPort ? DefaultPortFor(uri.Scheme) : uri.Port,
            IsWildcard = isWildcard,
        };
    }

    /// <summary>
    /// The comparable form of a host, or null when the host is not usable. Backslashes,
    /// zone identifiers and control characters are rejected because parsers disagree about
    /// where they end a host, and a disagreement about that is a disagreement about which
    /// origin was addressed.
    /// </summary>
    private static string? NormalizeHost(Uri uri)
    {
        var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();

        if (host.Length == 0
            || host.Contains('\\', StringComparison.Ordinal)
            || host.Contains('%', StringComparison.Ordinal)
            || host.Any(char.IsControl))
        {
            return null;
        }

        return host;
    }

    private static int DefaultPortFor(string scheme)
        => string.Equals(scheme, "https", StringComparison.Ordinal) ? 443 : 80;
}
