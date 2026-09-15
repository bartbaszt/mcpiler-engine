using System.Text;

namespace MCPiler.Engine.Authentication.Signing;

/// <summary>
/// The transport-neutral view of a request that a signer may read and rewrite.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately mutable and deliberately small: a signer adds a header, replaces a query string,
/// or reads the payload hash, and nothing else. The type exposes no client, no socket and no
/// framework request object, so a signer cannot reach the network, and the whole signing path is
/// exercisable without one.
/// </para>
/// <para>
/// The body is read through <see cref="ReadBodyAsync"/> rather than a materialized property.
/// Most requests carry no body, so requiring one would make every signer pay for a read it does
/// not need; and a store-backed source can only be consumed once per signature, which is exactly
/// what a redirect hop does.
/// </para>
/// </remarks>
public sealed class SignableRequest
{
    private readonly Dictionary<string, string[]> _headers;

    /// <summary>Creates a signable view.</summary>
    /// <param name="method">The upper-case HTTP method.</param>
    /// <param name="uri">The absolute destination.</param>
    /// <param name="headers">The request headers, compared case-insensitively.</param>
    public SignableRequest(
        string method,
        Uri uri,
        IReadOnlyDictionary<string, string[]>? headers = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentNullException.ThrowIfNull(uri);

        Method = method;
        Uri = uri;
        _headers = headers is null
            ? new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string[]>(headers, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The upper-case HTTP method.</summary>
    public string Method { get; }

    /// <summary>The destination, which signing may rewrite only by adding query parameters.</summary>
    public Uri Uri { get; private set; }

    /// <summary>The request headers as a case-insensitive map.</summary>
    public IReadOnlyDictionary<string, string[]> Headers => _headers;

    /// <summary>
    /// Reads the whole request body, or an empty array when the request carries none.
    /// </summary>
    /// <remarks>
    /// A store-backed source is read fresh on each call, which is what a redirect chain needs: the
    /// first hop's signature and every later hop's signature must each see the same bytes.
    /// </remarks>
    public Func<CancellationToken, ValueTask<byte[]>>? ReadBodyAsync { get; init; }

    /// <summary>Replaces the value of <paramref name="name"/>, preserving its casing.</summary>
    public void SetHeader(string name, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(value);

        if (TryFindHeaderKey(name, out var key))
        {
            _headers[key] = [value];
            return;
        }

        _headers[name] = [value];
    }

    /// <summary>Removes every value of <paramref name="name"/>.</summary>
    public bool RemoveHeader(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return TryFindHeaderKey(name, out var key) && _headers.Remove(key);
    }

    /// <summary>The single value of <paramref name="name"/>, joined with <c>,</c>, or null.</summary>
    public string? Header(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return _headers.TryGetValue(name, out var values)
            ? string.Join(',', values)
            : null;
    }

    /// <summary>
    /// Replaces the query string with the supplied parameter pairs, encoding each name and value.
    /// </summary>
    /// <remarks>
    /// A signer that owns query parameters — Subsonic — rebuilds the whole query rather than
    /// editing individual members, because the signature covers the exact serialized query and a
    /// partial edit would leave the two disagreeing.
    /// </remarks>
    public void SetQuery(IEnumerable<KeyValuePair<string, string>> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var builder = new StringBuilder();
        foreach (var (name, value) in parameters)
        {
            if (builder.Length > 0)
            {
                builder.Append('&');
            }

            builder.Append(PercentEncode(name)).Append('=').Append(PercentEncode(value));
        }

        Uri = new UriBuilder(Uri) { Query = builder.ToString() }.Uri;
    }

    /// <summary>The query parameters in wire order, unescaped, excluding the leading <c>?</c>.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> QueryParameters()
    {
        if (string.IsNullOrEmpty(Uri.Query))
        {
            return [];
        }

        var parameters = new List<KeyValuePair<string, string>>();
        foreach (string part in Uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = part.IndexOf('=', StringComparison.Ordinal);
            string name = separator < 0 ? part : part[..separator];
            string value = separator < 0 ? string.Empty : part[(separator + 1)..];

            parameters.Add(new KeyValuePair<string, string>(
                Uri.UnescapeDataString(name),
                Uri.UnescapeDataString(value)));
        }

        return parameters;
    }

    private static string PercentEncode(string value) => Uri.EscapeDataString(value);

    private bool TryFindHeaderKey(string name, out string key)
    {
        key = string.Empty;

        foreach (string candidate in _headers.Keys)
        {
            if (string.Equals(candidate, name, StringComparison.OrdinalIgnoreCase))
            {
                key = candidate;
                return true;
            }
        }

        return false;
    }
}
