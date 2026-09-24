using System.Globalization;
using System.Text;

namespace MCPiler.Engine.Authentication.OAuth1;

/// <summary>
/// Pair-preserving RFC 5849 canonicalization. Every operation works over ordered name/value
/// pairs; request parameters are never collapsed into a dictionary, so duplicate and empty
/// pairs survive exactly as the signature rules require.
/// </summary>
/// <remarks>
/// The rules mirror the Platform implementation member for member: cross-implementation
/// agreement is defined as equality of emitted values for the shared corpus, so the two
/// sides must not drift in encoding, ordering, or edge-case behavior.
/// </remarks>
internal static class OAuth1Canonicalizer
{
    /// <summary>
    /// Normalizes collected request parameters per RFC 5849 §3.4.1.3.2: each name and value
    /// is percent-encoded separately, pairs sort by encoded name then encoded value, and pairs
    /// join with '=' and '&amp;'.
    /// </summary>
    public static string NormalizeParameters(KeyValuePair<string, string>[] parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var encoded = parameters
            .Select(pair => (Name: Rfc3986Encode(pair.Key), Value: Rfc3986Encode(pair.Value)))
            .OrderBy(pair => pair.Name, StringComparer.Ordinal)
            .ThenBy(pair => pair.Value, StringComparer.Ordinal)
            .Select(pair => $"{pair.Name}={pair.Value}");
        return string.Join("&", encoded);
    }

    /// <summary>
    /// Builds the signature base-string URI per RFC 5849 §3.4.1.2: lowercase scheme and host,
    /// default ports omitted, an empty path canonicalized as '/'. The query and fragment never
    /// participate.
    /// </summary>
    public static string BaseStringUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri)
        {
            throw new InvalidOperationException("OAuth1 base-string URI requires an absolute request URI.");
        }
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new InvalidOperationException("OAuth1 signing refuses a request URI carrying userinfo.");
        }

        string scheme = uri.Scheme.ToLowerInvariant();
        if (scheme is not ("http" or "https"))
        {
            throw new InvalidOperationException("OAuth1 signing supports only http and https request URIs.");
        }

        var builder = new StringBuilder()
            .Append(scheme)
            .Append("://")
            .Append(uri.Host.ToLowerInvariant());
        if (!uri.IsDefaultPort)
        {
            builder.Append(':').Append(uri.Port.ToString(CultureInfo.InvariantCulture));
        }

        string path = uri.AbsolutePath;
        builder.Append(string.IsNullOrEmpty(path) ? "/" : path);
        return builder.ToString();
    }

    /// <summary>Concatenates the signature base string per RFC 5849 §3.4.1.1.</summary>
    public static string BuildSignatureBaseString(string method, string baseStringUri, string normalizedParameters)
    {
        if (string.IsNullOrEmpty(method))
        {
            throw new InvalidOperationException("OAuth1 signing requires an HTTP method.");
        }
        ArgumentNullException.ThrowIfNull(baseStringUri);
        ArgumentNullException.ThrowIfNull(normalizedParameters);

        return $"{method.ToUpperInvariant()}&{Rfc3986Encode(baseStringUri)}&{Rfc3986Encode(normalizedParameters)}";
    }

    /// <summary>
    /// Parses an application/x-www-form-urlencoded query or body into decoded pairs, preserving
    /// order, duplicates, and empty names/values. A '+' decodes to a space; malformed percent
    /// encoding fails closed rather than signing a guessed value.
    /// </summary>
    public static IReadOnlyList<KeyValuePair<string, string>> ParseFormEncodedPairs(string encoded)
    {
        ArgumentNullException.ThrowIfNull(encoded);

        var pairs = new List<KeyValuePair<string, string>>();
        if (encoded.Length == 0)
        {
            return pairs;
        }

        foreach (string part in encoded.Split('&'))
        {
            int separator = part.IndexOf('=');
            string name = separator < 0 ? part : part[..separator];
            string value = separator < 0 ? string.Empty : part[(separator + 1)..];
            pairs.Add(new KeyValuePair<string, string>(FormDecode(name), FormDecode(value)));
        }
        return pairs;
    }

    /// <summary>
    /// Parses the query component of an absolute request URI into decoded pairs. The fragment
    /// never participates in signature input.
    /// </summary>
    public static IReadOnlyList<KeyValuePair<string, string>> ParseQueryPairs(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri)
        {
            throw new InvalidOperationException("OAuth1 signing requires an absolute request URI.");
        }

        string query = uri.Query;
        if (query.Length <= 1)
        {
            return [];
        }
        return ParseFormEncodedPairs(query.TrimStart('?'));
    }

    /// <summary>
    /// Percent-encodes per RFC 5849 §3.6: everything outside unreserved
    /// (ALPHA / DIGIT / "-" / "." / "_" / "~") becomes an uppercase-hex % triplet.
    /// A space encodes as %20, never '+'.
    /// </summary>
    public static string Rfc3986Encode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var builder = new StringBuilder(value.Length);
        Span<byte> utf8 = stackalloc byte[4];
        foreach (var rune in value.EnumerateRunes())
        {
            if (IsUnreserved(rune.Value))
            {
                builder.Append((char)rune.Value);
                continue;
            }

            int length = rune.EncodeToUtf8(utf8);
            for (int i = 0; i < length; i++)
            {
                builder.Append('%').Append(utf8[i].ToString("X2", CultureInfo.InvariantCulture));
            }
        }
        return builder.ToString();
    }

    /// <summary>Serializes pairs for a query string or form body with RFC 5849 encoding.</summary>
    public static string SerializePairs(IEnumerable<KeyValuePair<string, string>> pairs)
    {
        ArgumentNullException.ThrowIfNull(pairs);

        return string.Join("&", pairs.Select(pair =>
            $"{Rfc3986Encode(pair.Key)}={Rfc3986Encode(pair.Value)}"));
    }

    /// <summary>
    /// Rejects pre-existing OAuth protocol parameters on caller-controlled input. A request
    /// that already carries oauth_* values is ambiguous about who owns them, so signing it
    /// would either overwrite caller data or sign attacker-controlled input. Only names travel
    /// into the diagnostic; values never do.
    /// </summary>
    public static void ThrowOnConflictingOAuthParameters(
        IEnumerable<KeyValuePair<string, string>> ordinaryPairs,
        string location)
    {
        string? conflict = ordinaryPairs
            .Select(pair => pair.Key)
            .FirstOrDefault(name => name.StartsWith("oauth_", StringComparison.Ordinal));
        if (conflict is not null)
        {
            throw new InvalidOperationException(
                $"OAuth1 signing refused {location}: the request already carries the OAuth protocol parameter '{conflict}'.");
        }
    }

    /// <summary>
    /// Whether a body may contribute entity-body signature parameters and accept body
    /// transport: exactly the RFC 5849 §3.4.1.3 single-part form-urlencoded entity.
    /// </summary>
    public static bool IsFormUrlEncodedContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return false;
        }
        string essence = contentType.Split(';', 2)[0].Trim();
        return string.Equals(essence, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);
    }

    private static string FormDecode(string value)
    {
        // Percent triplets decode to octets first; the octet run then decodes as UTF-8, so
        // multi-byte sequences such as %C3%A9 survive as one character rather than two.
        // Literal text accumulates as whole runs so astral-plane characters are encoded
        // together instead of surrogate by surrogate.
        var bytes = new List<byte>(value.Length);
        var literal = new StringBuilder();
        void FlushLiteral()
        {
            if (literal.Length > 0)
            {
                bytes.AddRange(Encoding.UTF8.GetBytes(literal.ToString()));
                literal.Clear();
            }
        }

        for (int i = 0; i < value.Length; i++)
        {
            char current = value[i];
            if (current == '+')
            {
                FlushLiteral();
                bytes.Add((byte)' ');
                continue;
            }
            if (current != '%')
            {
                literal.Append(current);
                continue;
            }
            if (i + 2 >= value.Length
                || !Uri.IsHexDigit(value[i + 1])
                || !Uri.IsHexDigit(value[i + 2]))
            {
                throw new InvalidOperationException("OAuth1 signing refused malformed percent encoding in request parameters.");
            }
            FlushLiteral();
            bytes.Add(Convert.ToByte(value.Substring(i + 1, 2), 16));
            i += 2;
        }
        FlushLiteral();

        try
        {
            return StrictUtf8.GetString(bytes.ToArray());
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidOperationException("OAuth1 signing refused invalid UTF-8 in request parameters.", ex);
        }
    }

    private static readonly Encoding StrictUtf8 = Encoding.GetEncoding(
        "utf-8",
        EncoderFallback.ExceptionFallback,
        DecoderFallback.ExceptionFallback);

    private static bool IsUnreserved(int value) =>
        (value >= 'A' && value <= 'Z')
        || (value >= 'a' && value <= 'z')
        || (value >= '0' && value <= '9')
        || value is '-' or '.' or '_' or '~';
}
