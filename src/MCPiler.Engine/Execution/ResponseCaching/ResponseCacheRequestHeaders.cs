namespace MCPiler.Engine.Execution.ResponseCaching;

internal sealed record ResponseCacheRequestHeaderSnapshot(
    IReadOnlyDictionary<string, string[]> Headers,
    IReadOnlyCollection<string> SensitiveHeaders,
    IReadOnlyCollection<string> AuthorityRepresentedSensitiveHeaders);

/// <summary>Builds the complete, pre-send header view known to the stock Engine HTTP adapter.</summary>
internal static class ResponseCacheRequestHeaders
{
    internal static ResponseCacheRequestHeaderSnapshot Create(UpstreamRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        Dictionary<string, List<string>> mutable = new(StringComparer.OrdinalIgnoreCase);
        IReadOnlyDictionary<string, string[]> source = request.CacheIdentityHeaders ?? request.Headers;
        foreach ((string name, string[] values) in source)
        {
            if (!mutable.TryGetValue(name, out List<string>? existing))
            {
                existing = [];
                mutable.Add(name, existing);
            }

            existing.AddRange(values);
        }

        SetWhenAbsent(mutable, "User-Agent", UpstreamRequestDefaults.UserAgent);
        SetWhenAbsent(mutable, "Accept-Encoding", UpstreamRequestDefaults.AcceptEncoding);
        SetWhenAbsent(mutable, "Host", request.Uri.Authority);

        // These two content headers are not taken from HttpRequestHeaders by UpstreamSender.
        // Content-Type comes from BodyMediaType; ByteArrayContent supplies Content-Length from
        // the exact materialized bytes. A streaming source bypasses key creation separately.
        mutable.Remove("Content-Type");
        mutable.Remove("Content-Length");
        if ((request.Body is not null || request.BodySource is not null)
            && request.BodyMediaType is { Length: > 0 } mediaType)
        {
            mutable["Content-Type"] = [mediaType];
        }

        if (request.Body is { } body)
        {
            mutable["Content-Length"] = [body.LongLength.ToString(System.Globalization.CultureInfo.InvariantCulture)];
        }
        else if (request.BodySource?.Length is { } sourceLength)
        {
            mutable["Content-Length"] = [sourceLength.ToString(System.Globalization.CultureInfo.InvariantCulture)];
        }

        Dictionary<string, string[]> snapshot = new(StringComparer.OrdinalIgnoreCase);
        foreach ((string name, List<string> values) in mutable)
        {
            snapshot.Add(name, [.. values]);
        }

        HashSet<string> sensitive = new(request.SensitiveHeaders, StringComparer.OrdinalIgnoreCase)
        {
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
        };

        return new ResponseCacheRequestHeaderSnapshot(
            snapshot,
            sensitive,
            request.AuthorityRepresentedSensitiveHeaders);
    }

    private static void SetWhenAbsent(Dictionary<string, List<string>> headers, string name, string value)
    {
        if (!headers.TryGetValue(name, out List<string>? values) || values.Count == 0)
        {
            headers[name] = [value];
        }
    }
}
