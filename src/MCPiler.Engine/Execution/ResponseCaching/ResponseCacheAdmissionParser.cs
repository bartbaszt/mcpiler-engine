using System.Globalization;
using System.Text;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Execution.ResponseCaching;

internal enum ResponseCacheRequestBypassReason
{
    None,
    UnsupportedMethod,
    RangeOrConditional,
    RequestDirective,
    MalformedHeader,
}

internal sealed record ResponseCacheRequestDecision(ResponseCacheRequestBypassReason Reason)
{
    internal bool CanLookup => Reason == ResponseCacheRequestBypassReason.None;
}

internal enum ResponseCacheAdmissionReason
{
    None,
    InvalidPolicy,
    UnsupportedMethod,
    UnsuccessfulStatus,
    PartialResponse,
    Redirected,
    FileResponse,
    UnsupportedMediaType,
    ConditionalRequest,
    RequestDirective,
    MalformedRequestHeader,
    AuthenticationMetadata,
    ResponseDirective,
    UnsupportedVary,
    PublicPrivateResponse,
    MalformedFreshness,
    FreshnessExpired,
    AuthorityExpired,
}

internal sealed record ResponseCacheAdmissionDecision(
    ResponseCacheAdmissionReason Reason,
    int EffectiveTtlSeconds)
{
    internal bool CanStore => Reason == ResponseCacheAdmissionReason.None
        && EffectiveTtlSeconds >= ResponseCacheOptions.MinimumTtlSeconds;
}

internal sealed record ResponseCacheAdmissionInput(
    string Method,
    int StatusCode,
    string? MediaType,
    long BodyLength,
    IReadOnlyDictionary<string, string[]> RequestHeaders,
    IReadOnlyDictionary<string, string[]> ResponseHeaders,
    bool WasRedirected,
    bool HasFile,
    bool CallerIsSpecific,
    DateTimeOffset? AuthorityExpiresAtUtc,
    int AuthoredTtlSeconds,
    int HostMaxTtlSeconds,
    DateTimeOffset NowUtc);

/// <summary>Conservative admission rules for MCPiler's bounded response cache.</summary>
/// <remarks>
/// This is deliberately not a general HTTP cache. It recognizes only security-relevant
/// directives and freshness bounds needed by the approved cache contract. Directive parsing is
/// structural: commas inside quoted extension values do not create directives, and repeated
/// lines/values are all considered.
/// </remarks>
internal static class ResponseCacheAdmissionParser
{
    private static readonly string[] HttpDateFormats =
    [
        "ddd, dd MMM yyyy HH':'mm':'ss 'GMT'",
        "dddd, dd-MMM-yy HH':'mm':'ss 'GMT'",
        "ddd MMM d HH':'mm':'ss yyyy",
        "ddd MMM  d HH':'mm':'ss yyyy",
    ];

    private static readonly HashSet<string> NonCacheableResponseDirectives = new(StringComparer.OrdinalIgnoreCase)
    {
        "no-store",
        "no-cache",
        "must-revalidate",
        "proxy-revalidate",
        "must-understand",
    };

    private static readonly HashSet<string> AuthenticationUpdateHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "set-cookie",
        "www-authenticate",
        "proxy-authenticate",
        "authentication-info",
        "proxy-authentication-info",
    };

    internal static ResponseCacheRequestDecision CheckRequest(
        string method,
        IReadOnlyDictionary<string, string[]> headers)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(headers);

        if (!IsCacheableMethod(method))
        {
            return new ResponseCacheRequestDecision(ResponseCacheRequestBypassReason.UnsupportedMethod);
        }

        if (headers.Keys.Any(static name => string.Equals(name, "Range", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("If-", StringComparison.OrdinalIgnoreCase)))
        {
            return new ResponseCacheRequestDecision(ResponseCacheRequestBypassReason.RangeOrConditional);
        }

        if (!TryParseDirectives(headers, "Cache-Control", out List<CacheDirective> cacheControl)
            || !TryParseDirectives(headers, "Pragma", out List<CacheDirective> pragma))
        {
            return new ResponseCacheRequestDecision(ResponseCacheRequestBypassReason.MalformedHeader);
        }

        if (cacheControl.Any(static directive => directive.Name is "no-store" or "no-cache")
            || pragma.Any(static directive => directive.Name == "no-cache"))
        {
            return new ResponseCacheRequestDecision(ResponseCacheRequestBypassReason.RequestDirective);
        }

        return new ResponseCacheRequestDecision(ResponseCacheRequestBypassReason.None);
    }

    internal static ResponseCacheAdmissionDecision Evaluate(ResponseCacheAdmissionInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (input.AuthoredTtlSeconds < ResponseCacheOptions.MinimumTtlSeconds
            || input.HostMaxTtlSeconds < ResponseCacheOptions.MinimumTtlSeconds
            || input.BodyLength < 0)
        {
            return Refuse(ResponseCacheAdmissionReason.InvalidPolicy);
        }

        ResponseCacheRequestDecision requestDecision = CheckRequest(input.Method, input.RequestHeaders);
        if (!requestDecision.CanLookup)
        {
            return Refuse(requestDecision.Reason switch
            {
                ResponseCacheRequestBypassReason.UnsupportedMethod => ResponseCacheAdmissionReason.UnsupportedMethod,
                ResponseCacheRequestBypassReason.RangeOrConditional => ResponseCacheAdmissionReason.ConditionalRequest,
                ResponseCacheRequestBypassReason.RequestDirective => ResponseCacheAdmissionReason.RequestDirective,
                _ => ResponseCacheAdmissionReason.MalformedRequestHeader,
            });
        }

        if (input.StatusCode == 206)
        {
            return Refuse(ResponseCacheAdmissionReason.PartialResponse);
        }

        if (input.StatusCode is < 200 or >= 300)
        {
            return Refuse(ResponseCacheAdmissionReason.UnsuccessfulStatus);
        }

        if (input.WasRedirected)
        {
            return Refuse(ResponseCacheAdmissionReason.Redirected);
        }

        if (input.HasFile)
        {
            return Refuse(ResponseCacheAdmissionReason.FileResponse);
        }

        if (!IsEligibleMediaType(input.Method, input.MediaType, input.BodyLength))
        {
            return Refuse(ResponseCacheAdmissionReason.UnsupportedMediaType);
        }

        if (input.ResponseHeaders.Keys.Any(static name => AuthenticationUpdateHeaders.Contains(name)))
        {
            return Refuse(ResponseCacheAdmissionReason.AuthenticationMetadata);
        }

        if (!TryParseDirectives(input.ResponseHeaders, "Cache-Control", out List<CacheDirective> directives))
        {
            return Refuse(ResponseCacheAdmissionReason.MalformedFreshness);
        }

        if (directives.Any(static directive => NonCacheableResponseDirectives.Contains(directive.Name)))
        {
            return Refuse(ResponseCacheAdmissionReason.ResponseDirective);
        }

        if (directives.Any(static directive => directive.Name == "private") && !input.CallerIsSpecific)
        {
            return Refuse(ResponseCacheAdmissionReason.PublicPrivateResponse);
        }

        if (!VaryIsSupported(input.ResponseHeaders, input.RequestHeaders))
        {
            return Refuse(ResponseCacheAdmissionReason.UnsupportedVary);
        }

        if (!TryOriginFreshness(input, directives, out double? remainingFreshnessSeconds))
        {
            return Refuse(ResponseCacheAdmissionReason.MalformedFreshness);
        }

        double effectiveSeconds = Math.Min(input.AuthoredTtlSeconds, input.HostMaxTtlSeconds);

        if (remainingFreshnessSeconds is { } freshness)
        {
            if (freshness <= 0)
            {
                return Refuse(ResponseCacheAdmissionReason.FreshnessExpired);
            }

            effectiveSeconds = Math.Min(effectiveSeconds, freshness);
        }

        if (input.AuthorityExpiresAtUtc is { } authorityExpiry)
        {
            double authorityRemaining = (authorityExpiry - input.NowUtc).TotalSeconds;
            if (authorityRemaining <= 0)
            {
                return Refuse(ResponseCacheAdmissionReason.AuthorityExpired);
            }

            effectiveSeconds = Math.Min(effectiveSeconds, authorityRemaining);
        }

        int effectiveTtl = (int)Math.Floor(effectiveSeconds);
        if (effectiveTtl < ResponseCacheOptions.MinimumTtlSeconds)
        {
            return Refuse(input.AuthorityExpiresAtUtc is { } expiry && expiry > input.NowUtc
                ? ResponseCacheAdmissionReason.AuthorityExpired
                : remainingFreshnessSeconds.HasValue
                    ? ResponseCacheAdmissionReason.FreshnessExpired
                    : ResponseCacheAdmissionReason.InvalidPolicy);
        }

        return new ResponseCacheAdmissionDecision(ResponseCacheAdmissionReason.None, effectiveTtl);
    }

    private static bool IsCacheableMethod(string method)
        => string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase)
            || string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase);

    private static bool IsEligibleMediaType(string method, string? mediaType, long bodyLength)
    {
        string essence = ContentSignature.Essence(mediaType);
        if (essence.Length == 0)
        {
            return string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase) && bodyLength == 0;
        }

        if (essence == "text/event-stream")
        {
            return false;
        }

        return essence == "application/json"
            || (essence.StartsWith("application/", StringComparison.Ordinal)
                && essence.EndsWith("+json", StringComparison.Ordinal))
            || essence.StartsWith("text/", StringComparison.Ordinal);
    }

    private static bool VaryIsSupported(
        IReadOnlyDictionary<string, string[]> responseHeaders,
        IReadOnlyDictionary<string, string[]> requestHeaders)
    {
        if (!TryGetValues(responseHeaders, "Vary", out IReadOnlyList<string> varyValues))
        {
            return false;
        }

        if (varyValues.Count == 0)
        {
            return true;
        }

        foreach (string value in varyValues)
        {
            string[] names = value.Split(',');
            foreach (string candidate in names)
            {
                string name = candidate.Trim(' ', '\t');
                if (name.Length == 0 || name == "*" || !IsToken(name) || !ContainsHeader(requestHeaders, name))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool TryOriginFreshness(
        ResponseCacheAdmissionInput input,
        IReadOnlyList<CacheDirective> directives,
        out double? remainingFreshnessSeconds)
    {
        remainingFreshnessSeconds = null;

        if (!TryParseDeltaValues(directives, "max-age", out List<long> maxAges)
            || !TryParseDeltaValues(directives, "s-maxage", out List<long> sharedMaxAges)
            || !TryParseHeaderDeltaValues(input.ResponseHeaders, "Age", out List<long> ages)
            || !TryParseDateValues(input.ResponseHeaders, "Date", out List<DateTimeOffset> dates)
            || !TryParseDateValues(input.ResponseHeaders, "Expires", out List<DateTimeOffset> expiresValues))
        {
            return false;
        }

        long ageSeconds = ages.Count == 0 ? 0 : ages.Max();
        DateTimeOffset? date = dates.Count == 0 ? null : dates.Min();
        double apparentAgeSeconds = date is { } statedDate
            ? Math.Max(0, (input.NowUtc - statedDate).TotalSeconds)
            : 0;
        double currentAgeSeconds = Math.Max(ageSeconds, apparentAgeSeconds);
        List<double> bounds = [];

        foreach (long seconds in maxAges.Concat(sharedMaxAges))
        {
            bounds.Add(seconds - currentAgeSeconds);
        }

        foreach (DateTimeOffset expires in expiresValues)
        {
            double remaining = (expires - input.NowUtc).TotalSeconds;

            if (date is { } freshnessDate)
            {
                remaining = Math.Min(remaining, (expires - freshnessDate).TotalSeconds - currentAgeSeconds);
            }
            else if (ages.Count > 0)
            {
                remaining = Math.Min(remaining, remaining - ageSeconds);
            }

            bounds.Add(remaining);
        }

        if (bounds.Count > 0)
        {
            remainingFreshnessSeconds = bounds.Min();
        }

        return true;
    }

    private static bool TryParseDeltaValues(
        IReadOnlyList<CacheDirective> directives,
        string name,
        out List<long> values)
    {
        values = [];

        foreach (CacheDirective directive in directives)
        {
            if (!string.Equals(directive.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!directive.HasValue || !TryParseDeltaSeconds(directive.Value, out long seconds))
            {
                return false;
            }

            values.Add(seconds);
        }

        return true;
    }

    private static bool TryParseHeaderDeltaValues(
        IReadOnlyDictionary<string, string[]> headers,
        string name,
        out List<long> values)
    {
        values = [];
        if (!TryGetValues(headers, name, out IReadOnlyList<string> rawValues))
        {
            return false;
        }

        if (rawValues.Count == 0)
        {
            return true;
        }

        foreach (string raw in rawValues)
        {
            foreach (string value in raw.Split(','))
            {
                if (!TryParseDeltaSeconds(value.Trim(' ', '\t'), out long seconds))
                {
                    return false;
                }

                values.Add(seconds);
            }
        }

        return true;
    }

    private static bool TryParseDateValues(
        IReadOnlyDictionary<string, string[]> headers,
        string name,
        out List<DateTimeOffset> values)
    {
        values = [];
        if (!TryGetValues(headers, name, out IReadOnlyList<string> rawValues))
        {
            return false;
        }

        if (rawValues.Count == 0)
        {
            return true;
        }

        foreach (string raw in rawValues)
        {
            if (!DateTimeOffset.TryParseExact(
                    raw.Trim(' ', '\t'),
                    HttpDateFormats,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out DateTimeOffset parsed))
            {
                return false;
            }

            values.Add(parsed);
        }

        return true;
    }

    private static bool TryParseDeltaSeconds(string? value, out long seconds)
        => long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out seconds);

    private static bool TryParseDirectives(
        IReadOnlyDictionary<string, string[]> headers,
        string name,
        out List<CacheDirective> directives)
    {
        directives = [];
        if (!TryGetValues(headers, name, out IReadOnlyList<string> values))
        {
            return false;
        }

        if (values.Count == 0)
        {
            return true;
        }

        foreach (string value in values)
        {
            if (!TryParseDirectiveLine(value, directives))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryParseDirectiveLine(string value, List<CacheDirective> directives)
    {
        int index = 0;
        SkipOws(value, ref index);
        if (index == value.Length)
        {
            return false;
        }

        while (index < value.Length)
        {
            if (!ReadToken(value, ref index, out string name))
            {
                return false;
            }

            SkipOws(value, ref index);
            bool hasValue = false;
            string? directiveValue = null;
            if (index < value.Length && value[index] == '=')
            {
                hasValue = true;
                index++;
                SkipOws(value, ref index);
                if (index == value.Length)
                {
                    return false;
                }

                if (value[index] == '"')
                {
                    if (!ReadQuotedString(value, ref index, out directiveValue))
                    {
                        return false;
                    }
                }
                else if (!ReadToken(value, ref index, out directiveValue))
                {
                    return false;
                }

                SkipOws(value, ref index);
            }

            directives.Add(new CacheDirective(name.ToLowerInvariant(), directiveValue, hasValue));
            if (index == value.Length)
            {
                return true;
            }

            if (value[index] != ',')
            {
                return false;
            }

            index++;
            SkipOws(value, ref index);
            if (index == value.Length)
            {
                return false;
            }
        }

        return true;
    }

    private static bool ReadToken(string value, ref int index, out string token)
    {
        int start = index;
        while (index < value.Length && IsTokenCharacter(value[index]))
        {
            index++;
        }

        token = value[start..index];
        return token.Length > 0;
    }

    private static bool ReadQuotedString(string value, ref int index, out string unescaped)
    {
        index++;
        StringBuilder result = new();

        while (index < value.Length)
        {
            char current = value[index++];
            if (current == '"')
            {
                unescaped = result.ToString();
                return true;
            }

            if (current == '\\')
            {
                if (index == value.Length)
                {
                    unescaped = string.Empty;
                    return false;
                }

                current = value[index++];
            }

            if ((current < ' ' && current != '\t') || current == '\u007f')
            {
                unescaped = string.Empty;
                return false;
            }

            result.Append(current);
        }

        unescaped = string.Empty;
        return false;
    }

    private static bool IsToken(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (!IsTokenCharacter(character))
            {
                return false;
            }
        }

        return true;
    }

    private static void SkipOws(string value, ref int index)
    {
        while (index < value.Length && value[index] is ' ' or '\t')
        {
            index++;
        }
    }

    private static bool TryGetValues(
        IReadOnlyDictionary<string, string[]> headers,
        string name,
        out IReadOnlyList<string> values)
    {
        List<string> collected = [];
        bool found = false;
        foreach ((string headerName, string[]? headerValues) in headers)
        {
            if (!string.Equals(headerName, name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (headerValues is null)
            {
                values = [];
                return false;
            }

            found = true;
            collected.AddRange(headerValues);
        }

        values = collected;
        return !found || collected.Count > 0;
    }

    private static bool ContainsHeader(IReadOnlyDictionary<string, string[]> headers, string name)
        => headers.Keys.Any(header => string.Equals(header, name, StringComparison.OrdinalIgnoreCase));

    private static bool IsTokenCharacter(char character)
        => character is >= '0' and <= '9'
            or >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_'
            or '`' or '|' or '~';

    private static ResponseCacheAdmissionDecision Refuse(ResponseCacheAdmissionReason reason)
        => new(reason, EffectiveTtlSeconds: 0);

    private sealed record CacheDirective(string Name, string? Value, bool HasValue);
}
