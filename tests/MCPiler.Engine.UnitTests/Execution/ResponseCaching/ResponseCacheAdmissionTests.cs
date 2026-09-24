using MCPiler.Engine.Execution.ResponseCaching;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.ResponseCaching;

public sealed class ResponseCacheAdmissionTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("GET", "application/json", 2)]
    [InlineData("GET", "application/vnd.example+json; charset=utf-8", 2)]
    [InlineData("GET", "text/plain; charset=utf-8", 2)]
    [InlineData("HEAD", null, 0)]
    public void Final_successful_json_text_or_empty_head_is_admitted(
        string method,
        string? mediaType,
        long bodyLength)
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            method: method,
            mediaType: mediaType,
            bodyLength: bodyLength));

        Assert.Equal(ResponseCacheAdmissionReason.None, decision.Reason);
        Assert.Equal(300, decision.EffectiveTtlSeconds);
    }

    [Theory]
    [InlineData("POST", 200, "application/json", 2, false, false, "UnsupportedMethod")]
    [InlineData("GET", 206, "application/json", 2, false, false, "PartialResponse")]
    [InlineData("GET", 302, "application/json", 2, false, false, "UnsuccessfulStatus")]
    [InlineData("GET", 404, "application/json", 2, false, false, "UnsuccessfulStatus")]
    [InlineData("GET", 429, "application/json", 2, false, false, "UnsuccessfulStatus")]
    [InlineData("GET", 500, "application/json", 2, false, false, "UnsuccessfulStatus")]
    [InlineData("GET", 200, "text/event-stream", 2, false, false, "UnsupportedMediaType")]
    [InlineData("GET", 200, "application/octet-stream", 2, false, false, "UnsupportedMediaType")]
    [InlineData("GET", 200, "application/json", 2, true, false, "Redirected")]
    [InlineData("GET", 200, "application/json", 2, false, true, "FileResponse")]
    public void Unsafe_response_shapes_are_not_admitted(
        string method,
        int statusCode,
        string? mediaType,
        long bodyLength,
        bool wasRedirected,
        bool hasFile,
        string expected)
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            method: method,
            statusCode: statusCode,
            mediaType: mediaType,
            bodyLength: bodyLength,
            wasRedirected: wasRedirected,
            hasFile: hasFile));

        Assert.Equal(Enum.Parse<ResponseCacheAdmissionReason>(expected), decision.Reason);
        Assert.Equal(0, decision.EffectiveTtlSeconds);
    }

    [Theory]
    [InlineData("no-store")]
    [InlineData("no-cache")]
    [InlineData("must-revalidate")]
    [InlineData("proxy-revalidate")]
    [InlineData("must-understand")]
    public void Restrictive_response_directives_refuse_admission(string directive)
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            responseHeaders: Headers(("Cache-Control", $"public, {directive}"))));

        Assert.Equal(ResponseCacheAdmissionReason.ResponseDirective, decision.Reason);
    }

    [Fact]
    public void Repeated_case_varied_cache_control_lines_and_quoted_values_are_parsed_structurally()
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            responseHeaders: Headers(
                ("Cache-Control", "extension=\"opaque, no-store\", MAX-AGE=\"120\""),
                ("cache-control", "public, max-age=60"))));

        Assert.Equal(ResponseCacheAdmissionReason.None, decision.Reason);
        Assert.Equal(60, decision.EffectiveTtlSeconds);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("Accept, X-Not-Sent")]
    [InlineData("Accept,,X-Mode")]
    public void Wildcard_or_unrepresented_vary_dimensions_refuse_admission(string vary)
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            responseHeaders: Headers(("Vary", vary))));

        Assert.Equal(ResponseCacheAdmissionReason.UnsupportedVary, decision.Reason);
    }

    [Fact]
    public void Concrete_vary_dimensions_present_in_the_canonical_request_are_supported()
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            requestHeaders: Headers(("accept", "application/json"), ("X-Mode", "compact")),
            responseHeaders: Headers(("Vary", "Accept, x-mode"))));

        Assert.Equal(ResponseCacheAdmissionReason.None, decision.Reason);
    }

    [Fact]
    public void Private_response_requires_a_caller_specific_partition()
    {
        ResponseCacheAdmissionDecision publicDecision = Evaluate(Input(
            responseHeaders: Headers(("Cache-Control", "private, max-age=90"))));
        ResponseCacheAdmissionDecision protectedDecision = Evaluate(Input(
            callerIsSpecific: true,
            responseHeaders: Headers(("Cache-Control", "private, max-age=90"))));

        Assert.Equal(ResponseCacheAdmissionReason.PublicPrivateResponse, publicDecision.Reason);
        Assert.Equal(ResponseCacheAdmissionReason.None, protectedDecision.Reason);
        Assert.Equal(90, protectedDecision.EffectiveTtlSeconds);
    }

    [Theory]
    [InlineData("Set-Cookie")]
    [InlineData("WWW-Authenticate")]
    [InlineData("Proxy-Authenticate")]
    [InlineData("Authentication-Info")]
    [InlineData("Proxy-Authentication-Info")]
    public void Authentication_or_session_update_headers_refuse_admission(string name)
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            responseHeaders: Headers((name, "opaque"))));

        Assert.Equal(ResponseCacheAdmissionReason.AuthenticationMetadata, decision.Reason);
    }

    [Fact]
    public void Origin_freshness_only_shortens_authored_ttl_and_consumes_age()
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            responseHeaders: Headers(
                ("Cache-Control", "max-age=300, s-maxage=30"),
                ("Age", "20"))));

        Assert.Equal(ResponseCacheAdmissionReason.None, decision.Reason);
        Assert.Equal(10, decision.EffectiveTtlSeconds);

        ResponseCacheAdmissionDecision largerOriginBound = Evaluate(Input(
            responseHeaders: Headers(("Cache-Control", "max-age=600"))));

        Assert.Equal(300, largerOriginBound.EffectiveTtlSeconds);
    }

    [Fact]
    public void Date_age_and_expires_use_the_most_restrictive_remaining_freshness()
    {
        ResponseCacheAdmissionDecision decision = Evaluate(Input(
            responseHeaders: Headers(
                ("Date", Now.AddMinutes(-2).ToString("R")),
                ("Age", "30"),
                ("Expires", Now.AddMinutes(3).ToString("R")),
                ("Cache-Control", "max-age=300"))));

        Assert.Equal(ResponseCacheAdmissionReason.None, decision.Reason);
        Assert.Equal(180, decision.EffectiveTtlSeconds);
    }

    [Theory]
    [InlineData("max-age=300, max-age=5", null, null, 5)]
    [InlineData("max-age=30", "20", null, 10)]
    [InlineData(null, null, "Wed, 23 Sep 2026 12:01:00 GMT", 60)]
    public void Repeated_or_absolute_freshness_bounds_take_the_shortest_positive_ttl(
        string? cacheControl,
        string? age,
        string? expires,
        int expectedTtl)
    {
        Dictionary<string, string[]> responseHeaders = new(StringComparer.OrdinalIgnoreCase);
        if (cacheControl is not null)
        {
            responseHeaders["Cache-Control"] = [cacheControl];
        }

        if (age is not null)
        {
            responseHeaders["Age"] = [age];
        }

        if (expires is not null)
        {
            responseHeaders["Expires"] = [expires];
        }

        ResponseCacheAdmissionDecision decision = Evaluate(Input(responseHeaders: responseHeaders));

        Assert.Equal(ResponseCacheAdmissionReason.None, decision.Reason);
        Assert.Equal(expectedTtl, decision.EffectiveTtlSeconds);
    }

    [Theory]
    [InlineData("max-age=not-a-number", null, null)]
    [InlineData("max-age=30", "invalid-age", null)]
    [InlineData(null, null, "not-an-http-date")]
    [InlineData("max-age=30", null, "09/23/2026 12:00:00")]
    public void Malformed_stated_freshness_never_falls_back_to_authored_ttl(
        string? cacheControl,
        string? age,
        string? expires)
    {
        Dictionary<string, string[]> responseHeaders = new(StringComparer.OrdinalIgnoreCase);
        if (cacheControl is not null)
        {
            responseHeaders["Cache-Control"] = [cacheControl];
        }

        if (age is not null)
        {
            responseHeaders["Age"] = [age];
        }

        if (expires is not null)
        {
            responseHeaders["Expires"] = [expires];
        }

        ResponseCacheAdmissionDecision decision = Evaluate(Input(responseHeaders: responseHeaders));

        Assert.Equal(ResponseCacheAdmissionReason.MalformedFreshness, decision.Reason);
        Assert.Equal(0, decision.EffectiveTtlSeconds);
    }

    [Fact]
    public void Authority_expiry_caps_the_effective_ttl_and_expired_authority_bypasses()
    {
        ResponseCacheAdmissionDecision capped = Evaluate(Input(
            authorityExpiresAtUtc: Now.AddSeconds(12)));
        ResponseCacheAdmissionDecision expired = Evaluate(Input(
            authorityExpiresAtUtc: Now));

        Assert.Equal(ResponseCacheAdmissionReason.None, capped.Reason);
        Assert.Equal(12, capped.EffectiveTtlSeconds);
        Assert.Equal(ResponseCacheAdmissionReason.AuthorityExpired, expired.Reason);
    }

    [Theory]
    [InlineData("GET", "Range", "bytes=0-4", "RangeOrConditional")]
    [InlineData("GET", "If-None-Match", "\"tag\"", "RangeOrConditional")]
    [InlineData("GET", "if-modified-since", "Wed, 23 Sep 2026 11:00:00 GMT", "RangeOrConditional")]
    [InlineData("GET", "Cache-Control", "max-age=20, NO-CACHE", "RequestDirective")]
    [InlineData("GET", "Cache-Control", "no-store", "RequestDirective")]
    [InlineData("GET", "Pragma", "extension=x, no-cache", "RequestDirective")]
    [InlineData("POST", "X-Other", "value", "UnsupportedMethod")]
    public void Request_directives_and_conditionals_bypass_lookup(
        string method,
        string name,
        string value,
        string expected)
    {
        ResponseCacheRequestDecision decision = ResponseCacheAdmissionParser.CheckRequest(
            method,
            Headers((name, value)));

        Assert.Equal(Enum.Parse<ResponseCacheRequestBypassReason>(expected), decision.Reason);
    }

    [Fact]
    public void Repeated_request_headers_are_structural_and_unrelated_lookalikes_do_not_bypass()
    {
        ResponseCacheRequestDecision unrelated = ResponseCacheAdmissionParser.CheckRequest(
            "GET",
            Headers(("X-Cache-Control", "no-store"), ("X-Pragma", "no-cache")));
        ResponseCacheRequestDecision repeated = ResponseCacheAdmissionParser.CheckRequest(
            "GET",
            Headers(("Cache-Control", "max-age=20"), ("cache-control", "No-Store")));

        Assert.Equal(ResponseCacheRequestBypassReason.None, unrelated.Reason);
        Assert.Equal(ResponseCacheRequestBypassReason.RequestDirective, repeated.Reason);
    }

    private static ResponseCacheAdmissionDecision Evaluate(ResponseCacheAdmissionInput input)
        => ResponseCacheAdmissionParser.Evaluate(input);

    private static ResponseCacheAdmissionInput Input(
        string method = "GET",
        int statusCode = 200,
        string? mediaType = "application/json",
        long bodyLength = 2,
        IReadOnlyDictionary<string, string[]>? requestHeaders = null,
        IReadOnlyDictionary<string, string[]>? responseHeaders = null,
        bool wasRedirected = false,
        bool hasFile = false,
        bool callerIsSpecific = false,
        DateTimeOffset? authorityExpiresAtUtc = null)
        => new(
            method,
            statusCode,
            mediaType,
            bodyLength,
            requestHeaders ?? Headers(("Accept", "application/json")),
            responseHeaders ?? Headers(),
            wasRedirected,
            hasFile,
            callerIsSpecific,
            authorityExpiresAtUtc,
            AuthoredTtlSeconds: 300,
            HostMaxTtlSeconds: 86_400,
            NowUtc: Now);

    private static IReadOnlyDictionary<string, string[]> Headers(params (string Name, string Value)[] values)
    {
        Dictionary<string, string[]> headers = new(StringComparer.OrdinalIgnoreCase);

        foreach ((string name, string value) in values)
        {
            headers[name] = [value];
        }

        return headers;
    }
}
