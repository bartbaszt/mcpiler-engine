using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Signing;
using MCPiler.Engine.Execution;
using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// Reviewed signer vectors.
/// </summary>
/// <remarks>
/// Nothing here reaches a host: signing is exercised over <see cref="SignableRequest"/>, which is
/// the whole point of the port. The vectors are the same reviewed examples the retired Platform
/// signers were pinned to, so a signature that drifts is caught as a byte difference rather than
/// as a provider rejection.
/// </remarks>
public sealed class RequestSignerTests
{
    [Fact]
    public async Task Aws_signs_the_official_s3_get_object_vector()
    {
        var signer = new AwsSigV4RequestSigner();
        var request = new SignableRequest(
            "GET",
            new Uri("https://examplebucket.s3.amazonaws.com/test.txt"),
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Range"] = ["bytes=0-9"],
            });

        await signer.SignAsync(
            request,
            new RequestSigningMaterial(
                signer.StrategyId,
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            new RequestSigningAttempt(new DateTimeOffset(2013, 5, 24, 0, 0, 0, TimeSpan.Zero), "unused"),
            TestContext.Current.CancellationToken);

        Assert.Equal("20130524T000000Z", request.Header("x-amz-date"));
        Assert.Equal(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            request.Header("x-amz-content-sha256"));
        Assert.Equal(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
                + "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
                + "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            request.Header("Authorization"));
    }

    [Theory]
    [InlineData("https://s3.wasabisys.com/bucket/key", "us-east-1")]
    [InlineData("https://s3.eu-central-1.wasabisys.com/bucket/key", "eu-central-1")]
    [InlineData("https://bucket.s3.eu-central-2.wasabisys.com/key", "eu-central-2")]
    public void Aws_region_is_derived_only_from_the_reviewed_s3_host_shape(string url, string expected)
        => Assert.Equal(expected, AwsSigV4RequestSigner.ResolveRegion(new Uri(url)));

    [Fact]
    public void Aws_refuses_a_host_it_cannot_derive_a_reviewed_region_from()
    {
        var exception = Assert.Throws<UnsupportedAuthenticationStrategyException>(
            () => AwsSigV4RequestSigner.ResolveRegion(new Uri("https://storage.example.test/key")));

        Assert.Contains("cannot derive a reviewed region", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Aws_query_and_header_order_do_not_change_the_signature()
    {
        var signer = new AwsSigV4RequestSigner();
        var material = new RequestSigningMaterial(
            signer.StrategyId,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        var attempt = new RequestSigningAttempt(
            new DateTimeOffset(2013, 5, 24, 0, 0, 0, TimeSpan.Zero),
            "unused");

        var first = new SignableRequest(
            "GET",
            new Uri("https://examplebucket.s3.amazonaws.com/test.txt?b=2&a=1"),
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["X-Second"] = ["  two   spaces "],
                ["X-First"] = ["one"],
            });

        var second = new SignableRequest(
            "GET",
            new Uri("https://examplebucket.s3.amazonaws.com/test.txt?a=1&b=2"),
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["X-First"] = ["one"],
                ["X-Second"] = ["two spaces"],
            });

        await signer.SignAsync(first, material, attempt, TestContext.Current.CancellationToken);
        await signer.SignAsync(second, material, attempt, TestContext.Current.CancellationToken);

        Assert.Equal(first.Header("Authorization"), second.Header("Authorization"));
    }

    [Fact]
    public async Task Ghost_jwt_has_the_reviewed_header_claims_lifetime_and_hmac()
    {
        const string Id = "0123456789abcdef01234567";
        const string SecretHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var now = new DateTimeOffset(2026, 9, 5, 20, 0, 0, TimeSpan.Zero);
        var signer = new JwtHmacRequestSigner();
        var request = new SignableRequest(
            "GET",
            new Uri("https://ghost.example/ghost/api/admin/site/"));

        await signer.SignAsync(
            request,
            new RequestSigningMaterial(signer.StrategyId, Id, SecretHex),
            new RequestSigningAttempt(now, "unused"),
            TestContext.Current.CancellationToken);

        var authorization = Assert.IsType<string>(request.Header("Authorization"));
        Assert.StartsWith("Ghost ", authorization, StringComparison.Ordinal);

        var segments = authorization["Ghost ".Length..].Split('.');
        Assert.Equal(3, segments.Length);

        using var header = JsonDocument.Parse(Base64UrlDecode(segments[0]));
        Assert.Equal("HS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal(Id, header.RootElement.GetProperty("kid").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());

        using var payload = JsonDocument.Parse(Base64UrlDecode(segments[1]));
        Assert.Equal(now.ToUnixTimeSeconds(), payload.RootElement.GetProperty("iat").GetInt64());
        Assert.Equal(now.ToUnixTimeSeconds() + 300, payload.RootElement.GetProperty("exp").GetInt64());
        Assert.Equal("/admin/", payload.RootElement.GetProperty("aud").GetString());

        var expected = HMACSHA256.HashData(
            Convert.FromHexString(SecretHex),
            Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]));
        Assert.Equal(expected, Base64UrlDecode(segments[2]));
    }

    [Fact]
    public async Task Ghost_refuses_a_signing_secret_that_is_not_hexadecimal_material()
    {
        var signer = new JwtHmacRequestSigner();
        var request = new SignableRequest("GET", new Uri("https://ghost.example/ghost/api/admin/site/"));

        var exception = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => signer.SignAsync(
                request,
                new RequestSigningMaterial(signer.StrategyId, "key-id", "not-hex"),
                new RequestSigningAttempt(DateTimeOffset.UnixEpoch, "unused"),
                TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("key-id", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("not-hex", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Subsonic_matches_the_documented_salted_md5_example()
    {
        var signer = new SubsonicMd5RequestSigner();
        var request = new SignableRequest(
            "GET",
            new Uri("https://music.example/rest/ping.view?extra=1"));

        await signer.SignAsync(
            request,
            new RequestSigningMaterial(signer.StrategyId, "joe", "sesame"),
            new RequestSigningAttempt(DateTimeOffset.UnixEpoch, "c19b2d"),
            TestContext.Current.CancellationToken);

        var query = ParseQuery(request.Uri);
        Assert.Equal("1", query["extra"]);
        Assert.Equal("joe", query["u"]);
        Assert.Equal("26719a1196d2a940705a59634eb18eab", query["t"]);
        Assert.Equal("c19b2d", query["s"]);
        Assert.Equal("1.16.1", query["v"]);
        Assert.Equal("MCPiler", query["c"]);
        Assert.Equal("json", query["f"]);
    }

    [Fact]
    public async Task Subsonic_drops_the_pre_existing_reserved_parameters_before_signing()
    {
        var signer = new SubsonicMd5RequestSigner();
        var request = new SignableRequest(
            "GET",
            new Uri("https://music.example/rest/ping.view?u=someone&t=stale&s=old&v=1.0&c=other&f=xml&extra=1"));

        await signer.SignAsync(
            request,
            new RequestSigningMaterial(signer.StrategyId, "joe", "sesame"),
            new RequestSigningAttempt(DateTimeOffset.UnixEpoch, "c19b2d"),
            TestContext.Current.CancellationToken);

        var query = ParseQuery(request.Uri);
        Assert.Equal("joe", query["u"]);
        Assert.Equal("c19b2d", query["s"]);
        Assert.Equal("1.16.1", query["v"]);
        Assert.Equal("MCPiler", query["c"]);
        Assert.Equal("json", query["f"]);
        Assert.Equal("1", query["extra"]);
    }

    [Fact]
    public async Task Exoscale_matches_the_independent_canonical_message_vector()
    {
        var signer = new ExoscaleHmacRequestSigner();
        var timestamp = new DateTimeOffset(2026, 9, 5, 20, 0, 0, TimeSpan.Zero);
        var body = Encoding.UTF8.GetBytes("{\"name\":\"demo\"}");
        var request = new SignableRequest(
            "POST",
            new Uri("https://api-ch-gva-2.exoscale.com/v2/servers?zone=ch-gva-2&name=demo"))
        {
            ReadBodyAsync = _ => ValueTask.FromResult(body),
        };

        await signer.SignAsync(
            request,
            new RequestSigningMaterial(signer.StrategyId, "EXOtest", "secret-value"),
            new RequestSigningAttempt(timestamp, "unused"),
            TestContext.Current.CancellationToken);

        var expires = timestamp.ToUnixTimeSeconds() + 60;
        var message = $"POST /v2/servers\n{{\"name\":\"demo\"}}\nch-gva-2demo\nzone;name\n\n{expires}";
        var signature = Convert.ToBase64String(HMACSHA256.HashData(
            Encoding.UTF8.GetBytes("secret-value"),
            Encoding.UTF8.GetBytes(message)));
        Assert.Equal(
            $"EXO2-HMAC-SHA256 credential=EXOtest,signed-query-args=zone;name,expires={expires},signature={signature}",
            request.Header("Authorization"));
    }

    [Fact]
    public async Task Exoscale_refuses_a_non_utf8_body_instead_of_signing_a_replacement()
    {
        var signer = new ExoscaleHmacRequestSigner();
        var request = new SignableRequest(
            "POST",
            new Uri("https://api-ch-gva-2.exoscale.com/v2/servers"))
        {
            ReadBodyAsync = _ => ValueTask.FromResult(new byte[] { 0xFF, 0xFE }),
        };

        await Assert.ThrowsAsync<UnsupportedAuthenticationStrategyException>(
            () => signer.SignAsync(
                request,
                new RequestSigningMaterial(signer.StrategyId, "EXOtest", "secret-value"),
                new RequestSigningAttempt(DateTimeOffset.UnixEpoch, "unused"),
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void Registry_names_every_reviewed_signer_and_refuses_an_unknown_one()
    {
        var registry = new RequestSignerRegistry(
        [
            new AwsSigV4RequestSigner(),
            new ExoscaleHmacRequestSigner(),
            new JwtHmacRequestSigner(),
            new SubsonicMd5RequestSigner(),
        ]);

        Assert.Equal(
            [
                "request-signing-aws-sigv4",
                "request-signing-hmac",
                "request-signing-jwt-hmac",
                "request-signing-subsonic-md5",
            ],
            registry.StrategyIds);

        var exception = Assert.Throws<UnsupportedAuthenticationStrategyException>(
            () => registry.Resolve(
                "profile",
                "request-signing-arbitrary",
                "key",
                "CANARY-SECRET-value",
                ["https://api.example.test"],
                TimeProvider.System));

        Assert.Contains("not installed", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-SECRET-value", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Resolved_signing_refuses_a_destination_outside_the_stored_scope()
    {
        var registry = new RequestSignerRegistry([new JwtHmacRequestSigner()]);
        var resolved = registry.Resolve(
            "profile",
            "request-signing-jwt-hmac",
            "0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ["https://api.example.test"],
            TimeProvider.System);
        var request = new SignableRequest("GET", new Uri("https://elsewhere.example.test/ping"));

        await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => resolved.SignAsync(request, resolved.CreateAttempt(), TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task A_signing_attempt_is_a_timestamp_and_a_nonce_that_survives_a_redirect()
    {
        var clock = new FixedClock(new DateTimeOffset(2026, 9, 5, 20, 0, 0, TimeSpan.Zero));
        var registry = new RequestSignerRegistry([new ExoscaleHmacRequestSigner()]);
        var resolved = registry.Resolve(
            "profile",
            "request-signing-hmac",
            "EXOtest",
            "secret-value",
            ["https://api.example.test"],
            clock);

        var first = resolved.CreateAttempt();
        var second = resolved.CreateAttempt();

        Assert.NotEqual(first.Nonce, second.Nonce);
        Assert.Equal(clock.GetUtcNow(), first.TimestampUtc);
    }

    private static Dictionary<string, string> ParseQuery(Uri uri)
        => uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .ToDictionary(
                part => Uri.UnescapeDataString(part[0]),
                part => part.Length > 1 ? Uri.UnescapeDataString(part[1]) : string.Empty,
                StringComparer.OrdinalIgnoreCase);

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
