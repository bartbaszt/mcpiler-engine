using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth1;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// Per-hop OAuth 1.0a signing: transports, fresh hop values, redirect recomputation,
/// previous-hop stripping, caller-collision refusal, body eligibility, scope refusal, and
/// input immutability.
/// </summary>
public sealed class OAuth1HopSigningTests
{
    private const string ConsumerSecretCanary = "CANARY-oauth1-consumer-secret";
    private const string TokenSecretCanary = "CANARY-oauth1-token-secret";

    private static readonly DateTimeOffset FixedNow = new(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("authorization-header")]
    [InlineData("query")]
    [InlineData("form-body")]
    public async Task Every_transport_carries_a_complete_fresh_parameter_set(string transport)
    {
        var signing = HmacSigning(transport);
        var request = new UpstreamRequest
        {
            Method = "POST",
            Uri = new Uri("https://api.example.test/thing?extra=1", UriKind.Absolute),
            Body = Encoding.UTF8.GetBytes("ordinary=hello+world"),
            BodyMediaType = "application/x-www-form-urlencoded",
        };

        var signed = await signing.SignAsync(request, hop: 0, TestContext.Current.CancellationToken);

        var oauth = OAuthParameters(signed, transport);
        Assert.Contains("oauth_consumer_key", oauth.Keys);
        Assert.Contains("oauth_token", oauth.Keys);
        Assert.Contains("oauth_signature_method", oauth.Keys);
        Assert.Contains("oauth_timestamp", oauth.Keys);
        Assert.Contains("oauth_nonce", oauth.Keys);
        Assert.Contains("oauth_signature", oauth.Keys);
        Assert.Equal("client", oauth["oauth_consumer_key"]);
        Assert.Equal("token", oauth["oauth_token"]);
        Assert.Equal(FixedNow.ToUnixTimeSeconds().ToString(), oauth["oauth_timestamp"]);

        // The ordinary parameter rides along untouched in every transport.
        Assert.Contains("extra=1", signed.Uri.Query, StringComparison.Ordinal);
        Assert.Contains("Authorization", signed.SensitiveHeaders);
        Assert.DoesNotContain(ConsumerSecretCanary, Rendered(signed), StringComparison.Ordinal);
        Assert.DoesNotContain(TokenSecretCanary, Rendered(signed), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Two_hops_carry_distinct_nonces_and_signatures()
    {
        var signing = HmacSigning("authorization-header");
        var request = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/thing", UriKind.Absolute),
        };

        var first = await signing.SignAsync(request, hop: 0, TestContext.Current.CancellationToken);
        var second = await signing.SignAsync(request, hop: 1, TestContext.Current.CancellationToken);

        string firstNonce = HeaderValue(first, "oauth_nonce");
        string secondNonce = HeaderValue(second, "oauth_nonce");
        Assert.NotEqual(firstNonce, secondNonce);
        Assert.NotEqual(HeaderValue(first, "oauth_signature"), HeaderValue(second, "oauth_signature"));
    }

    [Fact]
    public async Task Independent_retry_starts_a_fresh_send_attempt_with_a_new_timestamp()
    {
        var signing = HmacSigning("authorization-header", new AdvancingClock(FixedNow));
        var request = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/thing", UriKind.Absolute),
        };

        var first = await signing.SignAsync(request, hop: 0, TestContext.Current.CancellationToken);
        var retry = await signing.SignAsync(request, hop: 0, TestContext.Current.CancellationToken);

        Assert.NotEqual(HeaderValue(first, "oauth_nonce"), HeaderValue(retry, "oauth_nonce"));
        Assert.NotEqual(HeaderValue(first, "oauth_timestamp"), HeaderValue(retry, "oauth_timestamp"));
        Assert.NotEqual(HeaderValue(first, "oauth_signature"), HeaderValue(retry, "oauth_signature"));
    }

    [Fact]
    public async Task A_redirected_hop_is_signed_from_the_redirected_request()
    {
        var signing = HmacSigning("authorization-header");
        var first = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/first?a=1", UriKind.Absolute),
        };
        var redirected = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/second?b=2", UriKind.Absolute),
        };

        var signedFirst = await signing.SignAsync(first, hop: 0, TestContext.Current.CancellationToken);
        var signedRedirected = await signing.SignAsync(redirected, hop: 1, TestContext.Current.CancellationToken);

        // The redirected signature covers the redirected query, not a copy of the first hop.
        Assert.NotEqual(
            HeaderValue(signedFirst, "oauth_signature"),
            HeaderValue(signedRedirected, "oauth_signature"));
        Assert.Contains("b=2", signedRedirected.Uri.Query, StringComparison.Ordinal);
        Assert.DoesNotContain("a=1", signedRedirected.Uri.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Previous_hop_oauth_values_are_stripped_and_regenerated_once()
    {
        var signing = HmacSigning("query");
        var original = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/thing?ordinary=kept", UriKind.Absolute),
        };

        var first = await signing.SignAsync(original, hop: 0, TestContext.Current.CancellationToken);
        var signed = await signing.SignAsync(first, hop: 1, TestContext.Current.CancellationToken);

        var pairs = OAuth1Canonicalizer.ParseQueryPairs(signed.Uri);
        Assert.Contains(new KeyValuePair<string, string>("ordinary", "kept"), pairs);
        Assert.Equal(1, pairs.Count(pair => pair.Key == "oauth_nonce"));
        Assert.Equal(1, pairs.Count(pair => pair.Key == "oauth_timestamp"));
        Assert.Equal(1, pairs.Count(pair => pair.Key == "oauth_signature"));
        Assert.NotEqual(
            OAuthValue(first, "oauth_nonce"),
            OAuthValue(signed, "oauth_nonce"));
        Assert.NotEqual(
            OAuthValue(first, "oauth_signature"),
            OAuthValue(signed, "oauth_signature"));
    }

    [Fact]
    public async Task A_caller_supplied_oauth_parameter_fails_the_original_request_closed()
    {
        var signing = HmacSigning("query");
        var planted = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/thing?oauth_token=planted", UriKind.Absolute),
        };

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(() => signing.SignAsync(
            planted, hop: 0, TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("oauth_token", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("planted", failure.Message, StringComparison.Ordinal);

        var bodyCollision = new UpstreamRequest
        {
            Method = "POST",
            Uri = new Uri("https://api.example.test/thing", UriKind.Absolute),
            Body = Encoding.UTF8.GetBytes("oauth_token=body-planted"),
            BodyMediaType = "application/x-www-form-urlencoded",
        };
        var bodyFailure = await Assert.ThrowsAsync<CredentialUnavailableException>(() => signing.SignAsync(
            bodyCollision, hop: 0, TestContext.Current.CancellationToken).AsTask());
        Assert.Contains("oauth_token", bodyFailure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("body-planted", bodyFailure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Body_transport_on_an_ineligible_body_fails_before_any_credential_use()
    {
        var signing = HmacSigning("form-body");
        var json = new UpstreamRequest
        {
            Method = "POST",
            Uri = new Uri("https://api.example.test/write", UriKind.Absolute),
            Body = Encoding.UTF8.GetBytes("""{"name":"demo"}"""),
            BodyMediaType = "application/json",
        };

        await Assert.ThrowsAsync<CredentialUnavailableException>(() => signing.SignAsync(
            json, hop: 0, TestContext.Current.CancellationToken).AsTask());

        var noBody = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/read", UriKind.Absolute),
        };
        await Assert.ThrowsAsync<CredentialUnavailableException>(() => signing.SignAsync(
            noBody, hop: 0, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task Preflight_validates_replayable_form_sources_before_signing_material_is_resolved()
    {
        var profile = new AuthenticationProfile(
            "profile",
            AuthenticationKind.OAuth1Authorization,
            new System.Text.Json.Nodes.JsonObject
            {
                ["consumerKey"] = "client",
                ["signatureMethod"] = "HMAC-SHA1",
                ["parameterTransport"] = "form-body",
            },
            [],
            ["https://api.example.test:443"],
            []);
        var source = new ReplayableTestSource(Encoding.UTF8.GetBytes("ordinary=one"));
        var request = new UpstreamRequest
        {
            Method = "POST",
            Uri = new Uri("https://api.example.test/write", UriKind.Absolute),
            BodySource = source,
            BodyMediaType = "application/x-www-form-urlencoded",
        };

        await ResolvedOAuth1Signing.ValidateRequestShapeAsync(
            profile,
            request,
            TestContext.Current.CancellationToken);

        Assert.Equal(1, source.Reads);

        var collidingSource = new ReplayableTestSource(Encoding.UTF8.GetBytes("oauth_token=source-owned"));
        var collision = await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            ResolvedOAuth1Signing.ValidateRequestShapeAsync(
                profile,
                request with { BodySource = collidingSource },
                TestContext.Current.CancellationToken).AsTask());
        Assert.Contains("oauth_token", collision.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("source-owned", collision.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Caller_oauth_values_in_redirect_target_and_authorization_header_fail_closed()
    {
        var querySigning = HmacSigning("query");
        var first = await querySigning.SignAsync(new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/thing", UriKind.Absolute),
        }, hop: 0, TestContext.Current.CancellationToken);

        var redirectedCollision = first with
        {
            Uri = new Uri("https://api.example.test/moved?oauth_nonce=redirect-owned", UriKind.Absolute),
        };
        var redirectFailure = await Assert.ThrowsAsync<CredentialUnavailableException>(() => querySigning.SignAsync(
            redirectedCollision, hop: 1, TestContext.Current.CancellationToken).AsTask());
        Assert.DoesNotContain("redirect-owned", redirectFailure.Message, StringComparison.Ordinal);

        var headerSigning = HmacSigning("authorization-header");
        var headerCollision = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/thing", UriKind.Absolute),
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = ["OAuth oauth_token=caller-owned"],
            },
        };
        var headerFailure = await Assert.ThrowsAsync<CredentialUnavailableException>(() => headerSigning.SignAsync(
            headerCollision, hop: 0, TestContext.Current.CancellationToken).AsTask());
        Assert.DoesNotContain("caller-owned", headerFailure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_non_form_body_is_untouched_and_unsigned_under_other_transports()
    {
        var signing = HmacSigning("authorization-header");
        byte[] body = Encoding.UTF8.GetBytes("""{"name":"demo"}""");
        var request = new UpstreamRequest
        {
            Method = "POST",
            Uri = new Uri("https://api.example.test/write", UriKind.Absolute),
            Body = body,
            BodyMediaType = "application/json",
        };

        var signed = await signing.SignAsync(request, hop: 0, TestContext.Current.CancellationToken);

        Assert.Same(body, signed.Body);
        Assert.Equal("application/json", signed.BodyMediaType);
        Assert.NotNull(signed.Headers["Authorization"]);
    }

    [Fact]
    public async Task A_hop_outside_the_profile_scope_is_refused_before_signing()
    {
        var signing = HmacSigning("authorization-header");
        var elsewhere = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://elsewhere.example.test/thing", UriKind.Absolute),
        };

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(() => signing.SignAsync(
            elsewhere, hop: 1, TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("scope", failure.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(ConsumerSecretCanary, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Signing_never_mutates_the_input_request()
    {
        var signing = HmacSigning("query");
        var request = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/thing?extra=1", UriKind.Absolute),
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
        };
        string before = request.Uri.ToString();

        var signed = await signing.SignAsync(request, hop: 0, TestContext.Current.CancellationToken);

        Assert.Equal(before, request.Uri.ToString());
        Assert.Empty(request.Headers);
        Assert.NotSame(request, signed);
        Assert.Contains("oauth_signature", signed.Uri.Query, StringComparison.Ordinal);
        Assert.Contains("oauth_signature", signed.SensitiveQueryParameters);
    }

    [Fact]
    public async Task A_request_with_both_materialized_and_replayable_bodies_fails_closed()
    {
        var signing = HmacSigning("authorization-header");
        var request = new UpstreamRequest
        {
            Method = "POST",
            Uri = new Uri("https://api.example.test/write", UriKind.Absolute),
            Body = Encoding.UTF8.GetBytes("ordinary=CANARY-materialized-value"),
            BodySource = new ReplayableTestSource(Encoding.UTF8.GetBytes("ordinary=CANARY-streamed-value")),
            BodyMediaType = "application/x-www-form-urlencoded",
        };

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(() => signing.SignAsync(
            request, hop: 0, TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("both materialized and replayable", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-materialized-value", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-streamed-value", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Unknown_method_or_transport_is_refused_at_construction()
    {
        var material = new OAuth1SigningMaterial.SharedSecretMaterial
        {
            ConsumerKey = "client",
            Token = "token",
            ConsumerSecret = "cs",
            TokenSecret = "ts",
        };
        var destinations = new OriginAllowList(["https://api.example.test"]);

        Assert.Throws<UnsupportedAuthenticationStrategyException>(() => new ResolvedOAuth1Signing(
            "profile",
            "HMAC-SHA9",
            "authorization-header",
            material,
            destinations,
            TimeProvider.System));

        Assert.Throws<UnsupportedAuthenticationStrategyException>(() => ResolvedOAuth1Signing.Create(
            new AuthenticationProfile(
                "profile",
                AuthenticationKind.OAuth1Authorization,
                new System.Text.Json.Nodes.JsonObject
                {
                    ["consumerKey"] = "client",
                    ["signatureMethod"] = "HMAC-SHA1",
                    ["parameterTransport"] = "cookie",
                },
                [],
                ["https://api.example.test:443"],
                []),
            material,
            TimeProvider.System));
    }

    private static ResolvedOAuth1Signing HmacSigning(string transport, TimeProvider? timeProvider = null)
        => new(
            "profile",
            "HMAC-SHA1",
            transport,
            new OAuth1SigningMaterial.SharedSecretMaterial
            {
                ConsumerKey = "client",
                Token = "token",
                ConsumerSecret = ConsumerSecretCanary,
                TokenSecret = TokenSecretCanary,
            },
            new OriginAllowList(["https://api.example.test"]),
            timeProvider ?? new FixedClock(FixedNow));

    private static Dictionary<string, string> OAuthParameters(UpstreamRequest signed, string transport)
    {
        if (string.Equals(transport, "authorization-header", StringComparison.Ordinal))
        {
            return ParseAuthorizationHeader(signed.Headers["Authorization"][0]);
        }

        if (string.Equals(transport, "query", StringComparison.Ordinal))
        {
            return OAuth1Canonicalizer.ParseQueryPairs(signed.Uri)
                .Where(pair => pair.Key.StartsWith("oauth_", StringComparison.Ordinal))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        }

        return OAuth1Canonicalizer.ParseFormEncodedPairs(Encoding.UTF8.GetString(signed.Body!))
            .Where(pair => pair.Key.StartsWith("oauth_", StringComparison.Ordinal))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }

    private static string HeaderValue(UpstreamRequest signed, string name)
        => ParseAuthorizationHeader(signed.Headers["Authorization"][0])[name];

    private static string OAuthValue(UpstreamRequest signed, string name)
        => OAuth1Canonicalizer.ParseQueryPairs(signed.Uri)
            .Single(pair => string.Equals(pair.Key, name, StringComparison.Ordinal))
            .Value;

    private static Dictionary<string, string> ParseAuthorizationHeader(string value)
    {
        var parameters = value.StartsWith("OAuth ", StringComparison.Ordinal)
            ? value["OAuth ".Length..]
            : value;
        return parameters.Split(',').Select(part =>
        {
            var trimmed = part.Trim();
            int separator = trimmed.IndexOf('=');
            string name = Uri.UnescapeDataString(trimmed[..separator]);
            string quoted = trimmed[(separator + 1)..].Trim();
            return new KeyValuePair<string, string>(name, Uri.UnescapeDataString(quoted[1..^1]));
        }).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }

    private static string Rendered(UpstreamRequest signed)
    {
        var builder = new StringBuilder(signed.Uri.ToString());
        foreach (var values in signed.Headers.Values)
        {
            builder.Append(string.Concat(values));
        }
        if (signed.Body is { } body)
        {
            builder.Append(Encoding.UTF8.GetString(body));
        }
        return builder.ToString();
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class AdvancingClock(DateTimeOffset start) : TimeProvider
    {
        private long _seconds = -1;

        public override DateTimeOffset GetUtcNow()
            => start.AddSeconds(Interlocked.Increment(ref _seconds));
    }

    private sealed class ReplayableTestSource(byte[] bytes) : ReplayableBodySource
    {
        public int Reads { get; private set; }

        public override long? Length => bytes.Length;

        public override ValueTask CopyToAsync(Stream destination, CancellationToken cancellationToken)
        {
            Reads++;
            return destination.WriteAsync(bytes, cancellationToken);
        }

        public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
