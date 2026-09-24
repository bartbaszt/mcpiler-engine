using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.ResponseCaching;

public sealed class ResponseCacheKeyTests
{
    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();

    [Fact]
    public void The_key_is_a_stable_32_byte_hmac_and_fingerprint_is_short()
    {
        ResponseCacheIdentity identity = Identity();

        ResponseCacheKey first = Derive(identity);
        ResponseCacheKey second = Derive(identity);

        Assert.Equal(32, first.Digest.Length);
        Assert.Equal(first, second);
        Assert.Equal(12, first.Fingerprint.Length);
        Assert.Equal(first.Fingerprint, second.Fingerprint);
    }

    [Fact]
    public void Length_delimiting_prevents_adjacent_field_boundary_collisions()
    {
        ResponseCacheKey first = Derive(Identity() with
        {
            OperationSlug = "ab",
            ResolvedBindingSemantics = "c",
        });
        ResponseCacheKey second = Derive(Identity() with
        {
            OperationSlug = "a",
            ResolvedBindingSemantics = "bc",
        });

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Header_names_case_and_dictionary_order_are_canonicalized_before_sorting()
    {
        ResponseCacheIdentity firstIdentity = Identity() with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["X-Trace"] = ["one"],
                ["x-trace"] = ["two"],
                ["Accept"] = ["application/json"],
            },
        };
        ResponseCacheIdentity secondIdentity = Identity() with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["accept"] = ["application/json"],
                ["x-trace"] = ["one", "two"],
            },
        };

        Assert.Equal(Derive(firstIdentity), Derive(secondIdentity));
    }

    [Fact]
    public void Repeated_header_value_order_remains_significant()
    {
        ResponseCacheIdentity first = Identity() with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["X-Trace"] = ["one", "two"],
            },
        };
        ResponseCacheIdentity second = first with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["x-trace"] = ["two", "one"],
            },
        };

        Assert.NotEqual(Derive(first), Derive(second));
    }

    [Fact]
    public void Header_name_and_value_boundaries_do_not_collide()
    {
        ResponseCacheIdentity first = Identity() with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["ab"] = ["c"],
            },
        };
        ResponseCacheIdentity second = Identity() with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["a"] = ["bc"],
            },
        };

        Assert.NotEqual(Derive(first), Derive(second));
    }

    [Fact]
    public void Every_authority_policy_and_generation_dimension_separates_keys()
    {
        ResponseCacheIdentity baseline = Identity();
        ResponseCacheKey expected = Derive(baseline);

        Assert.NotEqual(expected, Derive(baseline with { UpstreamAuthority = "authority-2" }));
        Assert.NotEqual(expected, Derive(baseline with { CallerPartition = "caller-2" }));
        Assert.NotEqual(expected, Derive(baseline with { PolicyFingerprint = "ttl=60" }));
        Assert.NotEqual(expected, Derive(baseline with { ManifestGeneration = "generation-2" }));
        Assert.NotEqual(expected, Derive(baseline with { Method = "HEAD" }));
        Assert.NotEqual(expected, Derive(baseline with { EffectiveUri = "https://api.example.test/other" }));
        Assert.NotEqual(expected, Derive(baseline with { Body = "changed"u8.ToArray() }));
    }

    [Fact]
    public void Sensitive_header_values_are_represented_by_authority_not_retained_in_key()
    {
        const string credentialCanary = "credential-canary-do-not-retain";
        ResponseCacheIdentity first = Identity() with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = [$"Bearer {credentialCanary}"],
            },
            SensitiveHeaders = ["authorization"],
            AuthorityRepresentedSensitiveHeaders = ["authorization"],
        };
        ResponseCacheIdentity second = first with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["authorization"] = ["Bearer rotated-token"],
            },
        };

        ResponseCacheKey firstKey = Derive(first);
        ResponseCacheKey secondKey = Derive(second);

        Assert.Equal(firstKey, secondKey);
        Assert.DoesNotContain(credentialCanary, Convert.ToHexStringLower(firstKey.Digest), StringComparison.Ordinal);
        Assert.DoesNotContain(credentialCanary, firstKey.Fingerprint, StringComparison.Ordinal);
        Assert.NotEqual(firstKey, Derive(first with { UpstreamAuthority = "rotated-authority" }));
    }

    [Fact]
    public void Unrepresented_sensitive_values_still_separate_keys_without_entering_key_material()
    {
        const string firstSecret = "caller-token-canary-one";
        ResponseCacheIdentity first = Identity() with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = [$"Bearer {firstSecret}"],
            },
            SensitiveHeaders = ["Authorization"],
        };
        ResponseCacheIdentity second = first with
        {
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = ["Bearer caller-token-two"],
            },
        };

        ResponseCacheKey firstKey = Derive(first);
        ResponseCacheKey secondKey = Derive(second);

        Assert.NotEqual(firstKey, secondKey);
        Assert.DoesNotContain(firstSecret, Convert.ToHexStringLower(firstKey.Digest), StringComparison.Ordinal);
    }

    [Fact]
    public void Credential_applied_headers_and_query_values_are_normalized_by_authority()
    {
        CompiledRequest compiled = new()
        {
            Method = "GET",
            Uri = new Uri("https://api.example.test/items"),
            ExactUrl = "https://api.example.test/items",
        };
        ManifestCredential bearer = new(
            "bearer",
            CredentialScheme.Bearer,
            "Authorization",
            CredentialReference.Env("unused"));

        UpstreamRequest firstBearer = CredentialApplier.Apply(compiled, [new ResolvedCredential(bearer, "token-one")]);
        UpstreamRequest secondBearer = CredentialApplier.Apply(compiled, [new ResolvedCredential(bearer, "token-two")]);

        Assert.Equal(Derive(IdentityFor(firstBearer, "stable-authority")), Derive(IdentityFor(secondBearer, "stable-authority")));
        Assert.DoesNotContain("token-one", Assert.Single(firstBearer.CacheIdentityHeaders!["Authorization"]), StringComparison.Ordinal);

        ManifestCredential queryKey = new(
            "query-key",
            CredentialScheme.ApiKey,
            "api_key",
            CredentialReference.Env("unused"),
            CredentialLocation.Query);
        UpstreamRequest firstQuery = CredentialApplier.Apply(compiled, [new ResolvedCredential(queryKey, "query-one")]);
        UpstreamRequest secondQuery = CredentialApplier.Apply(compiled, [new ResolvedCredential(queryKey, "query-two")]);

        Assert.NotEqual(firstQuery.Uri, secondQuery.Uri);
        Assert.Equal(firstQuery.CacheIdentityUri, secondQuery.CacheIdentityUri);
        Assert.DoesNotContain("query-one", firstQuery.CacheIdentityUri!.AbsoluteUri, StringComparison.Ordinal);
        Assert.NotEqual(
            Derive(IdentityFor(firstQuery, "authority-one")),
            Derive(IdentityFor(secondQuery, "authority-two")));
    }

    [Fact]
    public void Unprovable_authority_or_caller_and_streaming_body_bypass_key_creation()
    {
        Assert.Null(ResponseCacheKeyDerivation.Derive(Key, "activation", "/api", null, new ResponseCacheEpoch(0, 0), Identity() with { UpstreamAuthority = null }, 300));
        Assert.Null(ResponseCacheKeyDerivation.Derive(Key, "activation", "/api", null, new ResponseCacheEpoch(0, 0), Identity() with { CallerPartition = null }, 300));
        Assert.Null(ResponseCacheKeyDerivation.Derive(Key, "activation", "/api", null, new ResponseCacheEpoch(0, 0), Identity() with { HasStreamingBody = true }, 300));
    }

    private static ResponseCacheKey Derive(ResponseCacheIdentity identity)
        => ResponseCacheKeyDerivation.Derive(
            Key,
            "activation-1",
            "/api",
            "generation-1",
            new ResponseCacheEpoch(0, 0),
            identity,
            300)!;

    private static ResponseCacheIdentity Identity()
        => new()
        {
            ManifestGeneration = null,
            OperationSlug = "list-pets",
            ResolvedBindingSemantics = "http:binding-1",
            EffectiveHttpOperationKey = "GET /pets",
            Method = "GET",
            EffectiveUri = "https://api.example.test/pets",
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Accept"] = ["application/json"],
            },
            Body = null,
            UpstreamAuthority = "authority-1",
            CallerPartition = "caller-1",
            PolicyFingerprint = "response-cache:ttl=300",
        };

    private static ResponseCacheIdentity IdentityFor(UpstreamRequest request, string authority)
    {
        ResponseCacheRequestHeaderSnapshot headers = ResponseCacheRequestHeaders.Create(request);
        return Identity() with
        {
            EffectiveUri = (request.CacheIdentityUri ?? request.Uri).AbsoluteUri,
            Headers = headers.Headers,
            SensitiveHeaders = headers.SensitiveHeaders,
            AuthorityRepresentedSensitiveHeaders = headers.AuthorityRepresentedSensitiveHeaders,
            UpstreamAuthority = authority,
        };
    }
}
