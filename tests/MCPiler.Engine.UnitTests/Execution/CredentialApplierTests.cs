using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Where a credential goes, and which headers that makes sensitive.
/// </summary>
/// <remarks>
/// Nothing here reaches a host. The values arrive already resolved, which is what makes "this
/// scheme writes this header with this shape" assertable as a statement rather than as the
/// outcome of an exchange.
/// </remarks>
public sealed class CredentialApplierTests
{
    private const string Canary = "CANARY-4d81b7-token";

    [Fact]
    public void A_bearer_credential_writes_an_authorization_header_with_the_scheme_word()
    {
        var applied = Apply(Resolved("api", CredentialScheme.Bearer, "Authorization", Canary));

        Assert.Equal($"Bearer {Canary}", Assert.Single(applied.Headers["Authorization"]));
        Assert.DoesNotContain(Canary, Assert.Single(applied.CacheIdentityHeaders!["Authorization"]), StringComparison.Ordinal);
        Assert.Contains("Authorization", applied.AuthorityRepresentedSensitiveHeaders);

        // The deployment supplies the token, not a token plus a scheme word it has to remember.
        Assert.DoesNotContain("Bearer Bearer", applied.Headers["Authorization"][0], StringComparison.Ordinal);
    }

    [Fact]
    public void A_basic_pair_writes_one_base64_authorization_header()
    {
        var applied = Apply(
            Resolved("user", CredentialScheme.Basic, ManifestCredential.BasicUsernameSlot, "alice"),
            Resolved("pass", CredentialScheme.Basic, ManifestCredential.BasicPasswordSlot, "s3cret"));

        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:s3cret"));
        Assert.Equal($"Basic {expected}", Assert.Single(applied.Headers["Authorization"]));
    }

    [Fact]
    public void Half_a_basic_pair_is_refused_rather_than_sent_with_an_empty_half()
    {
        // A well-formed header carrying an empty password is a silently wrong credential, and
        // the upstream's answer would describe neither half.
        var failure = Assert.Throws<CredentialUnavailableException>(() => Apply(
            Resolved("user", CredentialScheme.Basic, ManifestCredential.BasicUsernameSlot, "alice")));

        Assert.Contains("incomplete", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_basic_credential_naming_neither_half_is_refused()
    {
        var failure = Assert.Throws<CredentialUnavailableException>(() => Apply(
            Resolved("user", CredentialScheme.Basic, "login", "alice")));

        Assert.Contains("login", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_header_credential_writes_the_slot_it_names()
    {
        var applied = Apply(Resolved("tenant", CredentialScheme.Header, "X-Tenant", "acme"));

        Assert.Equal("acme", Assert.Single(applied.Headers["X-Tenant"]));
    }

    [Fact]
    public void An_api_key_defaults_to_a_header()
    {
        var applied = Apply(Resolved("key", CredentialScheme.ApiKey, "X-Api-Key", Canary));

        Assert.Equal(Canary, Assert.Single(applied.Headers["X-Api-Key"]));
    }

    [Fact]
    public void An_api_key_in_the_query_is_appended_to_the_compiled_url()
    {
        var applied = Apply(
            Compiled("https://api.example.com/v1/items?page=2"),
            Resolved("key", CredentialScheme.ApiKey, "access token", "a b&c", CredentialLocation.Query));

        // Read through the escaped form: the display form unescapes, and what matters is what
        // goes on the wire. A query value carrying a delimiter must arrive as one value.
        Assert.Equal(
            "https://api.example.com/v1/items?page=2&access%20token=a%20b%26c",
            applied.Uri.AbsoluteUri);
        Assert.DoesNotContain("a%20b%26c", applied.CacheIdentityUri!.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal(
            applied.CacheIdentityUri,
            Apply(
                Compiled("https://api.example.com/v1/items?page=2"),
                Resolved("key", CredentialScheme.ApiKey, "access token", "rotated", CredentialLocation.Query)).CacheIdentityUri);

        // Nothing in the query makes a header sensitive, and the applier must not invent one.
        Assert.Empty(applied.SensitiveHeaders);
    }

    [Fact]
    public void An_api_key_in_the_query_starts_the_query_when_there_is_none()
    {
        var applied = Apply(
            Compiled("https://api.example.com/v1/items"),
            Resolved("key", CredentialScheme.ApiKey, "token", "abc", CredentialLocation.Query));

        Assert.Equal("https://api.example.com/v1/items?token=abc", applied.Uri.ToString());
    }

    [Fact]
    public void An_api_key_in_a_cookie_is_merged_into_the_compiled_cookie_header()
    {
        var compiled = Compiled(
            "https://api.example.com/v1/items",
            headers: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Cookie"] = ["locale=en"],
            });

        var applied = Apply(
            compiled,
            Resolved("session", CredentialScheme.ApiKey, "session", Canary, CredentialLocation.Cookie));

        // Merged rather than replacing: the compiled request's cookies come from declared
        // parameters and a credential cookie is an addition to them.
        Assert.Equal($"locale=en; session={Canary}", Assert.Single(applied.Headers["Cookie"]));
        Assert.DoesNotContain(Canary, Assert.Single(applied.CacheIdentityHeaders!["Cookie"]), StringComparison.Ordinal);
        Assert.Contains("Cookie", applied.SensitiveHeaders);
    }

    [Fact]
    public void Two_cookie_credentials_are_both_carried()
    {
        var applied = Apply(
            Compiled("https://api.example.com/v1/items"),
            Resolved("a", CredentialScheme.ApiKey, "one", "1", CredentialLocation.Cookie),
            Resolved("b", CredentialScheme.ApiKey, "two", "2", CredentialLocation.Cookie));

        Assert.Equal("one=1; two=2", Assert.Single(applied.Headers["Cookie"]));
    }

    [Fact]
    public void Every_credential_bearing_header_is_marked_sensitive_for_redirects()
    {
        var applied = Apply(
            Resolved("api", CredentialScheme.Bearer, "Authorization", Canary),
            Resolved("tenant", CredentialScheme.Header, "X-Tenant", "acme"),
            Resolved("key", CredentialScheme.ApiKey, "X-Api-Key", "k"));

        // Not only the well-known names. A contract may put a secret in any header it likes,
        // and marking is the only thing that keeps a configured one from crossing an origin.
        Assert.Equal(
            ["Authorization", "X-Api-Key", "X-Tenant"],
            applied.SensitiveHeaders.OrderBy(name => name, StringComparer.Ordinal).ToList());
    }

    [Fact]
    public void A_compiled_header_that_carries_no_credential_is_not_marked_sensitive()
    {
        var compiled = Compiled(
            "https://api.example.com/v1/items",
            headers: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["X-Correlation-Id"] = ["trace-1"],
            });

        var applied = Apply(compiled, Resolved("api", CredentialScheme.Bearer, "Authorization", Canary));

        Assert.Equal("trace-1", Assert.Single(applied.Headers["X-Correlation-Id"]));
        Assert.DoesNotContain("X-Correlation-Id", applied.SensitiveHeaders);
    }

    [Fact]
    public void Two_credentials_targeting_one_header_are_refused_rather_than_ordered()
    {
        // Picking a winner would make which secret reached the upstream depend on how the
        // reference list happened to be sorted.
        var failure = Assert.Throws<CredentialUnavailableException>(() => Apply(
            Resolved("first", CredentialScheme.Header, "X-Api-Key", "one"),
            Resolved("second", CredentialScheme.ApiKey, "X-Api-Key", "two")));

        Assert.Equal("second", failure.CredentialId);
        Assert.Contains("first", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Two_credentials_targeting_one_cookie_name_are_refused()
    {
        var failure = Assert.Throws<CredentialUnavailableException>(() => Apply(
            Resolved("first", CredentialScheme.ApiKey, "session", "one", CredentialLocation.Cookie),
            Resolved("second", CredentialScheme.ApiKey, "session", "two", CredentialLocation.Cookie)));

        Assert.Contains("cookie:session", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_bearer_and_a_basic_pair_contending_for_authorization_are_refused()
    {
        var failure = Assert.Throws<CredentialUnavailableException>(() => Apply(
            Resolved("api", CredentialScheme.Bearer, "Authorization", Canary),
            Resolved("user", CredentialScheme.Basic, ManifestCredential.BasicUsernameSlot, "alice"),
            Resolved("pass", CredentialScheme.Basic, ManifestCredential.BasicPasswordSlot, "s3cret")));

        Assert.Contains("Authorization", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_credential_header_overrides_a_compiled_header_of_the_same_name()
    {
        // A declared parameter and a credential can name one header. The credential is the one
        // the upstream authenticates against, so it wins — and a case difference in the
        // compiled name must not produce two headers.
        var compiled = Compiled(
            "https://api.example.com/v1/items",
            headers: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["x-api-key"] = ["from-parameter"],
            });

        var applied = Apply(compiled, Resolved("key", CredentialScheme.ApiKey, "X-Api-Key", Canary));

        Assert.Equal(Canary, Assert.Single(applied.Headers["X-Api-Key"]));
        Assert.Single(
            applied.Headers,
            entry => string.Equals(entry.Key, "X-Api-Key", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Applying_nothing_preserves_the_compiled_request()
    {
        var compiled = Compiled(
            "https://api.example.com/v1/items?page=2",
            headers: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = ["application/json"],
            },
            body: Encoding.UTF8.GetBytes("{}"),
            bodyMediaType: "application/json");

        var applied = CredentialApplier.Apply(compiled, []);

        Assert.Equal("POST", applied.Method);
        Assert.Equal(compiled.ExactUrl, applied.Uri.ToString());
        Assert.Equal("application/json", applied.BodyMediaType);
        Assert.Equal(compiled.Body, applied.Body);
        Assert.Empty(applied.SensitiveHeaders);
    }

    [Fact]
    public void The_body_and_method_are_never_altered_by_applying_a_credential()
    {
        var compiled = Compiled(
            "https://api.example.com/v1/items",
            body: Encoding.UTF8.GetBytes("payload"),
            bodyMediaType: "text/plain");

        var applied = Apply(compiled, Resolved("api", CredentialScheme.Bearer, "Authorization", Canary));

        Assert.Equal("payload", Encoding.UTF8.GetString(applied.Body!));
        Assert.Equal("text/plain", applied.BodyMediaType);
        Assert.Equal("POST", applied.Method);
    }

    private static UpstreamRequest Apply(params ResolvedCredential[] credentials)
        => Apply(Compiled("https://api.example.com/v1/items"), credentials);

    private static UpstreamRequest Apply(CompiledRequest compiled, params ResolvedCredential[] credentials)
        => CredentialApplier.Apply(compiled, credentials);

    private static CompiledRequest Compiled(
        string url,
        IReadOnlyDictionary<string, string[]>? headers = null,
        byte[]? body = null,
        string? bodyMediaType = null)
        => new()
        {
            Method = "POST",
            Uri = new Uri(url),
            ExactUrl = url,
            Headers = headers ?? new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            Body = body,
            BodyMediaType = bodyMediaType,
        };

    private static ResolvedCredential Resolved(
        string id,
        CredentialScheme scheme,
        string slot,
        string value,
        CredentialLocation? location = null)
        => new(new ManifestCredential(id, scheme, slot, CredentialReference.Env("IRRELEVANT"), location), value);
}
