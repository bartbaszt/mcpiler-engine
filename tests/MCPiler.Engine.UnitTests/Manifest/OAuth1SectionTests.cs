using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// Reader and validator checks for the OAuth 1.0a section contract: the closed v2/v4
/// configuration shape, the method-specific slot sets, and the refusal of new vocabulary
/// in older section versions.
/// </summary>
public sealed class OAuth1SectionTests
{
    [Fact]
    public void Valid_hmac_manifest_loads_with_method_specific_references()
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 2,
            credentialsVersion: 4,
            configuration: """{"consumerKey":"flickr-client","signatureMethod":"HMAC-SHA1","parameterTransport":"query"}""",
            credentials:
            """
            {"id":"consumer-secret","scheme":"oauth1-authorization","slot":"consumerSecret","value":{"fromEnv":"OAUTH1_CS"}},
            {"id":"token","scheme":"oauth1-authorization","slot":"oauthToken","value":{"fromEnv":"OAUTH1_TOKEN"}},
            {"id":"token-secret","scheme":"oauth1-authorization","slot":"oauthTokenSecret","value":{"fromEnv":"OAUTH1_TS"}}
            """,
            credentialRefs: ["consumer-secret", "token", "token-secret"])));

        Assert.True(
            result.Succeeded,
            string.Join("\n", result.Errors.Select(static diagnostic => diagnostic.ToString())));
        var profile = Assert.Single(result.Manifest!.Authentication!.Profiles);
        Assert.Equal("HMAC-SHA1", profile.Configuration["signatureMethod"]!.GetValue<string>());
        Assert.Equal("flickr-client", profile.Configuration["consumerKey"]!.GetValue<string>());
        Assert.Equal(
            ["consumer-secret", "token", "token-secret"],
            profile.CredentialRef.Select(static reference => reference).ToList());
    }

    [Fact]
    public void Valid_rsa_manifest_loads_without_a_token_secret()
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 2,
            credentialsVersion: 4,
            configuration: """{"consumerKey":"jira-client","signatureMethod":"RSA-SHA1","parameterTransport":"authorization-header"}""",
            credentials:
            """
            {"id":"private-key","scheme":"oauth1-authorization","slot":"rsaPrivateKey","value":{"fromEnv":"OAUTH1_KEY"}},
            {"id":"token","scheme":"oauth1-authorization","slot":"oauthToken","value":{"fromEnv":"OAUTH1_TOKEN"}}
            """,
            credentialRefs: ["private-key", "token"])));

        Assert.True(
            result.Succeeded,
            string.Join("\n", result.Errors.Select(static diagnostic => diagnostic.ToString())));
    }

    [Fact]
    public void Older_authentication_version_is_refused_even_with_new_vocabulary()
    {
        // Pre-1.0 sections are refused rather than migrated: producers re-export. An older
        // section carrying the new kind is therefore refused at its version gate instead of
        // being reinterpreted as the newer contract.
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 1,
            credentialsVersion: 4,
            configuration: """{"consumerKey":"client","signatureMethod":"HMAC-SHA1","parameterTransport":"query"}""",
            credentials:
            """
            {"id":"consumer-secret","scheme":"oauth1-authorization","slot":"consumerSecret","value":{"fromEnv":"OAUTH1_CS"}},
            {"id":"token","scheme":"oauth1-authorization","slot":"oauthToken","value":{"fromEnv":"OAUTH1_TOKEN"}},
            {"id":"token-secret","scheme":"oauth1-authorization","slot":"oauthTokenSecret","value":{"fromEnv":"OAUTH1_TS"}}
            """,
            credentialRefs: ["consumer-secret", "token", "token-secret"])));

        Assert.False(result.Succeeded);
        var refusal = Assert.Single(
            result.Errors,
            diagnostic => string.Equals(
                diagnostic.Code,
                ManifestDiagnosticCodes.SectionFormatVersionUnsupported,
                StringComparison.Ordinal));
        Assert.Contains("format version 1", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Older_credentials_version_is_refused_even_with_new_vocabulary()
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 2,
            credentialsVersion: 3,
            configuration: """{"consumerKey":"client","signatureMethod":"HMAC-SHA1","parameterTransport":"query"}""",
            credentials:
            """
            {"id":"consumer-secret","scheme":"oauth1-authorization","slot":"consumerSecret","value":{"fromEnv":"OAUTH1_CS"}},
            {"id":"token","scheme":"oauth1-authorization","slot":"oauthToken","value":{"fromEnv":"OAUTH1_TOKEN"}},
            {"id":"token-secret","scheme":"oauth1-authorization","slot":"oauthTokenSecret","value":{"fromEnv":"OAUTH1_TS"}}
            """,
            credentialRefs: ["consumer-secret", "token", "token-secret"])));

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            diagnostic => string.Equals(
                diagnostic.Code,
                ManifestDiagnosticCodes.SectionFormatVersionUnsupported,
                StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("HMAC-SHA9", "signatureMethod")]
    [InlineData("cookie", "parameterTransport")]
    public void Unknown_method_or_transport_is_refused_with_the_legal_set(string value, string member)
    {
        var configuration = member == "signatureMethod"
            ? $$"""{"consumerKey":"client","signatureMethod":"{{value}}","parameterTransport":"query"}"""
            : $$"""{"consumerKey":"client","signatureMethod":"HMAC-SHA1","parameterTransport":"{{value}}"}""";
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 2,
            credentialsVersion: 4,
            configuration: configuration,
            credentials:
            """
            {"id":"consumer-secret","scheme":"oauth1-authorization","slot":"consumerSecret","value":{"fromEnv":"OAUTH1_CS"}},
            {"id":"token","scheme":"oauth1-authorization","slot":"oauthToken","value":{"fromEnv":"OAUTH1_TOKEN"}},
            {"id":"token-secret","scheme":"oauth1-authorization","slot":"oauthTokenSecret","value":{"fromEnv":"OAUTH1_TS"}}
            """,
            credentialRefs: ["consumer-secret", "token", "token-secret"])));

        Assert.False(result.Succeeded);
        var refusal = Assert.Single(
            result.Errors,
            diagnostic => string.Equals(
                diagnostic.Code,
                ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                StringComparison.Ordinal));
        Assert.Contains(value, refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Platform_only_authorization_members_are_refused_as_unknown()
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 2,
            credentialsVersion: 4,
            configuration:
            """
            {"consumerKey":"client","signatureMethod":"HMAC-SHA1","parameterTransport":"query",
             "temporaryCredentialEndpoint":"https://provider.example.test/request-token"}
            """,
            credentials:
            """
            {"id":"consumer-secret","scheme":"oauth1-authorization","slot":"consumerSecret","value":{"fromEnv":"OAUTH1_CS"}},
            {"id":"token","scheme":"oauth1-authorization","slot":"oauthToken","value":{"fromEnv":"OAUTH1_TOKEN"}},
            {"id":"token-secret","scheme":"oauth1-authorization","slot":"oauthTokenSecret","value":{"fromEnv":"OAUTH1_TS"}}
            """,
            credentialRefs: ["consumer-secret", "token", "token-secret"])));

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            diagnostic => string.Equals(
                diagnostic.Code,
                ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                StringComparison.Ordinal));
    }

    [Fact]
    public void Unknown_oauth1_slot_is_refused_at_read()
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 2,
            credentialsVersion: 4,
            configuration: """{"consumerKey":"client","signatureMethod":"HMAC-SHA1","parameterTransport":"query"}""",
            credentials: """{"id":"password","scheme":"oauth1-authorization","slot":"password","value":{"fromEnv":"OAUTH1_X"}}""",
            credentialRefs: ["password"])));

        Assert.False(result.Succeeded);
        var refusal = Assert.Single(
            result.Errors,
            diagnostic => string.Equals(
                diagnostic.Code,
                ManifestDiagnosticCodes.CredentialSlotInvalid,
                StringComparison.Ordinal));
        Assert.Contains("password", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_method_slot_is_refused_at_validation()
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 2,
            credentialsVersion: 4,
            configuration: """{"consumerKey":"client","signatureMethod":"HMAC-SHA1","parameterTransport":"query"}""",
            credentials:
            """
            {"id":"consumer-secret","scheme":"oauth1-authorization","slot":"consumerSecret","value":{"fromEnv":"OAUTH1_CS"}},
            {"id":"token","scheme":"oauth1-authorization","slot":"oauthToken","value":{"fromEnv":"OAUTH1_TOKEN"}}
            """,
            credentialRefs: ["consumer-secret", "token"])));

        Assert.False(result.Succeeded);
        var refusal = Assert.Single(
            result.Errors,
            diagnostic => string.Equals(
                diagnostic.Code,
                ManifestDiagnosticCodes.AuthenticationCredentialIncompatible,
                StringComparison.Ordinal));
        Assert.Contains("oauthTokenSecret", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Unexpected_method_slot_is_refused_at_validation()
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(Document(
            authVersion: 2,
            credentialsVersion: 4,
            configuration: """{"consumerKey":"client","signatureMethod":"RSA-SHA1","parameterTransport":"authorization-header"}""",
            credentials:
            """
            {"id":"private-key","scheme":"oauth1-authorization","slot":"rsaPrivateKey","value":{"fromEnv":"OAUTH1_KEY"}},
            {"id":"token","scheme":"oauth1-authorization","slot":"oauthToken","value":{"fromEnv":"OAUTH1_TOKEN"}},
            {"id":"token-secret","scheme":"oauth1-authorization","slot":"oauthTokenSecret","value":{"fromEnv":"OAUTH1_TS"}}
            """,
            credentialRefs: ["private-key", "token", "token-secret"])));

        Assert.False(result.Succeeded);
        var refusal = Assert.Single(
            result.Errors,
            diagnostic => string.Equals(
                diagnostic.Code,
                ManifestDiagnosticCodes.AuthenticationCredentialIncompatible,
                StringComparison.Ordinal));
        Assert.Contains("oauthTokenSecret", refusal.Message, StringComparison.Ordinal);
    }

    private static string Document(
        int authVersion,
        int credentialsVersion,
        string configuration,
        string credentials,
        string[] credentialRefs)
    {
        var refs = string.Join(",", credentialRefs.Select(reference => $"\"{reference}\""));
        return $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "OAuth1 test" } },
                "policy": { "inline": { "baseUrl": "https://api.example.test", "allowedOrigins": ["https://api.example.test"] } },
                "operations": { "inline": { "operations": [{ "key": "GET /pets", "method": "GET", "path": "/pets" }] } },
                "agentSurface": { "inline": { "operations": [{ "slug": "list-pets", "name": "List pets", "binding": { "type": "http", "operation": "GET /pets", "authenticationRef": "oauth1-test" } }] } },
                "credentials": { "inline": { "formatVersion": {{credentialsVersion}}, "credentials": [{{credentials}}] } },
                "authentication": { "inline": { "formatVersion": {{authVersion}}, "profiles": [{
                  "id": "oauth1-test",
                  "kind": "oauth1-authorization",
                  "configuration": {{configuration}},
                  "authenticationOrigins": ["https://api.example.test:443"],
                  "destinationOrigins": ["https://api.example.test:443"],
                  "credentialRef": [{{refs}}],
                  "scopeFingerprint": "0000000000000000000000000000000000000000000000000000000000000001"
                }] } }
              }
            }
            """;
    }
}
