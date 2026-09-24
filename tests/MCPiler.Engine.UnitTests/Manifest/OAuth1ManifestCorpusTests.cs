using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.UnitTests;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>Failure-first Engine reader checks for the shared OAuth1 Manifest v2/v4 fixture.</summary>
public sealed class OAuth1ManifestCorpusTests
{
    [Fact]
    public void Fixture_pins_root_03_authentication_v2_credentials_v4_and_method_slots()
    {
        var root = Fixture();
        var sections = root["sections"]!.AsObject();
        var authentication = sections["authentication"]!["inline"]!.AsObject();
        var credentials = sections["credentials"]!["inline"]!.AsObject();

        Assert.Equal("0.3", root["manifestFormatVersion"]!.GetValue<string>());
        Assert.Equal(2, authentication["formatVersion"]!.GetValue<int>());
        Assert.Equal(4, credentials["formatVersion"]!.GetValue<int>());
        Assert.Equal(2, AuthenticationSection.FormatVersion);
        Assert.Equal(4, CredentialsSection.FormatVersion);

        var byId = credentials["credentials"]!.AsArray()
            .Select(static item => item!.AsObject())
            .ToDictionary(static item => item["id"]!.GetValue<string>(), StringComparer.Ordinal);
        var profiles = authentication["profiles"]!.AsArray().Select(static item => item!.AsObject()).ToList();
        Assert.Equal(3, profiles.Count);
        Assert.Equal(
            ["HMAC-SHA1", "RSA-SHA1", "HMAC-SHA256"],
            profiles.Select(static profile => profile["configuration"]!["signatureMethod"]!.GetValue<string>()));

        foreach (var profile in profiles)
        {
            Assert.Equal("oauth1-authorization", profile["kind"]!.GetValue<string>());
            var expectedSlots = profile["configuration"]!["signatureMethod"]!.GetValue<string>() == "RSA-SHA1"
                ? new[] { "oauthToken", "rsaPrivateKey" }
                : new[] { "consumerSecret", "oauthToken", "oauthTokenSecret" };
            var actualSlots = profile["credentialRef"]!.AsArray()
                .Select(reference => byId[reference!.GetValue<string>()]["slot"]!.GetValue<string>())
                .Order(StringComparer.Ordinal);
            Assert.Equal(expectedSlots.Order(StringComparer.Ordinal), actualSlots);
        }
    }

    [Fact]
    public void Engine_reader_loads_every_OAuth1_profile_from_its_local_fixture_copy()
    {
        var path = TestRepository.Fixture("manifests", "manifest-0.3", "oauth1-authorization", "manifest.json");
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(File.ReadAllText(path)));

        Assert.True(
            result.Succeeded,
            string.Join(Environment.NewLine, result.Errors.Select(static diagnostic => diagnostic.ToString())));
        Assert.Equal(3, result.Manifest!.Authentication!.Profiles.Count);
        Assert.Equal(
            ["HMAC-SHA1", "RSA-SHA1", "HMAC-SHA256"],
            result.Manifest.Authentication.Profiles.Select(static profile =>
                profile.Configuration["signatureMethod"]!.GetValue<string>()));
    }

    private static JsonObject Fixture()
        => JsonNode.Parse(File.ReadAllText(TestRepository.Fixture(
            "manifests", "manifest-0.3", "oauth1-authorization", "manifest.json")))!.AsObject();
}
