using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Sealing;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Managed;

/// <summary>
/// Pins the managed synchronization wire fixture: the envelope shape Platform will send and
/// Engine will consume, plus the sanitized metadata shape that never contains a secret.
/// </summary>
/// <remarks>
/// The fixture is the contract between two repositories that cannot share an assembly, so it is
/// authored once, committed to both trees, and asserted here from the Engine side. The test
/// decodes every mount through the real archive reader and loads the resulting bundle with the
/// managed load options, which is what turns "the bytes parse" into "the bytes are a servable
/// generation".
/// </remarks>
public sealed class ManagedGenerationFixtureTests
{
    private const string GenerationFile = "generation-v2.json";
    private const string LegacyGenerationFile = "generation-v1.json";
    private const string MetadataFile = "expected-metadata.json";
    private const string ProviderKey = "MCPILER_OAUTH2_CLIENT_CREDENTIALS_CLIENTSECRET";

    private static string FixtureDirectory => TestRepository.Fixture("managed");

    [Fact]
    public void The_fixture_declares_the_documented_envelope()
    {
        var root = Root();

        Assert.Equal(2, root["protocolVersion"]!.GetValue<int>());
        Assert.True(root["generationId"]!.GetValue<string>().Length > 0);

        var mounts = Assert.IsType<JsonArray>(root["mounts"]);
        Assert.NotEmpty(mounts);

        foreach (var mountNode in mounts)
        {
            var mount = Assert.IsType<JsonObject>(mountNode);
            var prefix = mount["prefix"]!.GetValue<string>();

            // A prefix is a public mount path; an empty or non-rooted prefix would make two
            // mounts indistinguishable at the routing layer.
            Assert.StartsWith("/", prefix, StringComparison.Ordinal);
            Assert.NotEmpty(mount["bundle"]!.GetValue<string>());
            Assert.NotNull(mount["externalResources"]!.AsObject());
        }

        Assert.NotNull(root["secrets"]!.AsObject());
        Assert.NotNull(root["metadata"]!.AsObject());
    }

    [Fact]
    public void The_v1_fixture_is_retained_as_an_explicitly_incompatible_legacy_contract()
    {
        var legacy = JsonNode.Parse(
            File.ReadAllText(Path.Combine(FixtureDirectory, LegacyGenerationFile)))!.AsObject();

        Assert.Equal(1, legacy["protocolVersion"]!.GetValue<int>());
        foreach (var mountNode in legacy["mounts"]!.AsArray())
        {
            Assert.False(mountNode!.AsObject().ContainsKey("externalResources"));
        }
    }

    [Fact]
    public void Every_mount_decodes_to_a_loadable_managed_bundle()
    {
        var root = Root();
        var loaded = 0;

        foreach (var mountNode in root["mounts"]!.AsArray())
        {
            var mount = mountNode!.AsObject();
            var bundled = Convert.FromBase64String(mount["bundle"]!.GetValue<string>());
            var unpacked = Unpack(bundled);

            Assert.True(
                unpacked.ContainsKey("manifest.json"),
                $"Mount '{mount["prefix"]}' has no root document.");

            var sections = unpacked
                .Where(pair => !string.Equals(pair.Key, "manifest.json", StringComparison.Ordinal))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);

            var result = ManifestReader.Read(
                new InMemoryManifestSource(unpacked["manifest.json"], sections),
                ManifestLoadOptions.Default with { AllowProviderReferences = true });

            Assert.True(
                result.Succeeded,
                $"Mount '{mount["prefix"]}' did not load: "
                    + string.Join("; ", result.Errors.Select(diagnostic => diagnostic.ToString())));

            loaded++;
        }

        Assert.Equal(root["mounts"]!.AsArray().Count, loaded);
    }

    [Fact]
    public void The_fixture_carries_the_provider_keys_its_bundles_reference()
    {
        var root = Root();
        var secrets = root["secrets"]!.AsObject();
        var providerKeys = ProviderKeys();

        Assert.NotEmpty(providerKeys);

        foreach (var key in providerKeys)
        {
            Assert.True(
                secrets.ContainsKey(key),
                $"The envelope does not supply a value for provider key '{key}', so the referenced "
                    + "credential could never resolve.");
        }
    }

    [Fact]
    public void The_metadata_fixture_exposes_no_secret_value()
    {
        var metadata = JsonNode.Parse(File.ReadAllText(Path.Combine(FixtureDirectory, MetadataFile)))!.AsObject();
        var text = metadata.ToJsonString();
        var secrets = Root()["secrets"]!.AsObject();

        foreach (var (_, value) in secrets)
        {
            var secret = value!.GetValue<string>();

            Assert.DoesNotContain(
                secret,
                text,
                StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Unpacks an archive in memory through the repository's own reader. The transport archive
    /// is a format contract, so using the product reader here is what proves the fixture is a
    /// real archive rather than bytes the test itself assembled.
    /// </summary>
    private static IReadOnlyDictionary<string, ReadOnlyMemory<byte>> Unpack(byte[] archive)
    {
        var directory = Path.Combine(Path.GetTempPath(), "mcpiler-managed-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try
        {
            using var stream = new MemoryStream(archive);
            var unpacked = ManifestArchive.Unpack(stream, directory);

            Assert.True(
                unpacked.Succeeded,
                string.Join("; ", unpacked.Diagnostics.Select(diagnostic => diagnostic.ToString())));

            return Directory
                .GetFiles(directory, "*", SearchOption.AllDirectories)
                .ToDictionary(
                    path => Path.GetRelativePath(directory, path).Replace(Path.DirectorySeparatorChar, '/'),
                    path => (ReadOnlyMemory<byte>)File.ReadAllBytes(path),
                    StringComparer.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Every provider key the fixture's credentials reference.</summary>
    private static List<string> ProviderKeys()
    {
        var keys = new List<string>();

        foreach (var mountNode in Root()["mounts"]!.AsArray())
        {
            var bundled = Convert.FromBase64String(mountNode!["bundle"]!.GetValue<string>());
            var unpacked = Unpack(bundled);

            if (!unpacked.TryGetValue("manifest.json", out var rootBytes))
            {
                continue;
            }

            var manifest = JsonNode.Parse(rootBytes.Span)?.AsObject();
            var credentials = manifest?["sections"]?["credentials"]?["inline"]?["credentials"];

            if (credentials is not JsonArray entries)
            {
                continue;
            }

            foreach (var entry in entries)
            {
                if (entry?["value"]?["fromProvider"] is JsonValue provider)
                {
                    keys.Add(provider.GetValue<string>());
                }
            }
        }

        return keys;
    }

    private static JsonObject Root() =>
        JsonNode.Parse(File.ReadAllText(Path.Combine(FixtureDirectory, GenerationFile)))!.AsObject();
}

