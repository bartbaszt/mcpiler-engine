using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// Drives the hand-authored fixture corpus. The valid fixtures prove the format is
/// authorable; the hostile fixtures pin each refusal to the exact code it must produce.
/// Both sets are enumerated from disk, so a fixture cannot be added without being asserted.
/// </summary>
public sealed class FixtureCorpusTests
{
    private const string InlineSecretCanary = "CANARY-fixture-secret-must-not-appear";

    private static string CorpusRoot => TestRepository.Fixture("manifests");

    public static TheoryData<string> ValidFixtures()
    {
        var data = new TheoryData<string>();

        foreach (var name in ValidFixtureNames())
        {
            data.Add(name);
        }

        return data;
    }

    public static TheoryData<string> HostileBundles()
    {
        var data = new TheoryData<string>();

        foreach (var directory in Directory.GetDirectories(Path.Combine(CorpusRoot, "hostile", "bundle")))
        {
            data.Add(Path.GetFileName(directory));
        }

        return data;
    }

    public static TheoryData<string> HostileDocuments()
    {
        var data = new TheoryData<string>();

        foreach (var name in DocumentCases().Keys)
        {
            data.Add(name);
        }

        return data;
    }

    [Fact]
    public void CorpusContainsTheDocumentedFixtures()
    {
        var expected = new[]
        {
            "compound", "credentials", "files", "minimal", "multi-surface", "refs", "sealed-bundle", "search",
            "transformed",
        };

        Assert.Equal(expected, ValidFixtureNames());
    }

    [Theory]
    [MemberData(nameof(ValidFixtures))]
    public void ValidFixtureLoadsWithoutErrors(string fixture)
    {
        var result = ReadFixture(fixture);

        Assert.Empty(result.Errors.Select(diagnostic => diagnostic.ToString()).ToList());
        Assert.True(result.Succeeded);
        Assert.NotNull(result.Manifest);
    }

    [Theory]
    [MemberData(nameof(ValidFixtures))]
    public void ValidFixtureResolvesADefaultSurface(string fixture)
    {
        var manifest = ReadFixture(fixture).Manifest;

        Assert.NotNull(manifest);
        Assert.NotNull(manifest!.ResolveSurface(null));
    }

    [Fact]
    public void MinimalFixtureStaysUnderFortyLines()
    {
        // The acceptance target for "tens of lines, not hundreds". A manifest that cannot be
        // written by hand in one screen is not authorable outside Studio, whatever the schema says.
        var lines = File.ReadAllLines(Path.Combine(CorpusRoot, "minimal", "manifest.json"));

        Assert.True(lines.Length < 40, $"minimal/manifest.json has grown to {lines.Length} lines.");
    }

    [Fact]
    public void MinimalFixtureSynthesizesTheDefaultSurface()
    {
        var manifest = ReadFixture("minimal").Manifest;

        Assert.NotNull(manifest);

        var surface = manifest!.ResolveSurface(null);

        Assert.NotNull(surface);
        Assert.Equal("default", surface!.Slug);
        Assert.True(surface.IsDefault);
        Assert.Equal(OperationExposure.Direct, surface.ExposureOf("list-pets"));
        Assert.False(surface.EffectiveNavigator.Enabled);
    }

    [Fact]
    public void SealedBundleVerifiesEverySectionAndTheIndex()
    {
        var result = ReadFixture("sealed-bundle", ManifestLoadOptions.Default with { RequireSealed = true });

        Assert.Empty(result.Errors.Select(diagnostic => diagnostic.ToString()).ToList());
        Assert.NotNull(result.Manifest);
        Assert.True(result.Manifest!.IsSealed);
        Assert.DoesNotContain(
            result.Diagnostics,
            diagnostic => string.Equals(diagnostic.Code, ManifestDiagnosticCodes.Unsealed, System.StringComparison.Ordinal));
    }

    [Fact]
    public void UnsealedFixtureIsReportedButStillLoads()
    {
        var result = ReadFixture("minimal");

        Assert.True(result.Succeeded);
        Assert.Contains(
            result.Warnings,
            diagnostic => string.Equals(diagnostic.Code, ManifestDiagnosticCodes.Unsealed, System.StringComparison.Ordinal));
    }

    [Fact]
    public void UnsealedFixtureIsRefusedWhenSealingIsRequired()
    {
        var result = ReadFixture("minimal", ManifestLoadOptions.Default with { RequireSealed = true });

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            diagnostic => string.Equals(diagnostic.Code, ManifestDiagnosticCodes.SealRequired, System.StringComparison.Ordinal));
    }

    [Fact]
    public void MultiSurfaceFixtureKeepsExposurePerSurface()
    {
        var manifest = ReadFixture("multi-surface").Manifest;

        Assert.NotNull(manifest);

        var full = manifest!.Server.Surface("default");
        var readOnly = manifest.Server.Surface("read-only");

        Assert.NotNull(full);
        Assert.NotNull(readOnly);

        // The same operation is reachable on one surface and refused on the other. That is the
        // whole point of the exposure list being per surface rather than a property of the operation.
        Assert.True(full!.InvocationAllowed("delete-pet"));
        Assert.False(readOnly!.InvocationAllowed("delete-pet"));
        Assert.Equal(OperationExposure.Navigator, full.ExposureOf("delete-pet"));
        Assert.Equal(OperationExposure.Hidden, readOnly.ExposureOf("delete-pet"));
        Assert.Equal(["pets.read"], readOnly.RequiredScopes);
    }

    [Fact]
    public void RefsFixtureResolvesSharedAndSelfReferentialComponents()
    {
        var manifest = ReadFixture("refs").Manifest;

        Assert.NotNull(manifest);
        Assert.NotNull(manifest!.OperationsDocument);

        var resolver = new SchemaReferenceResolver(manifest.OperationsDocument!, manifest.Policy.EffectiveSchemaBounds);
        var operation = manifest.Operations.Operation("POST /nodes");

        Assert.NotNull(operation);

        var body = operation!.RequestBody!.Content["application/json"].Schema;

        Assert.NotNull(body);
        Assert.True(body!.IsReference);
        Assert.True(resolver.TryResolve(body, out var resolved, out var failure));
        Assert.Null(failure);
        Assert.Equal("object", resolved.Type);

        // A self-referential component must validate. Charging it once per referenced component
        // rather than once per use site is what keeps a recursive tree type legal.
        Assert.Empty(resolver.Validate(body, "operations", "/operations/0").ToList());
    }

    [Fact]
    public void CompoundFixtureExposesStepsThroughTheDispatcher()
    {
        var manifest = ReadFixture("compound").Manifest;

        Assert.NotNull(manifest);

        var workflow = manifest!.AgentSurface.Operation("place-order");

        Assert.NotNull(workflow);
        Assert.Equal(AgentOperationKind.Compound, workflow!.EffectiveKind);
        var steps = ManifestBindingDispatcher.TryResolveCompoundSteps(workflow.Binding);

        Assert.NotNull(steps);
        Assert.Equal(["cart", "item", "order"], steps!.Select(step => step.StepId).ToList());
    }

    [Fact]
    public void CredentialsFixtureCarriesReferencesOnly()
    {
        var manifest = ReadFixture("credentials").Manifest;

        Assert.NotNull(manifest);

        var credentials = manifest!.EffectiveCredentials.Credentials;

        Assert.Equal(6, credentials.Count);
        Assert.All(credentials, credential => Assert.False(credential.Value.IsInline));
        Assert.Contains(credentials, credential => credential.Scheme == CredentialScheme.Basic);
        Assert.Contains(credentials, credential => credential.Scheme == CredentialScheme.ApiKey);
        Assert.Contains(credentials, credential => credential.Scheme == CredentialScheme.Header);
        Assert.Contains(
            credentials,
            credential => credential.Scheme == CredentialScheme.ApiKey && credential.EffectiveLocation == CredentialLocation.Query);
    }

    [Theory]
    [MemberData(nameof(HostileBundles))]
    public void HostileBundleProducesItsPinnedCode(string bundle)
    {
        var directory = Path.Combine(CorpusRoot, "hostile", "bundle", bundle);
        var expected = ReadExpectation(Path.Combine(directory, "expected.json"));

        var result = ManifestReader.Read(new DirectoryManifestSource(directory));

        Assert.False(result.Succeeded, $"{bundle} was expected to be refused.");
        Assert.Contains(
            result.Errors,
            diagnostic => string.Equals(diagnostic.Code, expected, System.StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(HostileDocuments))]
    public void HostileDocumentProducesItsPinnedCode(string name)
    {
        var (expected, document) = DocumentCases()[name];

        var result = ManifestReader.Read(InMemoryManifestSource.FromText(document));

        Assert.False(result.Succeeded, $"{name} was expected to be refused.");
        Assert.Contains(
            result.Errors,
            diagnostic => string.Equals(diagnostic.Code, expected, System.StringComparison.Ordinal));
    }

    [Fact]
    public void EveryHostileCodeIsAKnownDiagnosticCode()
    {
        var codes = HostileCodes();

        Assert.NotEmpty(codes);
        Assert.All(codes, code => Assert.Contains(code, ManifestDiagnosticCodes.All));
    }

    [Fact]
    public void HostileCorpusCoversEveryDiagnosticGroup()
    {
        // A group with no hostile fixture is a group whose refusals are only asserted by
        // hand-written unit tests, which drift from the format far more easily than a corpus does.
        var covered = HostileCodes()
            .Concat([ManifestDiagnosticCodes.SchemaBoundExceeded])
            .Select(code => code.Split('/')[0])
            .ToHashSet(System.StringComparer.Ordinal);

        var expected = new[]
        {
            "manifest", "schema", "operations", "agent", "binding", "surface", "policy", "credential",
        };

        Assert.All(expected, group => Assert.Contains(group, covered));
    }

    [Fact]
    public void NoDiagnosticEchoesAnInlineSecret()
    {
        var (_, document) = DocumentCases()["credential-inline-not-permitted"];

        foreach (var options in new[]
                 {
                     ManifestLoadOptions.Default,
                     ManifestLoadOptions.Default with { AllowInlineSecrets = true },
                 })
        {
            var result = ManifestReader.Read(InMemoryManifestSource.FromText(document), options);

            Assert.All(
                result.Diagnostics,
                diagnostic => Assert.DoesNotContain(InlineSecretCanary, diagnostic.Message, System.StringComparison.Ordinal));
        }
    }

    [Fact]
    public void SchemaDepthBombIsRefused()
    {
        var chain = new StringBuilder("{\"type\":\"object\"}");

        for (var i = 0; i < 40; i++)
        {
            chain.Insert(0, "{\"type\":\"object\",\"properties\":{\"next\":").Append('}').Append('}');
        }

        AssertBoundExceeded(BombManifest(chain.ToString(), maxDepth: 8, maxNodes: 4096, maxProperties: 256));
    }

    [Fact]
    public void SchemaNodeBombIsRefused()
    {
        var members = Enumerable
            .Range(0, 64)
            .Select(index => string.Create(
                CultureInfo.InvariantCulture,
                $"\"p{index}\":{{\"type\":\"object\",\"properties\":{{\"a\":{{\"type\":\"string\"}},\"b\":{{\"type\":\"string\"}}}}}}"));

        var schema = "{\"type\":\"object\",\"properties\":{" + string.Join(',', members) + "}}";

        AssertBoundExceeded(BombManifest(schema, maxDepth: 32, maxNodes: 32, maxProperties: 256));
    }

    [Fact]
    public void SchemaPropertyBombIsRefused()
    {
        var members = Enumerable
            .Range(0, 64)
            .Select(index => string.Create(CultureInfo.InvariantCulture, $"\"p{index}\":{{\"type\":\"string\"}}"));

        var schema = "{\"type\":\"object\",\"properties\":{" + string.Join(',', members) + "}}";

        AssertBoundExceeded(BombManifest(schema, maxDepth: 32, maxNodes: 4096, maxProperties: 8));
    }

    [Fact]
    public void HostileFormatVersionIsTruncatedInTheDiagnostic()
    {
        var hostile = new string('9', 4096);
        var document = "{\"manifestFormatVersion\":\"" + hostile + "\",\"sections\":{}}";

        var result = ManifestReader.Read(InMemoryManifestSource.FromText(document));

        var diagnostic = Assert.Single(
            result.Errors,
            candidate => string.Equals(
                candidate.Code,
                ManifestDiagnosticCodes.FormatVersionMalformed,
                System.StringComparison.Ordinal));

        Assert.True(
            diagnostic.Message.Length < 256,
            "A hostile version string must be truncated before it reaches a diagnostic message.");
    }

    private static void AssertBoundExceeded(string document)
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(document));

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            diagnostic => string.Equals(
                diagnostic.Code,
                ManifestDiagnosticCodes.SchemaBoundExceeded,
                System.StringComparison.Ordinal));
    }

    private static string BombManifest(string schema, int maxDepth, int maxNodes, int maxProperties)
    {
        var bounds = string.Create(
            CultureInfo.InvariantCulture,
            $"{{\"maxDepth\":{maxDepth},\"maxNodes\":{maxNodes},\"maxPropertiesPerLevel\":{maxProperties}}}");

        return """
            {
              "manifestFormatVersion": "0.1",
              "sections": {
                "server": { "inline": { "name": "Bomb" } },
                "policy": { "inline": { "baseUrl": "https://api.example.com", "schemaBounds": __BOUNDS__ } },
                "operations": {
                  "inline": {
                    "operations": [
                      {
                        "key": "POST /bomb",
                        "method": "POST",
                        "path": "/bomb",
                        "requestBody": { "content": { "application/json": { "schema": __SCHEMA__ } } }
                      }
                    ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      { "slug": "bomb", "name": "Bomb", "binding": { "type": "http", "operation": "POST /bomb" } }
                    ]
                  }
                }
              }
            }
            """
            .Replace("__BOUNDS__", bounds, System.StringComparison.Ordinal)
            .Replace("__SCHEMA__", schema, System.StringComparison.Ordinal);
    }

    private static IReadOnlyList<string> ValidFixtureNames() =>
        Directory
            .GetDirectories(CorpusRoot)
            .Select(Path.GetFileName)
            .Where(name => !string.Equals(name, "hostile", System.StringComparison.Ordinal))
            .Select(name => name!)
            .Order(System.StringComparer.Ordinal)
            .ToList();

    private static ManifestReadResult ReadFixture(string fixture, ManifestLoadOptions? options = null) =>
        ManifestReader.Read(new DirectoryManifestSource(Path.Combine(CorpusRoot, fixture)), options);

    private static string ReadExpectation(string path)
    {
        var document = JsonNode.Parse(File.ReadAllText(path))!.AsObject();

        return document["code"]!.GetValue<string>();
    }

    private static IReadOnlyList<string> HostileCodes()
    {
        var fromBundles = Directory
            .GetDirectories(Path.Combine(CorpusRoot, "hostile", "bundle"))
            .Select(directory => ReadExpectation(Path.Combine(directory, "expected.json")));

        return fromBundles
            .Concat(DocumentCases().Values.Select(entry => entry.Code))
            .Distinct(System.StringComparer.Ordinal)
            .ToList();
    }

    private static IReadOnlyDictionary<string, (string Code, string Document)> DocumentCases()
    {
        var path = Path.Combine(CorpusRoot, "hostile", "document-cases.json");
        var root = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        var parsed = new Dictionary<string, (string, string)>(System.StringComparer.Ordinal);

        foreach (var entry in root["cases"]!.AsArray())
        {
            var element = entry!.AsObject();
            var name = element["name"]!.GetValue<string>();

            parsed[name] = (element["code"]!.GetValue<string>(), element["manifest"]!.ToJsonString());
        }

        return parsed;
    }
}
