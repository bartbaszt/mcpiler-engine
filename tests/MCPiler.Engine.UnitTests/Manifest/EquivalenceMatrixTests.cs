using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Sealing;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// Semantically equivalent manifests that differ textually must load to the same thing.
/// A parser that is order-, whitespace- or escaping-sensitive passes a canonical fixture and
/// then behaves differently on the same document produced by another writer.
/// </summary>
/// <remarks>
/// The derived-versus-explicit dimension for the <c>tools</c> and <c>search</c> sections lives
/// with the code it compares, in the derivation suites, because proving it needs a deriver and
/// a ranker rather than a document digest.
/// </remarks>
public sealed class EquivalenceMatrixTests
{
    [Fact]
    public void MemberOrderDoesNotChangeMeaning()
    {
        var natural = Manifest(
            server: """{ "name": "Order API", "description": "d", "version": "1.0" }""");

        var reordered = Manifest(
            server: """{ "version": "1.0", "description": "d", "name": "Order API" }""");

        AssertEquivalent(natural, reordered);
    }

    [Fact]
    public void WhitespaceDoesNotChangeMeaning()
    {
        var spaced = Manifest();
        var dense = System.Text.Json.Nodes.JsonNode.Parse(spaced)!.ToJsonString();

        Assert.NotEqual(spaced, dense);
        AssertEquivalent(spaced, dense);
    }

    [Fact]
    public void EscapedAndLiteralTextAreTheSameString()
    {
        var literal = Manifest(server: """{ "name": "Café & Bar <München>" }""");
        var escaped = Manifest(
            server: """{ "name": "Caf\u00e9 \u0026 Bar \u003CM\u00fcnchen\u003E" }""");

        Assert.NotEqual(literal, escaped);
        AssertEquivalent(literal, escaped);
    }

    [Fact]
    public void SurrogatePairsSurviveEitherSpelling()
    {
        var literal = Manifest(server: """{ "name": "Widgets 😀" }""");
        var escaped = Manifest(server: """{ "name": "Widgets \ud83d\ude00" }""");

        Assert.NotEqual(literal, escaped);
        AssertEquivalent(literal, escaped);

        var manifest = Read(literal).Manifest;

        Assert.NotNull(manifest);
        Assert.Equal("Widgets 😀", manifest!.Server.Name);
    }

    [Fact]
    public void OmittedMembersEqualTheirDocumentedDefaults()
    {
        var implicitDefaults = Manifest();

        var spelledOut = Manifest(
            policy: """
                {
                  "baseUrl": "https://api.example.com",
                  "allowedOrigins": ["https://api.example.com"],
                  "limits": {
                    "upstreamConnectTimeoutSeconds": 10,
                    "upstreamRequestTimeoutSeconds": 100,
                    "upstreamResponseSizeLimitBytes": 52428800,
                    "redirectHopLimit": 5,
                    "concurrency": 8,
                    "mcpRequestSizeLimitBytes": 1048576
                  },
                  "transformCeiling": {
                    "maxSteps": 64, "maxDepth": 32, "maxNodes": 8192,
                    "maxOutputBytes": 262144, "maxArrayFanout": 1024
                  },
                  "compound": { "maxTotalResponseBytes": 104857600, "workflowTimeoutSeconds": 120 },
                  "schemaBounds": { "maxDepth": 32, "maxNodes": 2048, "maxPropertiesPerLevel": 256 },
                  "files": {
                    "handleLifetimeSeconds": 86400,
                    "uploadSizeLimitBytes": 104857600,
                    "rejectMagicMismatch": true
                  }
                }
                """);

        Assert.NotEqual(implicitDefaults, spelledOut);
        AssertEquivalent(implicitDefaults, spelledOut);
    }

    [Fact]
    public void SynthesizedSurfaceEqualsTheSpelledOutOne()
    {
        var synthesized = Manifest();

        var spelledOut = Manifest(
            server: """
                {
                  "name": "Order API",
                  "surfaces": [
                    {
                      "slug": "default",
                      "name": "Order API",
                      "isDefault": true,
                      "enabled": true,
                      "requiredScopes": [],
                      "navigator": { "enabled": false, "pageSize": 25 },
                      "outputSchemas": false,
                      "operations": [{ "operation": "ping", "exposure": "direct" }]
                    }
                  ]
                }
                """);

        Assert.NotEqual(synthesized, spelledOut);
        AssertEquivalent(synthesized, spelledOut);
    }

    [Fact]
    public void InlineAndExternalSectionsAreTheSameManifest()
    {
        var inline = Manifest();

        const string externalRoot = """
            {
              "manifestFormatVersion": "0.1",
              "sections": {
                "server": { "path": "sections/server.json" },
                "policy": { "path": "sections/policy.json" },
                "operations": { "path": "sections/operations.json" },
                "agentSurface": { "path": "sections/agentSurface.json" }
              }
            }
            """;

        var external = InMemoryManifestSource.FromText(
            externalRoot,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["sections/server.json"] = DefaultServer,
                ["sections/policy.json"] = DefaultPolicy,
                ["sections/operations.json"] = DefaultOperations,
                ["sections/agentSurface.json"] = DefaultAgentSurface,
            });

        var fromInline = Read(inline);
        var fromExternal = ManifestReader.Read(external);

        Assert.True(fromExternal.Succeeded, string.Join('\n', fromExternal.Errors));
        Assert.Equal(Digest(fromInline.Manifest), Digest(fromExternal.Manifest));
    }

    [Fact]
    public void ADirectoryAndItsArchiveAreTheSameManifest()
    {
        // The directory is the canonical physical form and the archive is only transport, so
        // moving a bundle through one must not be able to change what Engine reads out of it.
        var origin = Directory.CreateTempSubdirectory("mcpiler-manifest-origin");
        var destination = Directory.CreateTempSubdirectory("mcpiler-manifest-unpacked");

        try
        {
            Directory.CreateDirectory(Path.Combine(origin.FullName, "sections"));

            File.WriteAllText(
                Path.Combine(origin.FullName, "manifest.json"),
                """
                {
                  "manifestFormatVersion": "0.1",
                  "sections": {
                    "server": { "path": "sections/server.json" },
                    "policy": { "path": "sections/policy.json" },
                    "operations": { "path": "sections/operations.json" },
                    "agentSurface": { "path": "sections/agentSurface.json" }
                  }
                }
                """);

            File.WriteAllText(Path.Combine(origin.FullName, "sections", "server.json"), DefaultServer);
            File.WriteAllText(Path.Combine(origin.FullName, "sections", "policy.json"), DefaultPolicy);
            File.WriteAllText(Path.Combine(origin.FullName, "sections", "operations.json"), DefaultOperations);
            File.WriteAllText(Path.Combine(origin.FullName, "sections", "agentSurface.json"), DefaultAgentSurface);

            using var archive = new MemoryStream();

            Assert.True(ManifestArchive.Pack(origin.FullName, archive).Succeeded);

            archive.Position = 0;
            Directory.Delete(destination.FullName, recursive: true);

            Assert.True(ManifestArchive.Unpack(archive, destination.FullName).Succeeded);

            var fromDirectory = ManifestReader.Read(new DirectoryManifestSource(origin.FullName));
            var fromArchive = ManifestReader.Read(new DirectoryManifestSource(destination.FullName));

            Assert.True(fromArchive.Succeeded, string.Join('\n', fromArchive.Errors));
            Assert.Equal(Digest(fromDirectory.Manifest), Digest(fromArchive.Manifest));
        }
        finally
        {
            Directory.Delete(origin.FullName, recursive: true);

            if (Directory.Exists(destination.FullName))
            {
                Directory.Delete(destination.FullName, recursive: true);
            }
        }
    }

    [Fact]
    public void SealingChangesNothingButTheSealItself()
    {
        var unsealed = Manifest();
        var sealedText = Seal(unsealed);

        var withoutSeal = Read(unsealed);
        var withSeal = Read(sealedText);

        Assert.True(withSeal.Succeeded, string.Join('\n', withSeal.Errors));
        Assert.Equal(Digest(withoutSeal.Manifest), Digest(withSeal.Manifest));

        Assert.False(withoutSeal.Manifest!.IsSealed);
        Assert.True(withSeal.Manifest!.IsSealed);

        // The only observable difference is the advisory warning, which is the whole point of
        // integrity being optional rather than required.
        Assert.Contains(withoutSeal.Warnings, d => d.Code == ManifestDiagnosticCodes.Unsealed);
        Assert.DoesNotContain(withSeal.Warnings, d => d.Code == ManifestDiagnosticCodes.Unsealed);
    }

    [Fact]
    public void ASealSurvivesReorderingTheSectionIndex()
    {
        // The seal is computed over the canonicalized index, so a writer that emits members in a
        // different order must not invalidate it. Otherwise every re-serialization would look
        // like tampering.
        var sealedText = Seal(Manifest());
        var root = JsonNode.Parse(sealedText)!.AsObject();
        var sections = root["sections"]!.AsObject();

        var reversed = new JsonObject();

        foreach (var member in sections.Select(entry => entry.Key).Reverse().ToList())
        {
            var payload = sections[member]!.DeepClone();
            sections.Remove(member);
            reversed[member] = payload;
        }

        root["sections"] = reversed;

        var result = Read(root.ToJsonString());

        Assert.True(result.Succeeded, string.Join('\n', result.Errors));
        Assert.True(result.Manifest!.IsSealed);
    }

    [Fact]
    public void NumericTokensArePreservedRatherThanNormalised()
    {
        // This dimension deliberately does NOT assert equivalence. Numbers keep their original
        // token, so '1.50' and '1.5' are the same number with different bytes. Normalising them
        // would be textbook canonical JSON and would also change the digest of every document
        // already sealed with a lexically preserved bound.
        var wide = Manifest(operationSchema: """{ "type": "number", "minimum": 1.50 }""");
        var narrow = Manifest(operationSchema: """{ "type": "number", "minimum": 1.5 }""");

        var fromWide = Read(wide);
        var fromNarrow = Read(narrow);

        Assert.True(fromWide.Succeeded);
        Assert.True(fromNarrow.Succeeded);

        Assert.Equal("1.50", BoundOf(fromWide.Manifest!));
        Assert.Equal("1.5", BoundOf(fromNarrow.Manifest!));
        Assert.NotEqual(Digest(fromWide.Manifest), Digest(fromNarrow.Manifest));
    }

    [Fact]
    public void TheDigestDetectsARealDifference()
    {
        // Without this, every equivalence assertion above would still pass if the projection
        // silently collapsed to a constant. This is the suite's own tautology detector.
        var direct = Manifest();

        var hidden = Manifest(
            server: """
                {
                  "name": "Order API",
                  "surfaces": [
                    { "slug": "default", "isDefault": true, "operations": [{ "operation": "ping", "exposure": "hidden" }] }
                  ]
                }
                """);

        Assert.NotEqual(Digest(Read(direct).Manifest), Digest(Read(hidden).Manifest));
    }

    private static string BoundOf(ManifestDocument manifest)
    {
        var schema = manifest.Operations.Operation("GET /ping")!.Parameters[0].Schema!;

        return schema.Object!["minimum"]!.ToJsonString();
    }

    private static void AssertEquivalent(string left, string right)
    {
        var fromLeft = Read(left);
        var fromRight = Read(right);

        Assert.True(fromLeft.Succeeded, string.Join('\n', fromLeft.Errors));
        Assert.True(fromRight.Succeeded, string.Join('\n', fromRight.Errors));
        Assert.Equal(Digest(fromLeft.Manifest), Digest(fromRight.Manifest));
    }

    private static ManifestReadResult Read(string document) =>
        ManifestReader.Read(InMemoryManifestSource.FromText(document));

    private static string Seal(string document)
    {
        var root = JsonNode.Parse(document)!.AsObject();

        root["completeness"] = new JsonObject
        {
            ["algorithm"] = ManifestCompleteness.Sha256,
            ["value"] = CanonicalJson.Hash(root["sections"]),
        };

        return root.ToJsonString();
    }

    /// <summary>
    /// Projects a loaded manifest onto the facts that decide runtime behavior, then hashes the
    /// canonical form. Comparing this rather than the source bytes is what makes the assertion
    /// about meaning instead of about formatting.
    /// </summary>
    private static string Digest(ManifestDocument? manifest)
    {
        Assert.NotNull(manifest);

        var document = new JsonObject
        {
            ["formatVersion"] = manifest!.FormatVersion.ToString(),
            ["server"] = ServerFacts(manifest.Server),
            ["policy"] = PolicyFacts(manifest.Policy),
            ["credentials"] = CredentialFacts(manifest.EffectiveCredentials),
            ["operations"] = OperationFacts(manifest.Operations),
            ["agentSurface"] = AgentFacts(manifest.AgentSurface),
        };

        return CanonicalJson.Hash(document);
    }

    private static JsonObject ServerFacts(ServerSection server)
    {
        var surfaces = new JsonArray();

        foreach (var surface in server.Surfaces)
        {
            var operations = new JsonArray();

            foreach (var operation in surface.Operations)
            {
                operations.Add(new JsonObject
                {
                    ["operation"] = operation.Operation,
                    ["exposure"] = Vocabulary.Write(operation.Exposure),
                });
            }

            surfaces.Add(new JsonObject
            {
                ["slug"] = surface.Slug,
                ["name"] = surface.DisplayName,
                ["isDefault"] = surface.IsDefault,
                ["enabled"] = surface.Enabled,
                ["requiredScopes"] = Texts(surface.RequiredScopes),
                ["navigatorEnabled"] = surface.EffectiveNavigator.Enabled,
                ["navigatorPageSize"] = surface.EffectiveNavigator.PageSize,
                ["outputSchemas"] = surface.OutputSchemas,
                ["operations"] = operations,
            });
        }

        return new JsonObject
        {
            ["name"] = server.Name,
            ["description"] = server.Description,
            ["version"] = server.Version,
            ["surfaces"] = surfaces,
        };
    }

    private static JsonObject PolicyFacts(PolicySection policy)
    {
        var limits = policy.EffectiveLimits;
        var ceiling = policy.EffectiveTransformCeiling;
        var compound = policy.EffectiveCompound;
        var bounds = policy.EffectiveSchemaBounds;
        var files = policy.EffectiveFiles;

        return new JsonObject
        {
            ["baseUrl"] = policy.BaseUrl.ToString(),
            ["allowedOrigins"] = Texts(policy.AllowedOrigins),
            ["connectSeconds"] = limits.UpstreamConnectTimeout.TotalSeconds,
            ["requestSeconds"] = limits.UpstreamRequestTimeout.TotalSeconds,
            ["responseBytes"] = limits.UpstreamResponseSizeLimitBytes,
            ["redirectHops"] = limits.RedirectHopLimit,
            ["concurrency"] = limits.Concurrency,
            ["mcpRequestBytes"] = limits.McpRequestSizeLimitBytes,
            ["transformSteps"] = ceiling.MaxSteps,
            ["transformDepth"] = ceiling.MaxDepth,
            ["transformNodes"] = ceiling.MaxNodes,
            ["transformOutputBytes"] = ceiling.MaxOutputBytes,
            ["transformFanout"] = ceiling.MaxArrayFanout,
            ["compoundBytes"] = compound.MaxTotalResponseBytes,
            ["compoundSeconds"] = compound.WorkflowTimeout.TotalSeconds,
            ["schemaDepth"] = bounds.MaxDepth,
            ["schemaNodes"] = bounds.MaxNodes,
            ["schemaProperties"] = bounds.MaxPropertiesPerLevel,
            ["fileLifetimeSeconds"] = files.HandleLifetime.TotalSeconds,
            ["uploadBytes"] = files.UploadSizeLimitBytes,
            ["rejectMagicMismatch"] = files.RejectMagicMismatch,
        };
    }

    private static JsonArray CredentialFacts(CredentialsSection credentials)
    {
        var facts = new JsonArray();

        foreach (var credential in credentials.Credentials)
        {
            facts.Add(new JsonObject
            {
                ["scheme"] = Vocabulary.Write(credential.Scheme),
                ["slot"] = credential.Slot,
                ["location"] = Vocabulary.Write(credential.EffectiveLocation),
                ["reference"] = credential.Value.ToString(),
            });
        }

        return facts;
    }

    private static JsonArray OperationFacts(OperationsSection operations)
    {
        var facts = new JsonArray();

        foreach (var operation in operations.Operations)
        {
            var parameters = new JsonArray();

            foreach (var parameter in operation.Parameters)
            {
                parameters.Add(new JsonObject
                {
                    ["name"] = parameter.Name,
                    ["in"] = Vocabulary.Write(parameter.In),
                    ["required"] = parameter.Required,
                    ["style"] = Vocabulary.Write(parameter.EffectiveStyle),
                    ["explode"] = parameter.EffectiveExplode,
                    ["schema"] = Schema(parameter.Schema),
                });
            }

            facts.Add(new JsonObject
            {
                ["key"] = operation.Key,
                ["method"] = operation.Method,
                ["path"] = operation.Path,
                ["parameters"] = parameters,
                ["requestBody"] = Texts(
                    operation.RequestBody is null ? [] : operation.RequestBody.Content.Keys.Order(StringComparer.Ordinal)),
                ["responses"] = Texts(operation.Responses.Keys.Order(StringComparer.Ordinal)),
            });
        }

        return facts;
    }

    private static JsonArray AgentFacts(AgentSurfaceSection surface)
    {
        var facts = new JsonArray();

        foreach (var operation in surface.Operations)
        {
            var annotations = operation.EffectiveAnnotations(null);

            facts.Add(new JsonObject
            {
                ["slug"] = operation.Slug,
                ["kind"] = Vocabulary.Write(operation.EffectiveKind),
                ["name"] = operation.Name,
                ["description"] = operation.ToolDescription,
                ["inputSchema"] = Schema(operation.InputSchema),
                ["outputSchema"] = Schema(operation.OutputSchema),
                ["risk"] = operation.EffectiveRisk,
                ["readOnly"] = annotations.ReadOnly,
                ["destructive"] = annotations.Destructive,
                ["idempotent"] = annotations.Idempotent,
                ["openWorld"] = annotations.OpenWorld,
                ["operationKey"] = ManifestBindingDispatcher.TryResolveOperationKey(operation.Binding),
                ["serverUrl"] = ManifestBindingDispatcher.TryResolveServerUrl(operation.Binding),
            });
        }

        return facts;
    }

    private static JsonNode? Schema(ManifestSchema? schema) =>
        schema is null ? null : schema.Node.DeepClone();

    private static JsonArray Texts(IEnumerable<string> values)
    {
        var array = new JsonArray();

        foreach (var value in values)
        {
            array.Add(value);
        }

        return array;
    }

    private const string DefaultServer = """{ "name": "Order API" }""";

    private const string DefaultPolicy = """{ "baseUrl": "https://api.example.com" }""";

    private const string DefaultAgentSurface = """
        {
          "operations": [
            { "slug": "ping", "name": "Ping", "binding": { "type": "http", "operation": "GET /ping" } }
          ]
        }
        """;

    private static string DefaultOperations => Operations("""{ "type": "string" }""");

    private static string Operations(string schema) => string.Create(
        CultureInfo.InvariantCulture,
        $$"""
        {
          "operations": [
            {
              "key": "GET /ping",
              "method": "GET",
              "path": "/ping",
              "parameters": [{ "name": "q", "in": "query", "schema": {{schema}} }],
              "responses": { "200": { "content": { "application/json": { "schema": { "type": "object" } } } } }
            }
          ]
        }
        """);

    private static string Manifest(
        string? server = null,
        string? policy = null,
        string? operationSchema = null,
        string? agentSurface = null) => string.Create(
        CultureInfo.InvariantCulture,
        $$"""
        {
          "manifestFormatVersion": "0.1",
          "sections": {
            "server": { "inline": {{server ?? DefaultServer}} },
            "policy": { "inline": {{policy ?? DefaultPolicy}} },
            "operations": { "inline": {{Operations(operationSchema ?? """{ "type": "string" }""")}} },
            "agentSurface": { "inline": {{agentSurface ?? DefaultAgentSurface}} }
          }
        }
        """);
}
