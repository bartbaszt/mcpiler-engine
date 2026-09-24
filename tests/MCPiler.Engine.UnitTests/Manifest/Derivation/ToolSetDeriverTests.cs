using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Derivation;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Derivation;

/// <summary>
/// Tool-set derivation: what a surface advertises when it carries no pinned tool set, and
/// what happens when a pinned set and the derivation disagree.
/// </summary>
public sealed class ToolSetDeriverTests
{
    // ---- names -----------------------------------------------------------------------

    [Theory]
    [InlineData("list-pets", "list-pets")]
    [InlineData("list.pets", "list.pets")]
    [InlineData("list pets", "list_pets")]
    [InlineData("list/pets", "list_pets")]
    [InlineData("__leading", "leading")]
    [InlineData("trailing__", "trailing")]
    [InlineData("///", ToolName.Fallback)]
    [InlineData("", ToolName.Fallback)]
    public void SanitizeMapsASlugOntoThePermittedCharacterSet(string slug, string expected)
        => Assert.Equal(expected, ToolName.Sanitize(slug));

    [Fact]
    public void SanitizeTruncatesToTheAdvertisedLimit()
    {
        var name = ToolName.Sanitize(new string('a', 200));

        Assert.Equal(ManifestTool.MaxNameLength, name.Length);
    }

    [Fact]
    public void AllocateSuffixesNamesThatSanitizationCollapsedTogether()
    {
        var names = ToolName.Allocate(["list pets", "list/pets", "list_pets"]);

        // Ordinal slug order decides which one keeps the bare name: '/' < '_' < ' '... the
        // point of the assertion is that the three distinct slugs stay distinguishable.
        Assert.Equal(3, names.Values.Distinct(StringComparer.Ordinal).Count());
        Assert.Contains("list_pets", names.Values);
        Assert.Contains("list_pets_2", names.Values);
        Assert.Contains("list_pets_3", names.Values);
    }

    [Fact]
    public void AllocateIgnoresTheOrderTheSlugsArriveIn()
    {
        var forward = ToolName.Allocate(["list pets", "list/pets", "list_pets"]);
        var reversed = ToolName.Allocate(["list_pets", "list/pets", "list pets"]);

        Assert.Equal(forward.OrderBy(pair => pair.Key, StringComparer.Ordinal), reversed.OrderBy(pair => pair.Key, StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("list-pets", true)]
    [InlineData("catalogue.discover", true)]
    [InlineData("", false)]
    [InlineData("has space", false)]
    [InlineData("has/slash", false)]
    public void WellFormednessMatchesTheAdvertisedCharacterSet(string name, bool expected)
        => Assert.Equal(expected, ToolName.IsWellFormed(name));

    [Fact]
    public void WellFormednessRejectsANameLongerThanTheLimit()
        => Assert.False(ToolName.IsWellFormed(new string('a', ManifestTool.MaxNameLength + 1)));

    // ---- what a surface advertises ---------------------------------------------------

    [Fact]
    public void DerivationAdvertisesOnlyDirectOperations()
    {
        var manifest = Load(MultiSurface);
        var surface = manifest.Server.Surface("default")!;

        var tools = ToolSetDeriver.Derive(manifest, surface);

        Assert.Equal(
            ["list-pets", "get-pet", "catalogue.discover", "catalogue.describe", "catalogue.invoke"],
            tools.Tools.Select(tool => tool.Name));
    }

    [Fact]
    public void DerivationFollowsTheExposureListOrderRatherThanTheOperationOrder()
    {
        // The agentSurface declares list-pets first; the surface exposes get-pet first.
        var manifest = Load(MultiSurface);
        var reordered = Reverse(manifest, "default");

        var tools = ToolSetDeriver.Derive(reordered, reordered.Server.Surface("default")!);

        Assert.Equal(["get-pet", "list-pets"], tools.Tools.Where(tool => !tool.IsNavigatorTool).Select(tool => tool.Name));
    }

    [Fact]
    public void ReorderingTheExposureListDoesNotMoveANameOntoADifferentOperation()
    {
        var manifest = Load(MultiSurface);
        var reordered = Reverse(manifest, "default");

        var before = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);
        var after = ToolSetDeriver.Derive(reordered, reordered.Server.Surface("default")!);

        // The advertisement order follows the list; the names do not.
        Assert.NotEqual(
            before.Tools.Select(tool => tool.Name),
            after.Tools.Select(tool => tool.Name));
        foreach (var tool in before.Tools.Where(tool => !tool.IsNavigatorTool))
        {
            Assert.Equal(tool.Name, after.Tools.Single(candidate => candidate.Operation == tool.Operation).Name);
        }
    }

    [Fact]
    public void NavigatorToolsAppearOnlyWhenTheSurfaceEnablesNavigator()
    {
        var manifest = Load(MultiSurface);

        var withNavigator = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);
        var withoutNavigator = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("read-only")!);

        Assert.Equal(3, withNavigator.Tools.Count(tool => tool.IsNavigatorTool));
        Assert.DoesNotContain(withoutNavigator.Tools, tool => tool.IsNavigatorTool);
    }

    [Fact]
    public void DiscoveryAdvertisesTheSurfacesOwnPageSizeAsTheDefault()
    {
        var manifest = Load(MultiSurface);

        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);

        var discover = tools.Tools.Single(tool => tool.Name == ManifestTool.NavigatorDiscover);
        var pageSize = discover.InputSchema!.Object!["properties"]!["pageSize"]!;
        Assert.Equal(10, pageSize["default"]!.GetValue<int>());
        Assert.Equal(NavigatorToolDefinitions.MaxPageSize, pageSize["maximum"]!.GetValue<int>());
    }

    [Fact]
    public void EveryEnabledSurfaceGetsAToolSet()
    {
        var manifest = Load(MultiSurface);

        var section = ToolSetDeriver.Derive(manifest);

        Assert.Equal(["default", "read-only"], section.Surfaces.Keys.OrderBy(slug => slug, StringComparer.Ordinal));
    }

    [Fact]
    public void ADisabledSurfaceAdvertisesNothingAtAll()
    {
        var manifest = Load(MultiSurface.Replace(
            "\"slug\": \"read-only\",",
            "\"slug\": \"read-only\", \"enabled\": false,",
            StringComparison.Ordinal));

        var section = ToolSetDeriver.Derive(manifest);

        Assert.DoesNotContain("read-only", section.Surfaces.Keys);
    }

    // ---- descriptions ----------------------------------------------------------------

    [Fact]
    public void ASummaryOnlyOperationAdvertisesItsSummary()
        => Assert.Equal("Fetches one pet", DescriptionOf("get-pet"));

    [Fact]
    public void ADistinctSummaryAndDescriptionAreBothAdvertised()
    {
        var description = DescriptionOf(
            "get-pet",
            MultiSurface.Replace(
                "\"summary\": \"Fetches one pet\",",
                "\"summary\": \"Fetches one pet\", \"description\": \"Returns the full pet record.\",",
                StringComparison.Ordinal));

        Assert.Equal("Fetches one pet Returns the full pet record.", description);
    }

    [Fact]
    public void ADescriptionEqualToTheSummaryIsNotAdvertisedTwice()
    {
        var description = DescriptionOf(
            "get-pet",
            MultiSurface.Replace(
                "\"summary\": \"Fetches one pet\",",
                "\"summary\": \"Fetches one pet\", \"description\": \"Fetches one pet\",",
                StringComparison.Ordinal));

        Assert.Equal("Fetches one pet", description);
    }

    [Fact]
    public void AnOperationWithNoProseFallsBackToItsExecutionKey()
    {
        var description = DescriptionOf(
            "get-pet",
            MultiSurface.Replace(
                "\"summary\": \"Fetches one pet\",",
                string.Empty,
                StringComparison.Ordinal));

        Assert.Equal("Invokes GET /pets/{petId}.", description);
    }

    [Fact]
    public void AnOperationThatAcceptsFilesDisclosesHowFileArgumentsWork()
    {
        var description = DescriptionOf(
            "get-pet",
            MultiSurface.Replace(
                "\"properties\": { \"petId\": { \"type\": \"string\" } }",
                "\"properties\": { \"petId\": { \"type\": \"string\", \"x-mcp-file\": true } }",
                StringComparison.Ordinal));

        Assert.EndsWith(ToolSetDeriver.FileArgumentDisclosure, description, StringComparison.Ordinal);
    }

    [Fact]
    public void TheFileDisclosureSurvivesASchemaHeldBehindALocalReference()
    {
        var manifest = Load(FileSlotBehindAReference);

        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.DefaultSurface!);

        Assert.EndsWith(
            ToolSetDeriver.FileArgumentDisclosure,
            tools.Tools.Single(tool => tool.Operation == "upload").Description,
            StringComparison.Ordinal);
    }

    // ---- compound retry advice --------------------------------------------------------

    [Fact]
    public void ACompoundOperationDisclosesWhetherItIsSafeToRetry()
    {
        var manifest = Load(Compound(stepsAreIdempotent: true));

        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.DefaultSurface!);

        Assert.EndsWith(
            ToolSetDeriver.IdempotentCompoundDisclosure,
            tools.Tools.Single(tool => tool.Operation == "workflow").Description,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ACompoundWithOneUnsafeStepIsNotAdvertisedAsSafeToRetry()
    {
        var manifest = Load(Compound(stepsAreIdempotent: false));

        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.DefaultSurface!);

        Assert.EndsWith(
            ToolSetDeriver.NonIdempotentCompoundDisclosure,
            tools.Tools.Single(tool => tool.Operation == "workflow").Description,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ADeclaredClassificationOnTheCompoundOverridesTheStepFallback()
    {
        // Every step is non-idempotent, but the producer resolved the workflow's risk and
        // said otherwise. The producer knows more than the fallback does.
        var manifest = Load(Compound(stepsAreIdempotent: false).Replace(
            "\"slug\": \"workflow\",",
            "\"slug\": \"workflow\", \"annotations\": { \"idempotent\": true },",
            StringComparison.Ordinal));

        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.DefaultSurface!);

        Assert.EndsWith(
            ToolSetDeriver.IdempotentCompoundDisclosure,
            tools.Tools.Single(tool => tool.Operation == "workflow").Description,
            StringComparison.Ordinal);
    }

    // ---- output schema candidates -----------------------------------------------------

    [Fact]
    public void ASurfaceThatDoesNotSupportOutputSchemasAdvertisesNone()
    {
        var manifest = Load(MultiSurface);

        var permitted = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);
        var withheld = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("read-only")!);

        Assert.NotNull(permitted.Tools.Single(tool => tool.Operation == "list-pets").OutputSchema);
        Assert.Null(withheld.Tools.Single(tool => tool.Operation == "list-pets").OutputSchema);
    }

    [Theory]
    [InlineData("\"advertise\": \"no\"", false)]
    [InlineData("\"generate\": false, \"advertise\": \"yes\"", false)]
    [InlineData("\"advertise\": \"auto\"", true)]
    [InlineData("\"advertise\": \"yes\"", true)]
    public void TheOperationPolicyDecidesWhetherASchemaIsACandidate(string policy, bool expected)
    {
        var manifest = Load(MultiSurface.Replace(
            "\"outputSchemaPolicy\": { \"generate\": true, \"advertise\": \"yes\", \"useInternally\": false },",
            "\"outputSchemaPolicy\": { " + policy + " },",
            StringComparison.Ordinal));

        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);

        Assert.Equal(expected, tools.Tools.Single(tool => tool.Operation == "list-pets").OutputSchema is not null);
    }

    // ---- cross-operation continuation targets (ADR-0071) ------------------------------

    /// <summary>
    /// The projected <c>next.tool</c> for a Direct target is the actual advertised name, which is
    /// allocated from the whole agent surface rather than the surface's own list.
    /// </summary>
    [Fact]
    public void ADirectCrossOperationTargetKeepsItsAllocatedAdvertisedName()
    {
        var manifest = Load(MultiSurface);
        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);

        var getPet = tools.Tools.Single(tool => tool.Operation == "get-pet");

        Assert.Equal("get-pet", getPet.Name);
        Assert.True(manifest.AgentSurface.Operation("get-pet")!.OutputProjection is null);
    }

    /// <summary>
    /// A Navigator-only target is absent from the advertised set but present in the navigable set,
    /// which is exactly the distinction <c>catalogue.invoke</c> depends on.
    /// </summary>
    [Fact]
    public void ANavigatorOnlyTargetIsReachableWithoutBeingAdvertised()
    {
        var manifest = Load(MultiSurface);
        var surface = manifest.Server.Surface("default")!;

        var advertised = ToolSetDeriver.Derive(manifest, surface)
            .Tools.Select(tool => tool.Operation).ToHashSet(StringComparer.Ordinal);
        var navigable = ToolSetDeriver.DeriveNavigable(manifest, surface)
            .Tools.Select(tool => tool.Operation).ToHashSet(StringComparer.Ordinal);

        Assert.DoesNotContain("delete-pet", advertised);
        Assert.Contains("delete-pet", navigable);
    }

    // ---- derived versus pinned --------------------------------------------------------

    [Fact]
    public void AHandWrittenToolSectionMatchesWhatDerivationProduces()
    {
        var manifest = Load(MultiSurface);
        List<ManifestDiagnostic> diagnostics = [];

        var declared = SectionReader.ReadTools(
            JsonNode.Parse(File.ReadAllText(TestRepository.Fixture("manifests", "multi-surface", "expected-tools.json"))),
            diagnostics);

        Assert.Empty(diagnostics);
        Assert.NotNull(declared);

        foreach (var surface in manifest.Server.Surfaces)
        {
            var derived = ToolSetDeriver.Derive(manifest, surface);
            var pinned = declared.Surfaces[surface.Slug];

            Assert.Equal(ToolSetDeriver.Fingerprint(derived), ToolSetDeriver.Fingerprint(pinned));

            // The execution key is not advertised, so the fingerprint does not cover it.
            // Assert it separately rather than leaving it as unverified decoration in a
            // fixture that is supposed to be load-bearing.
            Assert.Equal(
                derived.Tools.Select(tool => tool.OperationKey),
                pinned.Tools.Select(tool => tool.OperationKey));
        }
    }

    [Fact]
    public void OmittingTheToolSectionAdvertisesExactlyWhatPinningItWould()
    {
        var manifest = Load(MultiSurface);
        var pinned = manifest with { Tools = ToolSetDeriver.Derive(manifest) };
        List<ManifestDiagnostic> diagnostics = [];

        foreach (var surface in manifest.Server.Surfaces)
        {
            var derived = ToolSetDeriver.Resolve(manifest, surface, diagnostics);
            var explicitly = ToolSetDeriver.Resolve(pinned, surface, diagnostics);

            Assert.Equal(ToolSetDeriver.Fingerprint(derived), ToolSetDeriver.Fingerprint(explicitly));
        }

        Assert.Empty(diagnostics);
    }

    [Fact]
    public void APinnedSetThatDisagreesIsAdvertisedButReported()
    {
        var manifest = Load(MultiSurface);
        var surface = manifest.Server.Surface("default")!;
        var tampered = new SurfaceToolSet([.. ToolSetDeriver.Derive(manifest, surface).Tools.Skip(1)]);
        var pinned = manifest with
        {
            Tools = new ToolsSection(new Dictionary<string, SurfaceToolSet>(StringComparer.Ordinal)
            {
                ["default"] = tampered,
            }),
        };
        List<ManifestDiagnostic> diagnostics = [];

        var advertised = ToolSetDeriver.Resolve(pinned, surface, diagnostics);

        Assert.Equal(ToolSetDeriver.Fingerprint(tampered), ToolSetDeriver.Fingerprint(advertised));
        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal(ManifestDiagnosticCodes.ToolDerivationMismatch, diagnostic.Code);
        Assert.Equal(ManifestSectionName.Tools, diagnostic.Section);
    }

    [Fact]
    public void ASurfaceWithNoPinnedEntryStillFallsBackToDerivation()
    {
        var manifest = Load(MultiSurface);
        var pinned = manifest with { Tools = new ToolsSection() };
        List<ManifestDiagnostic> diagnostics = [];

        var advertised = ToolSetDeriver.Resolve(pinned, manifest.Server.Surface("default")!, diagnostics);

        Assert.NotEmpty(advertised.Tools);
        Assert.Empty(diagnostics);
    }

    [Fact]
    public void TheFingerprintDetectsARealDifference()
    {
        var manifest = Load(MultiSurface);
        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);
        var renamed = new SurfaceToolSet([tools.Tools[0] with { Name = "renamed" }, .. tools.Tools.Skip(1)]);
        var reordered = new SurfaceToolSet([tools.Tools[1], tools.Tools[0], .. tools.Tools.Skip(2)]);

        Assert.NotEqual(ToolSetDeriver.Fingerprint(tools), ToolSetDeriver.Fingerprint(renamed));
        Assert.NotEqual(ToolSetDeriver.Fingerprint(tools), ToolSetDeriver.Fingerprint(reordered));
    }

    [Fact]
    public void TheFingerprintIgnoresProducerBookkeeping()
    {
        var manifest = Load(MultiSurface);
        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);
        var accounted = new SurfaceToolSet(
            [.. tools.Tools.Select(tool => tool with { SizeBytes = 1024, SizeTokens = 256 })]);

        Assert.Equal(ToolSetDeriver.Fingerprint(tools), ToolSetDeriver.Fingerprint(accounted));
    }

    // ---- pinned sets that are wrong regardless of derivation --------------------------

    [Fact]
    public void APinnedSetAddressedToAnUnknownSurfaceIsRefused()
    {
        var manifest = Load(MultiSurface) with
        {
            Tools = new ToolsSection(new Dictionary<string, SurfaceToolSet>(StringComparer.Ordinal)
            {
                ["ghost"] = new([new ManifestTool("x", "y", Operation: "list-pets")]),
            }),
        };

        Assert.Contains(
            ManifestValidator.Validate(manifest),
            diagnostic => diagnostic.Code == ManifestDiagnosticCodes.ToolSurfaceUnknown);
    }

    [Fact]
    public void APinnedToolCannotAdvertiseAnOperationTheSurfaceWithheld()
    {
        var manifest = Load(MultiSurface) with
        {
            Tools = new ToolsSection(new Dictionary<string, SurfaceToolSet>(StringComparer.Ordinal)
            {
                // delete-pet is navigator-only on this surface, so a direct tool for it would
                // grant through the tool list exactly what the exposure list withheld.
                ["default"] = new([new ManifestTool("delete-pet", "Removes a pet", Operation: "delete-pet")]),
            }),
        };

        Assert.Contains(
            ManifestValidator.Validate(manifest),
            diagnostic => diagnostic.Code == ManifestDiagnosticCodes.ToolOperationUnknown);
    }

    [Fact]
    public void APinnedToolNameTheProtocolCannotCarryIsRefused()
    {
        List<ManifestDiagnostic> diagnostics = [];

        SectionReader.ReadTools(
            JsonNode.Parse("""
            {
              "formatVersion": 1,
              "surfaces": { "default": { "tools": [ { "name": "has space", "description": "d", "operation": "list-pets" } ] } }
            }
            """),
            diagnostics);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == ManifestDiagnosticCodes.ToolNameInvalid);
    }

    [Fact]
    public void An_advertised_input_schema_carries_its_own_components()
    {
        var manifest = Load(Refs);
        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);
        var recursive = tools.Tools.Single(tool => tool.Operation == "create-node").InputSchema!;

        // The manifest declares this schema as a reference into its own agentSurface document,
        // and the component refers to itself. An advertised schema travels alone, so the
        // pointer has to be answerable from the schema and the recursion has to survive.
        Assert.Equal("object", recursive.Type);
        Assert.Equal(
            """{"$ref":"#/$defs/NodeInput"}""",
            recursive.Object!["properties"]!["children"]!["items"]!.ToJsonString());
        Assert.NotNull(recursive.Object[SchemaReferenceResolver.DefsKeyword]);

        var contained = recursive.Node.ToJsonString();

        Assert.DoesNotContain("#/components/", contained, StringComparison.Ordinal);
    }

    [Fact]
    public void An_inline_input_schema_is_advertised_untouched()
    {
        var manifest = Load(Refs);
        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);
        var inline = tools.Tools.Single(tool => tool.Operation == "get-tree").InputSchema!;

        // Containment must be reachable without being unconditional: a schema that references
        // nothing gains no '$defs' and no rewriting, so the bytes an author wrote are the bytes
        // advertised.
        Assert.Equal(
            """{"type":"object","required":["nodeId"],"properties":{"nodeId":{"type":"string"},"depth":{"type":"integer"}}}""",
            inline.Node.ToJsonString());
    }

    // ---- helpers ---------------------------------------------------------------------

    private static string DescriptionOf(string slug, string? manifestText = null)
    {
        var manifest = Load(manifestText ?? MultiSurface);
        var tools = ToolSetDeriver.Derive(manifest, manifest.Server.Surface("default")!);
        return tools.Tools.Single(tool => tool.Operation == slug).Description;
    }

    /// <summary>Returns the manifest with one surface's exposure list reversed.</summary>
    private static ManifestDocument Reverse(ManifestDocument manifest, string surfaceSlug)
    {
        var surfaces = manifest.Server.Surfaces
            .Select(surface => string.Equals(surface.Slug, surfaceSlug, StringComparison.Ordinal)
                ? surface with { Operations = [.. surface.Operations.Reverse()] }
                : surface)
            .ToList();

        return manifest with { Server = manifest.Server with { Surfaces = surfaces } };
    }

    private static ManifestDocument Load(string manifestText)
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(manifestText));
        Assert.True(result.Succeeded, string.Join("; ", result.Diagnostics.Select(diagnostic => diagnostic.ToString())));
        return result.Manifest!;
    }

    private static string MultiSurface { get; } =
        File.ReadAllText(TestRepository.Fixture("manifests", "multi-surface", "manifest.json"), Encoding.UTF8);

    private static string Refs { get; } =
        File.ReadAllText(TestRepository.Fixture("manifests", "refs", "manifest.json"), Encoding.UTF8);

    private const string FileSlotBehindAReference = """
    {
      "manifestFormatVersion": "0.3",
      "sections": {
        "server": { "inline": { "name": "Files" } },
        "policy": { "inline": { "baseUrl": "https://api.example.com" } },
        "operations": { "inline": { "operations": [
          { "key": "POST /upload", "method": "POST", "path": "/upload" } ] } },
        "agentSurface": { "inline": {
          "components": { "schemas": { "Upload": {
            "type": "object",
            "properties": { "file": { "type": "string", "x-mcp-file": true } } } } },
          "operations": [
            { "slug": "upload", "name": "Upload",
              "inputSchema": { "$ref": "#/components/schemas/Upload" },
              "binding": { "type": "http", "operation": "POST /upload" } } ] } }
      }
    }
    """;

    private static string Compound(bool stepsAreIdempotent) => $$"""
    {
      "manifestFormatVersion": "0.3",
      "sections": {
        "server": { "inline": { "name": "Workflow" } },
        "policy": { "inline": { "baseUrl": "https://api.example.com" } },
        "operations": { "inline": { "operations": [
          { "key": "PUT /a", "method": "PUT", "path": "/a" },
          { "key": "POST /b", "method": "POST", "path": "/b" } ] } },
        "agentSurface": { "inline": { "operations": [
          { "slug": "first", "name": "First",
            "binding": { "type": "http", "operation": "PUT /a" } },
          { "slug": "second", "name": "Second",
            "binding": { "type": "http", "operation": "{{(stepsAreIdempotent ? "PUT /a" : "POST /b")}}" } },
          { "slug": "workflow", "name": "Workflow", "summary": "Runs both steps",
            "binding": { "type": "compound", "steps": [
              { "stepId": "one", "operation": "first", "inputMappings": [] },
              { "stepId": "two", "operation": "second", "inputMappings": [] } ] } } ] } }
      }
    }
    """;
}
