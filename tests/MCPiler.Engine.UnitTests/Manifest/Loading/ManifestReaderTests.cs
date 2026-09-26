using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using System.Text.Json.Nodes;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

public sealed class ManifestReaderTests
{
    /// <summary>
    /// The single-file manifest the design names as the hand-authoring acceptance target.
    /// </summary>
    private const string MinimalManifest =
        """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server":       { "inline": { "name": "Example API" } },
            "policy":       { "inline": { "baseUrl": "https://api.example.com" } },
            "operations":   { "inline": { "operations": [
                { "key": "GET /pets", "method": "GET", "path": "/pets" } ] } },
            "agentSurface": { "inline": { "operations": [
                { "slug": "list-pets", "name": "List pets",
                  "binding": { "type": "http", "operation": "GET /pets" } } ] } }
          }
        }
        """;

    private static ManifestReadResult Read(string root, PolicyOverrides? overrides = null)
        => ManifestReader.Read(InMemoryManifestSource.FromText(root), options: null, overrides);

    private static IReadOnlyList<string> ErrorCodes(ManifestReadResult result)
        => [.. result.Errors.Select(static d => d.Code)];

    // ---- the minimal manifest -----------------------------------------------------------

    [Fact]
    public void The_minimal_manifest_reads_successfully()
    {
        ManifestReadResult result = Read(MinimalManifest);

        Assert.Empty(result.Errors);
        Assert.True(result.Succeeded);
        Assert.NotNull(result.Manifest);
    }

    /// <summary>
    /// The minimal manifest reads with warnings only, and both warnings are deliberate.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An unsealed manifest is a warning rather than a refusal because a hand-authored
    /// manifest is a first-class input; requiring a seal by default would make the format
    /// unusable without tooling.
    /// </para>
    /// <para>
    /// The absent response declaration is the second warning, and it is not cosmetic:
    /// response media types decide whether a response is classified as a file, and the
    /// response schema drives structured-content validation. The minimal manifest is
    /// therefore legal but behaviorally reduced, and it says so.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_minimal_manifest_reports_only_deliberate_warnings()
    {
        ManifestReadResult result = Read(MinimalManifest);

        Assert.Equal(
            [ManifestDiagnosticCodes.Unsealed, ManifestDiagnosticCodes.NoResponsesDeclared],
            result.Warnings.Select(static d => d.Code));
        Assert.All(
            result.Warnings,
            warning => Assert.Contains(warning.Code, ManifestDiagnosticCodes.AlwaysWarning));
    }

    /// <summary>
    /// Omitting <c>server.surfaces</c> synthesizes one default surface exposing everything.
    /// </summary>
    [Fact]
    public void An_omitted_surface_list_is_synthesized_from_the_agent_surface()
    {
        ManifestDocument manifest = Read(MinimalManifest).Manifest!;

        ManifestSurface surface = Assert.Single(manifest.Server.Surfaces);

        Assert.Equal("default", surface.Slug);
        Assert.True(surface.IsDefault);
        Assert.True(surface.Enabled);
        Assert.Equal("Example API", surface.Name);
        Assert.False(surface.EffectiveNavigator.Enabled);
        Assert.Equal([new SurfaceOperation("list-pets", OperationExposure.Direct)], surface.Operations);
    }

    /// <summary>
    /// Synthesis must not smuggle an exposure past cross-section validation.
    /// </summary>
    [Fact]
    public void A_synthesized_surface_passes_cross_section_validation()
        => Assert.Empty(ManifestValidator.Validate(Read(MinimalManifest).Manifest!));

    [Fact]
    public void A_declared_surface_list_is_not_replaced_by_synthesis()
    {
        ManifestReadResult result = Read(
            """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Example API", "surfaces": [
                    { "slug": "only", "isDefault": true, "operations": [
                        { "operation": "list-pets", "exposure": "navigator" } ] } ] } },
                "policy": { "inline": { "baseUrl": "https://api.example.com" } },
                "operations": { "inline": { "operations": [
                    { "key": "GET /pets", "method": "GET", "path": "/pets" } ] } },
                "agentSurface": { "inline": { "operations": [
                    { "slug": "list-pets", "name": "List pets",
                      "binding": { "type": "http", "operation": "GET /pets" } } ] } }
              }
            }
            """);

        Assert.Empty(result.Errors);

        ManifestSurface surface = Assert.Single(result.Manifest!.Server.Surfaces);

        Assert.Equal("only", surface.Slug);
        Assert.Equal(OperationExposure.Navigator, surface.ExposureOf("list-pets"));
    }

    // ---- required sections --------------------------------------------------------------

    [Theory]
    [InlineData("server")]
    [InlineData("policy")]
    [InlineData("operations")]
    [InlineData("agentSurface")]
    public void A_missing_required_section_is_refused(string section)
    {
        string root = MinimalManifest.Replace($"\"{section}\":", "\"provenanceHolder\":", StringComparison.Ordinal);

        ManifestReadResult result = ManifestReader.Read(InMemoryManifestSource.FromText(root));

        Assert.Contains(ManifestDiagnosticCodes.SectionMissing, ErrorCodes(result));
        Assert.Null(result.Manifest);
    }

    [Fact]
    public void The_optional_sections_may_all_be_absent()
    {
        ManifestDocument manifest = Read(MinimalManifest).Manifest!;

        Assert.Null(manifest.Credentials);
        Assert.Null(manifest.Tools);
        Assert.Null(manifest.Search);
        Assert.Null(manifest.Vectors);
        Assert.False(manifest.HasVectors);
        Assert.Empty(manifest.EffectiveCredentials.Credentials);
    }

    // ---- a partial parse produces no manifest at all ------------------------------------

    /// <summary>
    /// A section that failed to parse stops the read before cross-section validation.
    /// </summary>
    /// <remarks>
    /// Validating references against a half-built model produces confident diagnostics about
    /// the wrong thing, so the read is rejected wholesale instead.
    /// </remarks>
    [Fact]
    public void A_section_that_fails_to_parse_yields_no_manifest()
    {
        ManifestReadResult result = Read(
            MinimalManifest.Replace(
                "\"baseUrl\": \"https://api.example.com\"",
                "\"baseUrl\": \"not-a-url\"",
                StringComparison.Ordinal));

        Assert.Contains(ManifestDiagnosticCodes.BaseUrlInvalid, ErrorCodes(result));
        Assert.Null(result.Manifest);
        Assert.False(result.Succeeded);
    }

    /// <summary>
    /// Section-level findings from every section are still collected in one pass.
    /// </summary>
    /// <remarks>
    /// Failing wholesale is about not validating a partial model; it is not a reason to hide
    /// the other sections' defects from the author.
    /// </remarks>
    [Fact]
    public void Defects_in_several_sections_are_all_reported()
    {
        ManifestReadResult result = Read(
            """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Example API", "surfaces": [
                    { "slug": "a", "isDefault": true, "operations": [] },
                    { "slug": "a", "operations": [] } ] } },
                "policy": { "inline": { "baseUrl": "nonsense" } },
                "operations": { "inline": { "operations": [
                    { "key": "GET /pets", "method": "GET", "path": "/pets" },
                    { "key": "GET /pets", "method": "GET", "path": "/pets" } ] } },
                "agentSurface": { "inline": { "operations": [
                    { "slug": "x", "name": "X", "binding": { "type": "http", "operation": "GET /pets" } },
                    { "slug": "x", "name": "X", "binding": { "type": "http", "operation": "GET /pets" } } ] } }
              }
            }
            """);

        var codes = ErrorCodes(result);

        Assert.Contains(ManifestDiagnosticCodes.DuplicateSurfaceSlug, codes);
        Assert.Contains(ManifestDiagnosticCodes.BaseUrlInvalid, codes);
        Assert.Contains(ManifestDiagnosticCodes.DuplicateOperationKey, codes);
        Assert.Contains(ManifestDiagnosticCodes.DuplicateAgentSlug, codes);
        Assert.Null(result.Manifest);
    }

    [Fact]
    public void A_format_version_problem_stops_before_any_section_is_read()
    {
        ManifestReadResult result = Read(
            MinimalManifest.Replace("\"0.3\"", "\"9.0\"", StringComparison.Ordinal));

        Assert.Equal([ManifestDiagnosticCodes.FormatVersionUnsupported], ErrorCodes(result));
        Assert.Null(result.Manifest);
    }

    // ---- cross-section validation is part of reading ------------------------------------

    [Fact]
    public void Cross_section_defects_surface_through_the_reader()
    {
        ManifestReadResult result = Read(
            MinimalManifest.Replace("\"operation\": \"GET /pets\"", "\"operation\": \"GET /ghost\"", StringComparison.Ordinal));

        Assert.Equal([ManifestDiagnosticCodes.BindingOperationKeyUnknown], ErrorCodes(result));
        Assert.NotNull(result.Manifest);
        Assert.False(result.Succeeded);
    }

    /// <summary>
    /// A manifest produced by the reader always carries the documents reference resolution
    /// needs, so the validator's "document absent" path is unreachable in production.
    /// </summary>
    [Fact]
    public void A_read_manifest_retains_the_section_documents()
    {
        ManifestDocument manifest = Read(MinimalManifest).Manifest!;

        Assert.NotNull(manifest.OperationsDocument);
        Assert.NotNull(manifest.AgentSurfaceDocument);
    }

    // ---- narrowing happens before validation --------------------------------------------

    /// <summary>
    /// Local narrowing is applied before validation, so validation sees the perimeter that
    /// will actually be enforced.
    /// </summary>
    /// <remarks>
    /// Running narrowing afterwards would validate a policy the deployment never uses. Here a
    /// per-operation destination is inside the compiled perimeter but outside the narrowed
    /// one, which must be reported rather than passed.
    /// </remarks>
    [Fact]
    public void A_destination_removed_by_local_narrowing_is_reported()
    {
        const string Root =
            """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Example API" } },
                "policy": { "inline": { "baseUrl": "https://api.example.com",
                    "allowedOrigins": ["https://api.example.com", "https://eu.example.com"] } },
                "operations": { "inline": { "operations": [
                    { "key": "GET /pets", "method": "GET", "path": "/pets" } ] } },
                "agentSurface": { "inline": { "operations": [
                    { "slug": "list-pets", "name": "List pets", "binding": {
                        "type": "http", "operation": "GET /pets",
                        "serverUrl": "https://eu.example.com/v2" } } ] } }
              }
            }
            """;

        Assert.Empty(Read(Root).Errors);

        ManifestReadResult narrowed = Read(
            Root,
            new PolicyOverrides { AllowedOrigins = ["https://api.example.com"] });

        Assert.Equal([ManifestDiagnosticCodes.DestinationNotAllowed], ErrorCodes(narrowed));
    }

    [Fact]
    public void A_widening_override_is_refused_during_reading()
    {
        ManifestReadResult result = Read(
            MinimalManifest,
            new PolicyOverrides { RedirectHopLimit = 500 });

        Assert.Equal([ManifestDiagnosticCodes.LimitWidened], ErrorCodes(result));
    }

    [Fact]
    public void A_narrowing_override_reaches_the_manifest_policy()
    {
        ManifestDocument manifest = Read(
            MinimalManifest,
            new PolicyOverrides { Concurrency = 1, SchemaMaxNodes = 16 }).Manifest!;

        Assert.Equal(1, manifest.Policy.EffectiveLimits.Concurrency);
        Assert.Equal(16, manifest.Policy.EffectiveSchemaBounds.MaxNodes);
    }

    // ---- surface routing ----------------------------------------------------------------

    [Fact]
    public void The_bare_route_resolves_to_the_default_surface()
    {
        ManifestDocument manifest = Read(MinimalManifest).Manifest!;

        Assert.Equal("default", manifest.ResolveSurface(null)?.Slug);
        Assert.Equal("default", manifest.ResolveSurface(string.Empty)?.Slug);
        Assert.Equal("default", manifest.ResolveSurface("default")?.Slug);
        Assert.Null(manifest.ResolveSurface("missing"));
    }

    /// <summary>
    /// A disabled surface is indistinguishable from one that does not exist.
    /// </summary>
    [Fact]
    public void A_disabled_surface_is_not_resolvable_and_discloses_nothing()
    {
        ManifestReadResult result = Read(
            """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Example API", "surfaces": [
                    { "slug": "live", "isDefault": true, "operations": [
                        { "operation": "list-pets" } ] },
                    { "slug": "retired", "enabled": false, "operations": [
                        { "operation": "list-pets" } ] } ] } },
                "policy": { "inline": { "baseUrl": "https://api.example.com" } },
                "operations": { "inline": { "operations": [
                    { "key": "GET /pets", "method": "GET", "path": "/pets" } ] } },
                "agentSurface": { "inline": { "operations": [
                    { "slug": "list-pets", "name": "List pets",
                      "binding": { "type": "http", "operation": "GET /pets" } } ] } }
              }
            }
            """);

        Assert.Empty(result.Errors);
        Assert.Null(result.Manifest!.ResolveSurface("retired"));
        Assert.Equal("live", result.Manifest.ResolveSurface(null)?.Slug);
    }

    // ---- required-section list ----------------------------------------------------------

    [Fact]
    public void The_required_section_list_is_the_four_structural_sections()
        => Assert.Equal(
            [
                ManifestSectionName.Server,
                ManifestSectionName.Policy,
                ManifestSectionName.Operations,
                ManifestSectionName.AgentSurface,
            ],
            ManifestReader.RequiredSections);

    [Fact]
    public void Every_required_section_is_a_known_section()
        => Assert.All(ManifestReader.RequiredSections, name => Assert.True(ManifestSectionName.IsKnown(name)));

    [Fact]
    public void Independently_authored_v5_response_cache_sections_load_or_refuse_by_fixture_contract()
    {
        var fixture = JsonNode.Parse(File.ReadAllBytes(
            TestRepository.Fixture("response-cache", "contract.json")))!.AsObject();

        foreach (var entry in fixture["validSections"]!.AsArray())
        {
            var result = ReadWithAgentSurface(entry!["section"]!.DeepClone());
            Assert.True(
                result.Succeeded,
                $"Fixture '{entry["name"]!.GetValue<string>()}' failed: "
                + string.Join(" | ", result.Diagnostics.Select(static diagnostic => diagnostic.ToString())));
        }

        foreach (var entry in fixture["invalidSections"]!.AsArray())
        {
            var result = ReadWithAgentSurface(entry!["section"]!.DeepClone());
            var diagnosticCode = entry["diagnosticCode"]!.GetValue<string>();
            var pointer = entry["pointer"]!.GetValue<string>();
            var diagnostic = Assert.Single(result.Errors, item => item.Code == diagnosticCode);

            Assert.Equal(pointer, diagnostic.Pointer);
        }
    }

    private static ManifestReadResult ReadWithAgentSurface(JsonNode agentSurface)
    {
        var fixture = JsonNode.Parse(File.ReadAllBytes(
            TestRepository.Fixture("response-cache", "contract.json")))!.AsObject();
        var root = JsonNode.Parse(MinimalManifest)!.AsObject();
        var sections = root["sections"]!.AsObject();
        sections["agentSurface"]!.AsObject()["inline"] = agentSurface;
        sections["operations"]!.AsObject()["inline"]!["operations"] = fixture["httpOperations"]!.DeepClone();

        return Read(root.ToJsonString());
    }
}
