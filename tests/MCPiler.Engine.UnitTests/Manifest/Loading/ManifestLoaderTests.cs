using System.Text;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

public sealed class ManifestLoaderTests
{
    private const string MinimalRoot = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server":       { "inline": { "name": "Example API" } },
            "policy":       { "inline": { "baseUrl": "https://api.example.com" } },
            "operations":   { "inline": { "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ] } },
            "agentSurface": { "inline": { "operations": [
                { "slug": "list-pets", "name": "List pets",
                  "binding": { "type": "http", "operation": "GET /pets" } } ] } }
          }
        }
        """;

    [Fact]
    public void Loads_a_minimal_all_inline_manifest()
    {
        var result = Load(MinimalRoot);

        AssertNoErrors(result);
        Assert.True(result.Succeeded);
        Assert.NotNull(result.Root);
        Assert.Equal(new ManifestFormatVersion(0, 3), result.Root!.FormatVersion);
        Assert.Equal(4, result.Sections.Count);

        var server = result.Section(ManifestSectionName.Server);

        Assert.NotNull(server);
        Assert.True(server!.WasInline);
        Assert.False(server.IntegrityVerified);
        Assert.Equal("Example API", server.Document!["name"]!.GetValue<string>());
    }

    [Fact]
    public void A_minimal_manifest_stays_under_forty_lines()
    {
        // The authorability target: a working hand-written manifest is tens of lines, not
        // hundreds. If a required member is added without a default this assertion is what
        // notices.
        var lines = MinimalRoot.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;

        Assert.True(lines < 40, $"The minimal manifest grew to {lines} lines.");
        AssertNoErrors(Load(MinimalRoot));
    }

    [Fact]
    public void An_unsealed_manifest_loads_with_a_warning_that_names_the_lost_guarantee()
    {
        var result = Load(MinimalRoot);

        var warning = Assert.Single(result.Warnings);

        Assert.Equal(ManifestDiagnosticCodes.Unsealed, warning.Code);
        Assert.Contains("removed or truncated", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unsealed_manifest_is_refused_when_a_seal_is_required()
    {
        var result = Load(MinimalRoot, new ManifestLoadOptions { RequireSealed = true });

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == ManifestDiagnosticCodes.SealRequired);
        Assert.DoesNotContain(result.Diagnostics, d => d.Code == ManifestDiagnosticCodes.Unsealed);
    }

    [Fact]
    public void The_root_document_must_be_an_object()
    {
        var result = Load("[ 1, 2, 3 ]");

        Assert.False(result.Succeeded);
        Assert.Equal(ManifestDiagnosticCodes.RootNotAnObject, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void Unparseable_root_json_is_reported_as_a_packaging_failure()
    {
        var result = Load("{ not json");

        Assert.Equal(ManifestDiagnosticCodes.SectionUnparseable, Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData("""{ "sections": {} }""", ManifestDiagnosticCodes.FormatVersionMissing)]
    [InlineData("""{ "manifestFormatVersion": "0.1.0", "sections": {} }""", ManifestDiagnosticCodes.FormatVersionMalformed)]
    [InlineData("""{ "manifestFormatVersion": "01.1", "sections": {} }""", ManifestDiagnosticCodes.FormatVersionMalformed)]
    [InlineData("""{ "manifestFormatVersion": "9.0", "sections": {} }""", ManifestDiagnosticCodes.FormatVersionUnsupported)]
    public void A_format_version_problem_stops_loading_immediately(string root, string expectedCode)
    {
        var result = Load(root);

        Assert.False(result.Succeeded);
        Assert.Null(result.Root);
        Assert.Equal(expectedCode, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void A_version_refusal_names_the_observed_version_and_the_supported_range()
    {
        var error = Assert.Single(Load("""{ "manifestFormatVersion": "9.0", "sections": {} }""").Errors);

        Assert.Contains("9.0", error.Message, StringComparison.Ordinal);
        Assert.Contains(ManifestFormatSupport.SupportedRange, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_hostile_format_version_is_truncated_in_the_diagnostic()
    {
        var hostile = new string('9', 4096);
        var error = Assert.Single(Load($$"""{ "manifestFormatVersion": "{{hostile}}", "sections": {} }""").Errors);

        Assert.DoesNotContain(hostile, error.Message, StringComparison.Ordinal);
        Assert.Contains(DiagnosticText.TruncationMarker, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unknown_root_member_is_refused()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": {}, "polcy": { "baseUrl": "x" } }
            """);

        var error = Assert.Single(result.Errors, e => e.Code == ManifestDiagnosticCodes.UnknownMember);

        Assert.Equal("/polcy", error.Pointer);
        Assert.Contains("manifestFormatVersion", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unknown_section_name_is_refused_and_lists_the_known_names()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": { "polcy": { "inline": {} } } }
            """);

        var error = Assert.Single(result.Errors, e => e.Code == ManifestDiagnosticCodes.SectionUnknown);

        Assert.Equal("/sections/polcy", error.Pointer);
        Assert.Contains("agentSurface", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_section_name_is_matched_case_sensitively()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": { "agentsurface": { "inline": {} } } }
            """);

        Assert.Contains(result.Errors, e => e.Code == ManifestDiagnosticCodes.SectionUnknown);
    }

    [Fact]
    public void A_section_declaring_both_inline_and_path_is_refused()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3",
              "sections": { "policy": { "inline": {}, "path": "sections/policy.json" } } }
            """);

        Assert.Equal(
            ManifestDiagnosticCodes.SectionBothInlineAndPath,
            Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void A_section_declaring_neither_inline_nor_path_is_refused()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": { "policy": { "sha256": "abc" } } }
            """);

        Assert.Contains(
            result.Errors,
            e => e.Code == ManifestDiagnosticCodes.SectionNeitherInlineNorPath);
    }

    [Fact]
    public void A_section_that_is_not_an_object_is_refused()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": { "policy": "sections/policy.json" } }
            """);

        Assert.Equal(
            ManifestDiagnosticCodes.SectionNeitherInlineNorPath,
            Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void The_binary_vector_section_may_not_be_declared_inline()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": { "vectors": { "inline": "AAAA" } } }
            """);

        Assert.Equal(
            ManifestDiagnosticCodes.SectionMustBeExternal,
            Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData("sha256")]
    [InlineData("bytes")]
    public void An_integrity_declaration_on_an_inline_payload_is_refused(string member)
    {
        var value = member == "bytes" ? "12" : "\"abc\"";

        var result = Load($$"""
            { "manifestFormatVersion": "0.3",
              "sections": { "policy": { "inline": {}, "{{member}}": {{value}} } } }
            """);

        var error = Assert.Single(result.Errors);

        Assert.Equal(ManifestDiagnosticCodes.UnknownMember, error.Code);
        Assert.Equal("policy", error.Section);
        Assert.Contains("no meaning", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unknown_section_entry_member_is_refused()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3",
              "sections": { "policy": { "inline": {}, "sha512": "abc" } } }
            """);

        var error = Assert.Single(result.Errors, e => e.Code == ManifestDiagnosticCodes.UnknownMember);

        Assert.Equal("/sections/policy/sha512", error.Pointer);
    }

    [Fact]
    public void The_vector_section_accepts_its_model_and_dimension_members()
    {
        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3",
              "sections": { "vectors": { "path": "sections/vectors.bin",
                                         "model": "text-embedding-3-small", "dimension": 1536 } } }
            """,
            new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal)
            {
                ["sections/vectors.bin"] = new byte[] { 0x4D, 0x56, 0x4D, 0x58 },
            });

        AssertNoErrors(result);

        var entry = result.Root!.Section(ManifestSectionName.Vectors);

        Assert.Equal("text-embedding-3-small", entry!.Vectors!.Model);
        Assert.Equal(1536, entry.Vectors.Dimension);

        // A binary payload is carried as bytes and never parsed, so it can degrade instead of
        // failing the load.
        var resolved = result.Section(ManifestSectionName.Vectors);

        Assert.Null(resolved!.Document);
        Assert.Equal(4, resolved.Bytes.Length);
    }

    [Fact]
    public void A_malformed_vector_dimension_only_warns_because_the_section_degrades()
    {
        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3",
              "sections": { "vectors": { "path": "v.bin", "dimension": 0 } } }
            """,
            new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal) { ["v.bin"] = new byte[] { 1 } });

        Assert.True(result.Succeeded);
        Assert.Contains(result.Warnings, w => w.Code == ManifestDiagnosticCodes.VectorsDimensionMismatch);
    }

    [Fact]
    public void An_external_section_loads_and_reports_verified_integrity()
    {
        const string Payload = """{ "baseUrl": "https://api.example.com" }""";
        var bytes = Encoding.UTF8.GetBytes(Payload);
        var digest = CanonicalJson.ComputeHash(bytes);

        var result = LoadBundle(
            $$"""
            { "manifestFormatVersion": "0.3",
              "sections": { "policy": { "path": "sections/policy.json",
                                        "sha256": "{{digest}}", "bytes": {{bytes.Length}} } } }
            """,
            new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal)
            {
                ["sections/policy.json"] = bytes,
            });

        AssertNoErrors(result);

        var policy = result.Section(ManifestSectionName.Policy);

        Assert.False(policy!.WasInline);
        Assert.True(policy.IntegrityVerified);
        Assert.Equal("sections/policy.json", policy.DeclaredPath);
        Assert.Equal("https://api.example.com", policy.Document!["baseUrl"]!.GetValue<string>());
    }

    [Fact]
    public void An_external_section_without_a_digest_loads_unverified_rather_than_failing()
    {
        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3", "sections": { "policy": { "path": "p.json" } } }
            """,
            Text("p.json", """{ "baseUrl": "https://api.example.com" }"""));

        AssertNoErrors(result);
        Assert.False(result.Section(ManifestSectionName.Policy)!.IntegrityVerified);
    }

    [Fact]
    public void A_digest_mismatch_fails_closed_and_names_the_section()
    {
        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3",
              "sections": { "policy": { "path": "p.json", "sha256": "00" } } }
            """,
            Text("p.json", """{ "baseUrl": "https://api.example.com" }"""));

        var error = Assert.Single(result.Errors);

        Assert.Equal(ManifestDiagnosticCodes.SectionHashMismatch, error.Code);
        Assert.Equal("policy", error.Section);
        Assert.Equal("/sections/policy/sha256", error.Pointer);
    }

    [Fact]
    public void A_size_mismatch_fails_before_the_digest_is_even_computed()
    {
        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3",
              "sections": { "policy": { "path": "p.json", "sha256": "00", "bytes": 999 } } }
            """,
            Text("p.json", """{ "baseUrl": "https://api.example.com" }"""));

        var error = Assert.Single(result.Errors);

        Assert.Equal(ManifestDiagnosticCodes.SectionSizeMismatch, error.Code);
    }

    [Fact]
    public void A_non_integer_size_declaration_is_refused()
    {
        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3",
              "sections": { "policy": { "path": "p.json", "bytes": "many" } } }
            """,
            Text("p.json", "{}"));

        Assert.Equal(ManifestDiagnosticCodes.SectionSizeMismatch, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void A_missing_section_file_is_reported_with_its_section_name()
    {
        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3", "sections": { "policy": { "path": "absent.json" } } }
            """,
            new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal));

        var error = Assert.Single(result.Errors);

        Assert.Equal(ManifestDiagnosticCodes.SectionFileMissing, error.Code);
        Assert.Equal("policy", error.Section);
    }

    [Theory]
    [InlineData("../secrets.json")]
    [InlineData("/etc/passwd")]
    [InlineData("https://evil.example.com/policy.json")]
    [InlineData("sections\\policy.json")]
    public void A_path_that_leaves_the_bundle_is_refused_as_a_path_violation(string declared)
    {
        var result = LoadBundle(
            $$"""
            { "manifestFormatVersion": "0.3", "sections": { "policy": { "path": "{{declared.Replace("\\", "\\\\", StringComparison.Ordinal)}}" } } }
            """,
            new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal));

        var error = Assert.Single(result.Errors);

        Assert.Equal(ManifestDiagnosticCodes.SectionPathEscapesBundle, error.Code);
        Assert.Equal("policy", error.Section);
    }

    [Fact]
    public void An_unparseable_external_section_is_reported_against_its_path()
    {
        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3", "sections": { "policy": { "path": "p.json" } } }
            """,
            Text("p.json", "{ broken"));

        var error = Assert.Single(result.Errors);

        Assert.Equal(ManifestDiagnosticCodes.SectionUnparseable, error.Code);
        Assert.Equal("/sections/policy/path", error.Pointer);
    }

    [Fact]
    public void A_section_larger_than_the_load_limit_is_refused()
    {
        var payload = Encoding.UTF8.GetBytes("{\"padding\":\"" + new string('x', 512) + "\"}");

        var result = LoadBundle(
            """
            { "manifestFormatVersion": "0.3", "sections": { "policy": { "path": "p.json" } } }
            """,
            new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal) { ["p.json"] = payload },
            new ManifestLoadOptions { MaxSectionBytes = 64 });

        Assert.Contains(result.Errors, e => e.Code == ManifestDiagnosticCodes.SectionSizeMismatch);
    }

    [Fact]
    public void A_root_larger_than_the_load_limit_is_refused()
    {
        var result = Load(MinimalRoot, new ManifestLoadOptions { MaxRootBytes = 16 });

        Assert.Equal(ManifestDiagnosticCodes.SectionSizeMismatch, Assert.Single(result.Errors).Code);
        Assert.Null(result.Root);
    }

    [Fact]
    public void A_matching_completeness_seal_is_accepted()
    {
        var root = (JsonObject)JsonNode.Parse(MinimalRoot)!;
        var seal = CanonicalJson.Hash(root["sections"]);

        root["completeness"] = new JsonObject
        {
            ["algorithm"] = "sha256",
            ["value"] = seal,
        };

        var result = Load(root.ToJsonString());

        AssertNoErrors(result);
        Assert.True(result.Root!.IsSealed);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void A_sealed_manifest_detects_a_removed_section()
    {
        var root = (JsonObject)JsonNode.Parse(MinimalRoot)!;
        var seal = CanonicalJson.Hash(root["sections"]);

        root["completeness"] = new JsonObject { ["algorithm"] = "sha256", ["value"] = seal };

        // Removing a section leaves every surviving section internally consistent. Only a
        // seal over the index itself notices, which is why the seal covers the index rather
        // than the concatenated payloads.
        ((JsonObject)root["sections"]!).Remove("policy");

        var result = Load(root.ToJsonString());

        var error = Assert.Single(result.Errors);

        Assert.Equal(ManifestDiagnosticCodes.CompletenessMismatch, error.Code);
        Assert.Equal("/completeness/value", error.Pointer);
    }

    [Fact]
    public void A_seal_survives_member_reordering_because_it_is_computed_canonically()
    {
        var root = (JsonObject)JsonNode.Parse(MinimalRoot)!;
        var seal = CanonicalJson.Hash(root["sections"]);

        var reordered = new JsonObject
        {
            ["sections"] = ReorderedSections(),
            ["completeness"] = new JsonObject { ["algorithm"] = "sha256", ["value"] = seal },
            ["manifestFormatVersion"] = "0.3",
        };

        AssertNoErrors(Load(reordered.ToJsonString()));

        static JsonObject ReorderedSections()
        {
            var original = (JsonObject)JsonNode.Parse(MinimalRoot)!["sections"]!;
            var reordered = new JsonObject();

            foreach (var name in new[] { "agentSurface", "operations", "policy", "server" })
            {
                reordered[name] = original[name]!.DeepClone();
            }

            return reordered;
        }
    }

    [Theory]
    [InlineData("sha512")]
    [InlineData("SHA256")]
    [InlineData("")]
    public void An_unknown_completeness_algorithm_is_refused(string algorithm)
    {
        var result = Load($$"""
            { "manifestFormatVersion": "0.3", "sections": {},
              "completeness": { "algorithm": "{{algorithm}}", "value": "00" } }
            """);

        Assert.Contains(
            result.Errors,
            e => e.Code == ManifestDiagnosticCodes.CompletenessAlgorithmUnknown);
    }

    [Fact]
    public void A_completeness_seal_without_a_value_is_refused()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": {},
              "completeness": { "algorithm": "sha256" } }
            """);

        Assert.Contains(result.Errors, e => e.Code == ManifestDiagnosticCodes.CompletenessMismatch);
    }

    [Fact]
    public void Provenance_is_carried_opaquely_and_never_inspected()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3",
              "sections": { "policy": { "inline": { "baseUrl": "https://api.example.com" } } },
              "provenance": { "connectorId": "abc", "anythingAtAll": [ 1, { "deep": true } ],
                              "polcy": "a member name that would be refused anywhere else" } }
            """);

        AssertNoErrors(result);
        Assert.NotNull(result.Root!.Provenance);
        Assert.Equal("abc", result.Root.Provenance!["connectorId"]!.GetValue<string>());
    }

    [Fact]
    public void Provenance_must_still_be_an_object()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": {}, "provenance": [ 1 ] }
            """);

        Assert.Contains(result.Errors, e => e.Code == ManifestDiagnosticCodes.UnknownMember);
    }

    [Fact]
    public void Generator_information_is_read_for_diagnostics()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": {},
              "generator": { "name": "mcpiler-studio", "version": "0.6.0",
                             "producedAtUtc": "2026-09-07T10:00:00Z" } }
            """);

        AssertNoErrors(result);
        Assert.Equal("mcpiler-studio", result.Root!.Generator!.Name);
        Assert.Equal("0.6.0", result.Root.Generator.Version);
        Assert.Equal(new DateTime(2026, 9, 7, 10, 0, 0, DateTimeKind.Utc), result.Root.Generator.ProducedAtUtc);
    }

    [Fact]
    public void A_malformed_generator_timestamp_only_warns_because_it_is_diagnostic_only()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": {},
              "generator": { "producedAtUtc": "yesterday" } }
            """);

        Assert.True(result.Succeeded);
        Assert.Contains(result.Warnings, w => w.Pointer == "/generator/producedAtUtc");
        Assert.Null(result.Root!.Generator!.ProducedAtUtc);
    }

    [Fact]
    public void An_unknown_generator_member_is_refused()
    {
        var result = Load("""
            { "manifestFormatVersion": "0.3", "sections": {},
              "generator": { "buildHost": "ci-01" } }
            """);

        var error = Assert.Single(result.Errors, e => e.Code == ManifestDiagnosticCodes.UnknownMember);

        Assert.Equal("/generator/buildHost", error.Pointer);
    }

    [Fact]
    public void A_missing_sections_index_is_refused()
    {
        var result = Load("""{ "manifestFormatVersion": "0.3" }""");

        Assert.Equal(ManifestDiagnosticCodes.SectionMissing, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void Every_problem_is_reported_rather_than_only_the_first()
    {
        // The loader is also the authoring tool for hand-written manifests, so stopping at
        // the first error would make fixing a manifest an iterative guessing game.
        var result = Load("""
            { "manifestFormatVersion": "0.3",
              "unknownOne": 1,
              "unknownTwo": 2,
              "sections": { "polcy": { "inline": {} }, "srvr": { "inline": {} } } }
            """);

        Assert.Equal(2, result.Errors.Count(e => e.Code == ManifestDiagnosticCodes.UnknownMember));
        Assert.Equal(2, result.Errors.Count(e => e.Code == ManifestDiagnosticCodes.SectionUnknown));
    }

    [Fact]
    public void Every_diagnostic_carries_a_code_from_the_published_catalogue()
    {
        var results = new[]
        {
            Load("[ ]"),
            Load("{ broken"),
            Load("""{ "manifestFormatVersion": "0.3" }"""),
            Load("""{ "manifestFormatVersion": "9.9", "sections": {} }"""),
            Load(MinimalRoot),
            Load("""
                { "manifestFormatVersion": "0.3", "unknown": 1,
                  "sections": { "vectors": { "inline": "x" }, "policy": { "inline": {}, "path": "p" } } }
                """),
        };

        foreach (var diagnostic in results.SelectMany(static result => result.Diagnostics))
        {
            Assert.Contains(diagnostic.Code, ManifestDiagnosticCodes.All);

            if (ManifestDiagnosticCodes.AlwaysWarning.Contains(diagnostic.Code))
            {
                Assert.False(
                    diagnostic.IsError,
                    $"{diagnostic.Code} is declared always-warning but was reported as an error.");
            }
        }
    }

    [Fact]
    public void A_diagnostic_renders_its_severity_code_and_location()
    {
        var rendered = ManifestDiagnostic
            .Error(ManifestDiagnosticCodes.SectionHashMismatch, "Digest mismatch.", "policy", "/sha256")
            .ToString();

        Assert.Equal("error manifest/section-hash-mismatch at policy/sha256: Digest mismatch.", rendered);
    }

    [Fact]
    public void The_loader_requires_a_source()
    {
        Assert.Throws<ArgumentNullException>(() => ManifestLoader.Load(null!));
    }

    private static ManifestLoadResult Load(string root, ManifestLoadOptions? options = null)
        => ManifestLoader.Load(InMemoryManifestSource.FromText(root), options);

    private static ManifestLoadResult LoadBundle(
        string root,
        IReadOnlyDictionary<string, ReadOnlyMemory<byte>> sections,
        ManifestLoadOptions? options = null)
        => ManifestLoader.Load(
            new InMemoryManifestSource(Encoding.UTF8.GetBytes(root), sections),
            options);

    private static Dictionary<string, ReadOnlyMemory<byte>> Text(string path, string payload)
        => new(StringComparer.Ordinal) { [path] = Encoding.UTF8.GetBytes(payload) };

    private static void AssertNoErrors(ManifestLoadResult result)
    {
        Assert.True(
            !result.HasErrors,
            "Unexpected errors: " + string.Join("; ", result.Errors.Select(static e => e.ToString())));
    }
}
