using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using Xunit;
using ModelVocabulary = MCPiler.Engine.Manifest.Model.Vocabulary;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// The published schemas under <c>schemas/manifest-0.1/</c> describe the format for editors
/// and third-party tooling. The readers remain the runtime authority, so the schemas are a
/// second statement of the same rules and would drift silently if nobody watched them.
/// These tests are the watch: they compare the schemas against the corpus in both directions
/// and against the readers' own member lists and vocabularies by reflection.
/// </summary>
public sealed class PublishedSchemaTests
{
    private const string SchemaDirectory = "schemas/manifest-0.1";

    private static readonly IReadOnlyDictionary<string, string> SectionSchemaIds =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [ManifestSectionName.Server] = "urn:mcpiler:manifest:0.1:server",
            [ManifestSectionName.Policy] = "urn:mcpiler:manifest:0.1:policy",
            [ManifestSectionName.Credentials] = "urn:mcpiler:manifest:0.1:credentials",
            [ManifestSectionName.Operations] = "urn:mcpiler:manifest:0.1:operations",
            [ManifestSectionName.AgentSurface] = "urn:mcpiler:manifest:0.1:agent-surface",
            [ManifestSectionName.Tools] = "urn:mcpiler:manifest:0.1:tools",
            [ManifestSectionName.Search] = "urn:mcpiler:manifest:0.1:search",
        };

    private static string CorpusRoot => ManifestCorpus.Root;

    private static string SchemaRoot => Path.Combine(TestRepository.Root, SchemaDirectory);

    public static TheoryData<string> ValidFixtures()
    {
        var data = new TheoryData<string>();

        foreach (var name in ValidFixtureNames())
        {
            data.Add(name);
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

    public static TheoryData<string> HostileBundles()
    {
        var data = new TheoryData<string>();

        foreach (var directory in Directory.GetDirectories(Path.Combine(CorpusRoot, "hostile", "bundle")))
        {
            data.Add(Path.GetFileName(directory)!);
        }

        return data;
    }

    public static TheoryData<string> SchemaFiles()
    {
        var data = new TheoryData<string>();

        foreach (var file in Directory.GetFiles(SchemaRoot, "*.schema.json").Order(StringComparer.Ordinal))
        {
            data.Add(Path.GetFileName(file));
        }

        return data;
    }

    [Fact]
    public void EverySectionThatHasADocumentHasASchema()
    {
        // The vector section is binary and has no document of its own; its index entry is
        // described in the root schema. Every other section must be describable.
        var described = SectionSchemaIds.Keys.Append(ManifestSectionName.Vectors);

        Assert.Equal(
            ManifestSectionName.All.Order(StringComparer.Ordinal),
            described.Order(StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(SchemaFiles))]
    public void ASchemaFileIsItselfAValidSchema(string file)
    {
        var document = JsonNode.Parse(File.ReadAllText(Path.Combine(SchemaRoot, file)));
        var metaSchema = MetaSchemas.Draft202012;

        var results = metaSchema.Evaluate(JsonSerializer.SerializeToElement(document), Options);

        Assert.True(results.IsValid, Explain(file, results));
    }

    [Theory]
    [MemberData(nameof(SchemaFiles))]
    public void ASchemaFileDeclaresTheDraftAndAStableIdentifier(string file)
    {
        var document = JsonNode.Parse(File.ReadAllText(Path.Combine(SchemaRoot, file)))!.AsObject();

        Assert.Equal(
            "https://json-schema.org/draft/2020-12/schema",
            document["$schema"]!.GetValue<string>());

        // A URN rather than an https identifier: Engine has no published schema host yet,
        // and an identifier that does not resolve is worse than one that never promised to.
        Assert.StartsWith(
            "urn:mcpiler:manifest:0.1:",
            document["$id"]!.GetValue<string>(),
            StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(ValidFixtures))]
    public void AValidFixtureValidatesAgainstThePublishedSchemas(string fixture)
    {
        var failures = ValidateBundle(Path.Combine(CorpusRoot, fixture));

        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }

    [Theory]
    [MemberData(nameof(HostileDocuments))]
    public void AHostileDocumentFallsOnTheSideTheCorpusDeclares(string name)
    {
        var entry = DocumentCases()[name];
        var failures = ValidateDocument(entry.Document);
        var refused = failures.Count > 0;

        if (entry.SchemaRefuses)
        {
            Assert.True(
                refused,
                $"'{name}' declares schemaRefuses true, but the published schemas accepted it. "
                + $"Either the schema is missing a rule the reader has, or the declaration is wrong.");

            // A refusal that does not say where is not usable by an author or an editor,
            // so the location is part of what is being asserted, not incidental output.
            Assert.All(failures, failure => Assert.Contains("    at ", failure, StringComparison.Ordinal));
        }
        else
        {
            Assert.False(
                refused,
                $"'{name}' declares schemaRefuses false, but the published schemas refused it:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, failures));
        }
    }

    [Theory]
    [MemberData(nameof(HostileBundles))]
    public void AHostileBundleFallsOnTheSideTheCorpusDeclares(string bundle)
    {
        var directory = Path.Combine(CorpusRoot, "hostile", "bundle", bundle);
        var expectation = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "expected.json")))!.AsObject();
        var declared = ReadSchemaRefuses(expectation, bundle);

        // Only the root document is checked here. A bundle case attacks the relationship
        // between the index and the files on disk, which is where the reader lives and
        // where a schema, by construction, cannot look.
        var failures = ValidateRoot(File.ReadAllText(Path.Combine(directory, "manifest.json")));

        Assert.Equal(declared, failures.Count > 0);
    }

    [Fact]
    public void EveryHostileCaseDeclaresWhichSideItFallsOn()
    {
        // Without this the flag could be forgotten on a new case, and a forgotten flag would
        // quietly count as "the schema need not catch it" — exactly how a description drifts
        // away from the thing it describes. Reading both sources here makes the omission an
        // error at the corpus, not a silently weakened assertion somewhere else.
        Assert.NotEmpty(DocumentCases());

        var bundles = Directory.GetDirectories(Path.Combine(CorpusRoot, "hostile", "bundle"));

        Assert.NotEmpty(bundles);

        foreach (var directory in bundles)
        {
            var name = Path.GetFileName(directory)!;
            var expectation = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "expected.json")))!.AsObject();

            ReadSchemaRefuses(expectation, name);
        }
    }

    [Fact]
    public void TheSchemaCatchesTheStructuralHalfOfTheHostileCorpus()
    {
        // A guard against the schemas quietly degrading into "accepts everything": if this
        // number collapses, the schemas stopped describing anything worth describing.
        var refusing = DocumentCases().Values.Count(entry => entry.SchemaRefuses);

        Assert.True(
            refusing >= 12,
            $"Only {refusing} hostile cases are declared schema-refusable; the published schemas "
            + "are no longer describing the format's shape.");
    }

    [Theory]
    [MemberData(nameof(MemberSetLocations))]
    public void TheAcceptedMemberSetMatchesTheReader(string label)
    {
        var location = MemberSetTable().Single(entry =>
            string.Equals(entry.Label, label, StringComparison.Ordinal));

        var document = JsonNode.Parse(File.ReadAllText(Path.Combine(SchemaRoot, location.File)))!;
        var accepted = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var pointer in location.Pointers)
        {
            var node = Resolve(document, pointer)
                ?? throw new InvalidOperationException($"{location.File}{pointer} does not exist.");

            var subschema = node.AsObject();

            Assert.True(
                subschema["additionalProperties"] is JsonValue closed && !closed.GetValue<bool>(),
                $"{location.File}{pointer} must declare \"additionalProperties\": false, otherwise it "
                + "accepts members the reader refuses.");

            if (subschema["properties"] is JsonObject properties)
            {
                foreach (var (name, _) in properties)
                {
                    accepted.Add(name);
                }
            }
        }

        Assert.Equal(
            location.ReaderMembers.Order(StringComparer.Ordinal).ToList(),
            accepted.ToList());
    }

    [Fact]
    public void EveryReaderMemberListHasASchemaLocation()
    {
        // Reflection rather than a hand-kept list: adding a member list to a reader without
        // describing it in the published schemas must fail here, not in somebody's editor.
        var described = MemberSetTable()
            .Select(entry => entry.Origin)
            .ToHashSet(StringComparer.Ordinal);

        var declared = ReaderMemberListNames();

        Assert.Equal(
            declared.Order(StringComparer.Ordinal).ToList(),
            described.Order(StringComparer.Ordinal).ToList());
    }

    [Fact]
    public void ClosedVocabulariesMatchTheModel()
    {
        AssertEnum("server.schema.json", "#/$defs/surfaceOperation/properties/exposure", ModelVocabulary.ExposureNames);
        AssertEnum("operations.schema.json", "#/$defs/parameter/properties/in", ModelVocabulary.ParameterLocationNames);
        AssertEnum("operations.schema.json", "#/$defs/style", ModelVocabulary.ParameterStyleNames);
        AssertEnum("agent-surface.schema.json", "#/$defs/operation/properties/kind", ModelVocabulary.OperationKindNames);
        AssertEnum(
            "agent-surface.schema.json",
            "#/$defs/operation/properties/outputSchemaPolicy/properties/advertise",
            ModelVocabulary.AdvertisementNames);
        AssertEnum(
            "agent-surface.schema.json",
            "#/$defs/compoundBinding/properties/failurePolicy",
            ModelVocabulary.FailurePolicyNames);
        AssertEnum("credentials.schema.json", "#/$defs/credential/properties/scheme", ModelVocabulary.CredentialSchemeNames);
        AssertEnum("credentials.schema.json", "#/$defs/credential/properties/location", ModelVocabulary.CredentialLocationNames);
    }

    [Fact]
    public void TheSchemaDescribesTheCanonicalCasing()
    {
        // A deliberate, and the only, divergence. The readers match a closed vocabulary
        // case-insensitively as a courtesy to hand authors; the published schema describes
        // the form to write. An editor flagging "Direct" is the intended behaviour.
        const string document = """
        {
          "manifestFormatVersion": "0.1",
          "sections": {
            "server": { "inline": { "name": "Casing", "surfaces": [ { "slug": "default", "isDefault": true,
              "operations": [ { "operation": "ping", "exposure": "Direct" } ] } ] } },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": { "inline": { "operations": [ { "method": "GET", "path": "/ping" } ] } },
            "agentSurface": { "inline": { "operations": [ { "slug": "ping", "name": "Ping",
              "binding": { "type": "http", "operation": "GET /ping" } } ] } }
          }
        }
        """;

        Assert.True(ManifestReader.Read(InMemoryManifestSource.FromText(document)).Succeeded);
        Assert.NotEmpty(ValidateDocument(document));
    }

    [Fact]
    public void ASchemaValueSurvivesUnrecognisedKeywords()
    {
        // Schema values are carried verbatim, so the published schema must not constrain the
        // keyword set. Constraining it would refuse a manifest the reader serves happily.
        var value = JsonNode.Parse("""
        { "type": "object", "x-vendor-hint": { "anything": [1, 2] }, "minimum": 1.50 }
        """);

        var results = Evaluate("urn:mcpiler:manifest:0.1:schema", value);

        Assert.True(results.IsValid, Explain("schema.schema.json", results));
    }

    [Fact]
    public void ASchemaValueMustReferenceLocally()
    {
        var value = JsonNode.Parse("""{ "$ref": "https://example.com/Pet" }""");

        var results = Evaluate("urn:mcpiler:manifest:0.1:schema", value);

        Assert.False(results.IsValid);
    }

    public static TheoryData<string> MemberSetLocations()
    {
        var data = new TheoryData<string>();

        foreach (var entry in MemberSetTable())
        {
            data.Add(entry.Label);
        }

        return data;
    }

    private static void AssertEnum(string file, string pointer, IReadOnlyList<string> expected)
    {
        var document = JsonNode.Parse(File.ReadAllText(Path.Combine(SchemaRoot, file)))!;
        var node = Resolve(document, pointer)
            ?? throw new InvalidOperationException($"{file}{pointer} does not exist.");

        var declared = node.AsObject()["enum"]!.AsArray()
            .Select(item => item!.GetValue<string>())
            .ToList();

        Assert.Equal(expected.Order(StringComparer.Ordinal).ToList(), declared.Order(StringComparer.Ordinal).ToList());
    }

    private static IReadOnlyList<string> ValidateBundle(string directory)
    {
        var rootText = File.ReadAllText(Path.Combine(directory, DirectoryManifestSource.RootFileName));
        var failures = ValidateRoot(rootText).ToList();
        var root = JsonNode.Parse(rootText)!.AsObject();

        if (root["sections"] is not JsonObject sections)
        {
            return failures;
        }

        foreach (var (name, entry) in sections)
        {
            if (entry is not JsonObject declaration || !SectionSchemaIds.ContainsKey(name))
            {
                continue;
            }

            var payload = declaration["inline"];

            if (payload is null && declaration["path"]?.GetValue<string>() is { } relative)
            {
                var file = Path.Combine(directory, relative.Replace('/', Path.DirectorySeparatorChar));

                if (!File.Exists(file))
                {
                    continue;
                }

                payload = JsonNode.Parse(File.ReadAllText(file));
            }

            failures.AddRange(ValidateSection(name, payload));
        }

        return failures;
    }

    private static IReadOnlyList<string> ValidateDocument(string documentText)
    {
        var failures = ValidateRoot(documentText).ToList();

        if (JsonNode.Parse(documentText) is not JsonObject root || root["sections"] is not JsonObject sections)
        {
            return failures;
        }

        foreach (var (name, entry) in sections)
        {
            if (entry is JsonObject declaration
                && declaration["inline"] is { } payload
                && SectionSchemaIds.ContainsKey(name))
            {
                failures.AddRange(ValidateSection(name, payload));
            }
        }

        return failures;
    }

    private static IReadOnlyList<string> ValidateRoot(string documentText)
    {
        var document = JsonNode.Parse(documentText);
        var results = Evaluate("urn:mcpiler:manifest:0.1:root", document);

        return results.IsValid ? [] : [Explain("root", results)];
    }

    private static IReadOnlyList<string> ValidateSection(string name, JsonNode? payload)
    {
        if (payload is null)
        {
            return [];
        }

        var results = Evaluate(SectionSchemaIds[name], payload);

        return results.IsValid ? [] : [Explain(name, results)];
    }

    private static readonly EvaluationOptions Options = new() { OutputFormat = OutputFormat.List };

    private static readonly Lazy<IReadOnlyDictionary<string, JsonSchema>> Loaded = new(Load);

    private static IReadOnlyDictionary<string, JsonSchema> Load()
    {
        var byId = new Dictionary<string, JsonSchema>(StringComparer.Ordinal);

        foreach (var file in Directory.GetFiles(SchemaRoot, "*.schema.json").Order(StringComparer.Ordinal))
        {
            var text = File.ReadAllText(file);
            var id = JsonNode.Parse(text)!.AsObject()["$id"]!.GetValue<string>();
            var schema = JsonSchema.FromText(text);

            // The evaluator resolves cross-document references through its registry, which in
            // this version is process wide. Registering once keeps the URNs resolvable without
            // each test rebuilding the set.
            SchemaRegistry.Global.Register(new Uri(id), schema);
            byId[id] = schema;
        }

        return byId;
    }

    private static EvaluationResults Evaluate(string id, JsonNode? instance) =>
        Loaded.Value[id].Evaluate(JsonSerializer.SerializeToElement(instance), Options);

    private static string Explain(string what, EvaluationResults results)
    {
        var details = (results.Details ?? [])
            .Where(detail => detail.Errors is { Count: > 0 })
            .SelectMany(detail => detail.Errors!.Select(error =>
                $"    at {Where(detail.InstanceLocation.ToString())} "
                + $"({Where(detail.EvaluationPath.ToString())}): {error.Value}"))
            .Take(12);

        return $"{what} failed validation:" + Environment.NewLine + string.Join(Environment.NewLine, details);
    }

    // An empty JSON Pointer addresses the whole document, which is a real location and the
    // only correct one when the document itself is the wrong shape. Rendering it as nothing
    // would make a located error look unlocated.
    private static string Where(string pointer) => pointer.Length == 0 ? "#" : pointer;

    private static JsonNode? Resolve(JsonNode document, string pointer)
    {
        var current = document;

        foreach (var segment in pointer.TrimStart('#').Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var name = segment.Replace("~1", "/", StringComparison.Ordinal)
                .Replace("~0", "~", StringComparison.Ordinal);

            current = current switch
            {
                JsonObject o => o[name],
                JsonArray a when int.TryParse(name, out var index) && index < a.Count => a[index],
                _ => null,
            };

            if (current is null)
            {
                return null;
            }
        }

        return current;
    }

    private static IReadOnlyList<string> ReaderMemberListNames() =>
        typeof(ManifestLoader).Assembly
            .GetTypes()
            .Where(type => string.Equals(
                type.Namespace,
                "MCPiler.Engine.Manifest.Loading",
                StringComparison.Ordinal))
            .SelectMany(type => type
                .GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
                .Where(field => field.IsAssembly
                    && field.FieldType == typeof(string[])
                    && field.Name.EndsWith("Members", StringComparison.Ordinal))
                .Select(field => $"{type.Name}.{field.Name}"))
            .ToList();

    private sealed record MemberSetLocation(
        string Origin,
        string File,
        IReadOnlyList<string> Pointers,
        IReadOnlyList<string> ReaderMembers)
    {
        public string Label => Origin;
    }

    private static IReadOnlyList<MemberSetLocation> MemberSetTable() =>
    [
        new("ManifestLoader.RootMembers", "root.schema.json", ["#"], ManifestLoader.RootMembers),
        new("ManifestLoader.GeneratorMembers", "root.schema.json", ["#/properties/generator"], ManifestLoader.GeneratorMembers),
        new("ManifestLoader.CompletenessMembers", "root.schema.json", ["#/properties/completeness"], ManifestLoader.CompletenessMembers),
        new(
            "ManifestLoader.SectionEntryMembers",
            "root.schema.json",
            ["#/$defs/sectionEntry/oneOf/0", "#/$defs/sectionEntry/oneOf/1"],
            ManifestLoader.SectionEntryMembers),
        new("ManifestLoader.VectorSectionEntryMembers", "root.schema.json", ["#/$defs/vectorSectionEntry"], ManifestLoader.VectorSectionEntryMembers),

        new("ServerSectionReader.SectionMembers", "server.schema.json", ["#"], ServerSectionReader.SectionMembers),
        new("ServerSectionReader.SurfaceMembers", "server.schema.json", ["#/$defs/surface"], ServerSectionReader.SurfaceMembers),
        new("ServerSectionReader.NavigatorMembers", "server.schema.json", ["#/$defs/surface/properties/navigator"], ServerSectionReader.NavigatorMembers),
        new("ServerSectionReader.OperationMembers", "server.schema.json", ["#/$defs/surfaceOperation"], ServerSectionReader.OperationMembers),

        new("PolicySectionReader.SectionMembers", "policy.schema.json", ["#"], PolicySectionReader.SectionMembers),
        new("PolicySectionReader.LimitMembers", "policy.schema.json", ["#/properties/limits"], PolicySectionReader.LimitMembers),
        new("PolicySectionReader.CeilingMembers", "policy.schema.json", ["#/properties/transformCeiling"], PolicySectionReader.CeilingMembers),
        new("PolicySectionReader.CompoundMembers", "policy.schema.json", ["#/properties/compound"], PolicySectionReader.CompoundMembers),
        new("PolicySectionReader.SchemaBoundMembers", "policy.schema.json", ["#/properties/schemaBounds"], PolicySectionReader.SchemaBoundMembers),
        new("PolicySectionReader.FileMembers", "policy.schema.json", ["#/properties/files"], PolicySectionReader.FileMembers),

        new("CredentialsSectionReader.SectionMembers", "credentials.schema.json", ["#"], CredentialsSectionReader.SectionMembers),
        new("CredentialsSectionReader.CredentialMembers", "credentials.schema.json", ["#/$defs/credential"], CredentialsSectionReader.CredentialMembers),
        new(
            "CredentialsSectionReader.ValueMembers",
            "credentials.schema.json",
            ["#/$defs/reference/oneOf/0", "#/$defs/reference/oneOf/1", "#/$defs/reference/oneOf/2"],
            CredentialsSectionReader.ValueMembers),

        new("OperationsSectionReader.SectionMembers", "operations.schema.json", ["#"], OperationsSectionReader.SectionMembers),
        new("OperationsSectionReader.OperationMembers", "operations.schema.json", ["#/$defs/operation"], OperationsSectionReader.OperationMembers),
        new("OperationsSectionReader.ParameterMembers", "operations.schema.json", ["#/$defs/parameter"], OperationsSectionReader.ParameterMembers),
        new("OperationsSectionReader.RequestBodyMembers", "operations.schema.json", ["#/$defs/requestBody"], OperationsSectionReader.RequestBodyMembers),
        new("OperationsSectionReader.ResponseMembers", "operations.schema.json", ["#/$defs/response"], OperationsSectionReader.ResponseMembers),
        new("OperationsSectionReader.MediaTypeMembers", "operations.schema.json", ["#/$defs/mediaType"], OperationsSectionReader.MediaTypeMembers),
        new("OperationsSectionReader.EncodingMembers", "operations.schema.json", ["#/$defs/encoding"], OperationsSectionReader.EncodingMembers),
        new("OperationsSectionReader.SecuritySchemeMembers", "operations.schema.json", ["#/$defs/securityScheme"], OperationsSectionReader.SecuritySchemeMembers),

        new("AgentSurfaceSectionReader.SectionMembers", "agent-surface.schema.json", ["#"], AgentSurfaceSectionReader.SectionMembers),
        new("AgentSurfaceSectionReader.GroupMembers", "agent-surface.schema.json", ["#/$defs/group"], AgentSurfaceSectionReader.GroupMembers),
        new("AgentSurfaceSectionReader.OperationMembers", "agent-surface.schema.json", ["#/$defs/operation"], AgentSurfaceSectionReader.OperationMembers),
        new("AgentSurfaceSectionReader.PolicyMembers", "agent-surface.schema.json", ["#/$defs/operation/properties/outputSchemaPolicy"], AgentSurfaceSectionReader.PolicyMembers),
        new("AgentSurfaceSectionReader.AnnotationMembers", "agent-surface.schema.json", ["#/$defs/annotations"], AgentSurfaceSectionReader.AnnotationMembers),
        new("AgentSurfaceSectionReader.SearchMembers", "agent-surface.schema.json", ["#/$defs/operation/properties/search"], AgentSurfaceSectionReader.SearchMembers),
        new("AgentSurfaceSectionReader.HttpBindingMembers", "agent-surface.schema.json", ["#/$defs/httpBinding"], AgentSurfaceSectionReader.HttpBindingMembers),
        new("AgentSurfaceSectionReader.HttpBaseMembers", "agent-surface.schema.json", ["#/$defs/transformedBinding/properties/base"], AgentSurfaceSectionReader.HttpBaseMembers),
        new("AgentSurfaceSectionReader.TransformedBindingMembers", "agent-surface.schema.json", ["#/$defs/transformedBinding"], AgentSurfaceSectionReader.TransformedBindingMembers),
        new("AgentSurfaceSectionReader.CompoundBindingMembers", "agent-surface.schema.json", ["#/$defs/compoundBinding"], AgentSurfaceSectionReader.CompoundBindingMembers),
        new("AgentSurfaceSectionReader.StepMembers", "agent-surface.schema.json", ["#/$defs/step"], AgentSurfaceSectionReader.StepMembers),
        new(
            "AgentSurfaceSectionReader.MappingMembers",
            "agent-surface.schema.json",
            ["#/$defs/stepInputMapping", "#/$defs/outputEntry"],
            AgentSurfaceSectionReader.MappingMembers),
        new("AgentSurfaceSectionReader.OutputSelectionMembers", "agent-surface.schema.json", ["#/$defs/compoundBinding/properties/outputSelection"], AgentSurfaceSectionReader.OutputSelectionMembers),

        new("DerivedSectionReader.ToolsSectionMembers", "tools.schema.json", ["#"], DerivedSectionReader.ToolsSectionMembers),
        new("DerivedSectionReader.SurfaceToolSetMembers", "tools.schema.json", ["#/$defs/surfaceToolSet"], DerivedSectionReader.SurfaceToolSetMembers),
        new("DerivedSectionReader.ToolMembers", "tools.schema.json", ["#/$defs/tool"], DerivedSectionReader.ToolMembers),
        new("DerivedSectionReader.AnnotationMembers", "tools.schema.json", ["#/$defs/tool/properties/annotations"], DerivedSectionReader.AnnotationMembers),
        new("DerivedSectionReader.SearchSectionMembers", "search.schema.json", ["#"], DerivedSectionReader.SearchSectionMembers),
        new("DerivedSectionReader.ScoringMembers", "search.schema.json", ["#/properties/scoring"], DerivedSectionReader.ScoringMembers),
        new("DerivedSectionReader.SearchDocumentMembers", "search.schema.json", ["#/$defs/document"], DerivedSectionReader.SearchDocumentMembers),
    ];

    private static IReadOnlyList<string> ValidFixtureNames() => ManifestCorpus.BundleNames();


    private static bool ReadSchemaRefuses(JsonObject element, string name)
    {
        var declared = element["schemaRefuses"]
            ?? throw new InvalidOperationException(
                $"Hostile case '{name}' does not declare 'schemaRefuses'. Every case must record "
                + "whether the published schemas catch it, so the split stays a decision.");

        return declared.GetValue<bool>();
    }

    private static IReadOnlyDictionary<string, (string Document, bool SchemaRefuses)> DocumentCases()
    {
        var path = Path.Combine(CorpusRoot, "hostile", "document-cases.json");
        var root = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        var parsed = new Dictionary<string, (string, bool)>(StringComparer.Ordinal);

        foreach (var entry in root["cases"]!.AsArray())
        {
            var element = entry!.AsObject();
            var name = element["name"]!.GetValue<string>();

            parsed[name] = (element["manifest"]!.ToJsonString(), ReadSchemaRefuses(element, name));
        }

        return parsed;
    }
}
