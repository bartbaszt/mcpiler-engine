using System.Text.Json.Nodes;
using EngineManifest = MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// Pins the Engine half of the shared manifest defaults contract.
/// </summary>
/// <remarks>
/// <para>
/// An omitted member asserts that the documented default applies. The producer decides what to
/// omit and this reader decides what an omission means, and the two live in separate
/// repositories with no shared code. A disagreement changes what a manifest means without
/// changing a byte of it.
/// </para>
/// <para>
/// <c>tests/fixtures/manifests/defaults.json</c> states every default once and is duplicated
/// byte-identically into the Platform repository, where the compiler's constants are asserted
/// against it. This suite asserts the reader against the same file, and does so by reading
/// documents that omit the member rather than by inspecting a constant: what matters is the
/// value an absent member actually produces.
/// </para>
/// </remarks>
public sealed class SharedDefaultsTests
{
    private static readonly JsonObject Defaults = ReadDefaults();

    [Fact]
    public void The_supported_format_version_is_the_one_the_compiler_emits()
    {
        Assert.Equal(Text("manifestFormatVersion"), EngineManifest.ManifestFormatSupport.Maximum.ToString());
    }

    /// <summary>
    /// Each section version is asserted on its own.
    /// </summary>
    /// <remarks>
    /// A section version governs only its own payload, so the eight do not move together.
    /// One shared expectation would have made the first divergence look like a defect.
    /// </remarks>
    [Fact]
    public void Every_section_carries_its_own_declared_format_version()
    {
        var declared = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["server.formatVersion"] = ServerSection.FormatVersion,
            ["policy.formatVersion"] = PolicySection.FormatVersion,
            ["operations.formatVersion"] = OperationsSection.FormatVersion,
            ["agentSurface.formatVersion"] = AgentSurfaceSection.FormatVersion,
            ["credentials.formatVersion"] = CredentialsSection.FormatVersion,
            ["authentication.formatVersion"] = AuthenticationSection.FormatVersion,
            ["tools.formatVersion"] = ToolsSection.FormatVersion,
            ["search.formatVersion"] = SearchSection.FormatVersion,
        };

        Assert.All(declared, entry => Assert.Equal(Number(entry.Key), entry.Value));
    }

    [Fact]
    public void A_surface_that_states_nothing_takes_the_shared_surface_defaults()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadServer(
            JsonNode.Parse("""
            {
              "name": "Example API",
              "surfaces": [
                { "slug": "primary", "isDefault": true, "operations": [ { "operation": "list-pets" } ] },
                { "slug": "secondary", "operations": [ { "operation": "list-pets" } ] }
              ]
            }
            """),
            diagnostics);

        // A surface list must name its default explicitly, so the surface under test here is
        // the second one: the one that states nothing beyond its own identity.
        Assert.DoesNotContain(diagnostics, static d => d.IsError);
        var surface = section!.Surfaces[1];

        Assert.Equal(Flag("server.surface.isDefault"), surface.IsDefault);
        Assert.Equal(Flag("server.surface.enabled"), surface.Enabled);
        Assert.Equal(Flag("server.surface.outputSchemas"), surface.OutputSchemas);
        Assert.Equal(Flag("server.surface.navigator.enabled"), surface.EffectiveNavigator.Enabled);
        Assert.Equal(Number("server.surface.navigator.pageSize"), surface.EffectiveNavigator.PageSize);

        var operation = Assert.Single(surface.Operations);
        Assert.Equal(
            Text("server.surface.operation.exposure"),
            Vocabulary.Write(operation.Exposure));
    }

    /// <summary>
    /// A mount that states nothing is protected, and that default is the shared one.
    /// </summary>
    /// <remarks>
    /// The absent member is the case that matters: a Manifest written before the member existed,
    /// or one written by hand without it, must not become publicly served by omission.
    /// </remarks>
    [Fact]
    public void A_mount_that_states_no_authentication_requirement_takes_the_shared_default()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadServer(
            JsonNode.Parse("""{ "name": "Example API" }"""),
            diagnostics);

        Assert.DoesNotContain(diagnostics, static d => d.IsError);

        Assert.Equal(Flag("server.authenticationRequired"), section!.AuthenticationRequired);
    }

    [Fact]
    public void A_policy_that_states_only_a_base_url_takes_the_shared_bounds()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var policy = SectionReader.ReadPolicy(
            JsonNode.Parse("""{ "baseUrl": "https://api.example.com/v1" }"""),
            diagnostics);

        Assert.DoesNotContain(diagnostics, static d => d.IsError);

        var limits = policy!.EffectiveLimits;
        Assert.Equal(
            Number("policy.limits.upstreamConnectTimeoutSeconds"),
            (int)limits.UpstreamConnectTimeout.TotalSeconds);
        Assert.Equal(
            Number("policy.limits.upstreamRequestTimeoutSeconds"),
            (int)limits.UpstreamRequestTimeout.TotalSeconds);
        Assert.Equal(
            Number64("policy.limits.upstreamResponseSizeLimitBytes"),
            limits.UpstreamResponseSizeLimitBytes);
        Assert.Equal(Number("policy.limits.redirectHopLimit"), limits.RedirectHopLimit);
        Assert.Equal(Number("policy.limits.concurrency"), limits.Concurrency);
        Assert.Equal(
            Number64("policy.limits.mcpRequestSizeLimitBytes"),
            limits.McpRequestSizeLimitBytes);

        var ceiling = policy.EffectiveTransformCeiling;
        Assert.Equal(Number("policy.transformCeiling.maxSteps"), ceiling.MaxSteps);
        Assert.Equal(Number("policy.transformCeiling.maxDepth"), ceiling.MaxDepth);
        Assert.Equal(Number("policy.transformCeiling.maxNodes"), ceiling.MaxNodes);
        Assert.Equal(Number64("policy.transformCeiling.maxOutputBytes"), ceiling.MaxOutputBytes);
        Assert.Equal(Number("policy.transformCeiling.maxArrayFanout"), ceiling.MaxArrayFanout);

        var compound = policy.EffectiveCompound;
        Assert.Equal(
            Number64("policy.compound.maxTotalResponseBytes"),
            compound.MaxTotalResponseBytes);
        Assert.Equal(
            Number("policy.compound.workflowTimeoutSeconds"),
            (int)compound.WorkflowTimeout.TotalSeconds);

        var bounds = policy.EffectiveSchemaBounds;
        Assert.Equal(Number("policy.schemaBounds.maxDepth"), bounds.MaxDepth);
        Assert.Equal(Number("policy.schemaBounds.maxNodes"), bounds.MaxNodes);
        Assert.Equal(
            Number("policy.schemaBounds.maxPropertiesPerLevel"),
            bounds.MaxPropertiesPerLevel);

        var files = policy.EffectiveFiles;
        Assert.Equal(
            Number("policy.files.handleLifetimeSeconds"),
            (int)files.HandleLifetime.TotalSeconds);
        Assert.Equal(Number64("policy.files.uploadSizeLimitBytes"), files.UploadSizeLimitBytes);
        Assert.Equal(Flag("policy.files.rejectMagicMismatch"), files.RejectMagicMismatch);
    }

    [Fact]
    public void An_api_key_credential_that_states_no_location_takes_the_shared_default()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadCredentials(
            JsonNode.Parse("""
            {
              "credentials": [
                { "id": "x-api-key", "scheme": "apiKey", "slot": "X-Api-Key", "value": { "fromEnv": "KEY" } }
              ]
            }
            """),
            diagnostics);

        Assert.DoesNotContain(diagnostics, static d => d.IsError);
        var credential = Assert.Single(section!.Credentials);

        Assert.Equal(
            Text("credentials.credential.location"),
            Vocabulary.Write(credential.EffectiveLocation));
    }

    [Fact]
    public void An_operation_and_parameter_that_state_nothing_take_the_shared_defaults()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadOperations(
            JsonNode.Parse("""
            {
              "operations": [
                {
                  "key": "GET /pets", "method": "GET", "path": "/pets",
                  "parameters": [ { "name": "limit", "in": "query" } ],
                  "requestBody": { "content": {} }
                }
              ]
            }
            """),
            diagnostics);

        Assert.DoesNotContain(diagnostics, static d => d.IsError);
        var operation = Assert.Single(section!.Operations);

        Assert.Equal(Flag("operations.operation.deprecated"), operation.Deprecated);
        Assert.Equal(Flag("operations.requestBody.required"), operation.RequestBody!.Required);

        var parameter = Assert.Single(operation.Parameters);
        Assert.Equal(Flag("operations.parameter.required"), parameter.Required);
        Assert.Equal(Flag("operations.parameter.allowReserved"), parameter.AllowReserved);
        Assert.Equal(Flag("operations.parameter.allowEmptyValue"), parameter.AllowEmptyValue);
        Assert.Equal(Flag("operations.parameter.deprecated"), parameter.Deprecated);
    }

    [Theory]
    [InlineData(ParameterLocation.Path, "operations.parameter.style.path")]
    [InlineData(ParameterLocation.Query, "operations.parameter.style.query")]
    [InlineData(ParameterLocation.Header, "operations.parameter.style.header")]
    [InlineData(ParameterLocation.Cookie, "operations.parameter.style.cookie")]
    public void A_parameter_that_states_no_style_takes_the_shared_default(
        ParameterLocation location,
        string key)
    {
        Assert.Equal(Text(key), Vocabulary.Write(Vocabulary.DefaultStyle(location)));
    }

    [Theory]
    [InlineData(ParameterLocation.Query, ParameterStyle.Form, "operations.parameter.explode.queryForm")]
    [InlineData(ParameterLocation.Query, ParameterStyle.DeepObject, "operations.parameter.explode.queryOther")]
    [InlineData(ParameterLocation.Path, ParameterStyle.Simple, "operations.parameter.explode.path")]
    [InlineData(ParameterLocation.Header, ParameterStyle.Simple, "operations.parameter.explode.header")]
    [InlineData(ParameterLocation.Cookie, ParameterStyle.Form, "operations.parameter.explode.cookie")]
    public void A_parameter_that_states_no_explode_takes_the_shared_default(
        ParameterLocation location,
        ParameterStyle style,
        string key)
    {
        Assert.Equal(Flag(key), Vocabulary.DefaultExplode(location, style));
    }

    [Fact]
    public void An_agent_operation_that_states_nothing_takes_the_shared_defaults()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadAgentSurface(
            JsonNode.Parse("""
            {
              "groups": [ { "name": "pets" } ],
              "operations": [
                {
                  "slug": "create-cart", "name": "Create cart",
                  "binding": { "type": "http", "operation": "POST /carts" }
                },
                {
                  "slug": "place-order", "name": "Place order",
                  "binding": {
                    "type": "compound",
                    "steps": [
                      {
                        "stepId": "create", "operation": "create-cart",
                        "inputMappings": [ { "target": "/body/name", "argument": "/name" } ]
                      }
                    ]
                  }
                }
              ]
            }
            """),
            diagnostics);

        Assert.DoesNotContain(diagnostics, static d => d.IsError);

        var group = Assert.Single(section!.Groups);
        Assert.Equal(Number("agentSurface.group.priority"), group.Priority);

        var operation = section.Operations[1];
        var policy = operation.EffectiveOutputSchemaPolicy;
        Assert.Equal(
            Flag("agentSurface.operation.outputSchemaPolicy.generate"),
            policy.Generate);
        Assert.Equal(
            Text("agentSurface.operation.outputSchemaPolicy.advertise"),
            Vocabulary.Write(policy.Advertise));
        Assert.Equal(
            Flag("agentSurface.operation.outputSchemaPolicy.useInternally"),
            policy.UseInternally);

        var binding = Assert.IsType<CompoundBinding>(operation.Binding);
        Assert.Equal(
            Number("agentSurface.binding.compound.bindingVersion"),
            binding.BindingVersion);
        Assert.Equal(
            Text("agentSurface.binding.compound.failurePolicy"),
            Vocabulary.Write(binding.FailurePolicy));
    }

    [Fact]
    public void A_search_section_that_states_no_scoring_takes_the_shared_defaults()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadSearch(
            JsonNode.Parse("""{ "operations": [] }"""),
            diagnostics);

        Assert.DoesNotContain(diagnostics, static d => d.IsError);

        Assert.Equal(Number("search.builderVersion"), section!.BuilderVersion);

        var scoring = section.EffectiveScoring;
        Assert.Equal(Number("search.scoring.quantizationStep"), scoring.QuantizationStep);
        Assert.Equal(Number("search.scoring.metaMultiplier"), scoring.MetaMultiplier);
        Assert.Equal(Number("search.scoring.vectorScale"), scoring.VectorScale);
    }

    [Fact]
    public void The_advertised_tool_name_bound_is_shared()
    {
        var declared = ManifestTool.MaxNameLength;

        Assert.Equal(Number("tools.tool.nameMaxLength"), declared);
    }

    /// <summary>
    /// Every key this suite asserts. Kept explicit so a default added to the shared fixture
    /// cannot be carried unasserted on the Engine side.
    /// </summary>
    private static readonly string[] AssertedKeys =
    [
        "manifestFormatVersion",
        "server.formatVersion",
        "server.authenticationRequired",
        "policy.formatVersion",
        "operations.formatVersion",
        "agentSurface.formatVersion",
        "credentials.formatVersion",
        "authentication.formatVersion",
        "tools.formatVersion",
        "search.formatVersion",
        "server.surface.isDefault",
        "server.surface.enabled",
        "server.surface.outputSchemas",
        "server.surface.navigator.enabled",
        "server.surface.navigator.pageSize",
        "server.surface.operation.exposure",
        "policy.limits.upstreamConnectTimeoutSeconds",
        "policy.limits.upstreamRequestTimeoutSeconds",
        "policy.limits.upstreamResponseSizeLimitBytes",
        "policy.limits.redirectHopLimit",
        "policy.limits.concurrency",
        "policy.limits.mcpRequestSizeLimitBytes",
        "policy.transformCeiling.maxSteps",
        "policy.transformCeiling.maxDepth",
        "policy.transformCeiling.maxNodes",
        "policy.transformCeiling.maxOutputBytes",
        "policy.transformCeiling.maxArrayFanout",
        "policy.compound.maxTotalResponseBytes",
        "policy.compound.workflowTimeoutSeconds",
        "policy.schemaBounds.maxDepth",
        "policy.schemaBounds.maxNodes",
        "policy.schemaBounds.maxPropertiesPerLevel",
        "policy.files.handleLifetimeSeconds",
        "policy.files.uploadSizeLimitBytes",
        "policy.files.rejectMagicMismatch",
        "credentials.credential.location",
        "operations.operation.deprecated",
        "operations.parameter.required",
        "operations.parameter.allowReserved",
        "operations.parameter.allowEmptyValue",
        "operations.parameter.deprecated",
        "operations.parameter.style.path",
        "operations.parameter.style.query",
        "operations.parameter.style.header",
        "operations.parameter.style.cookie",
        "operations.parameter.explode.queryForm",
        "operations.parameter.explode.queryOther",
        "operations.parameter.explode.path",
        "operations.parameter.explode.header",
        "operations.parameter.explode.cookie",
        "operations.requestBody.required",
        "agentSurface.group.priority",
        "agentSurface.operation.outputSchemaPolicy.generate",
        "agentSurface.operation.outputSchemaPolicy.advertise",
        "agentSurface.operation.outputSchemaPolicy.useInternally",
        "agentSurface.binding.compound.bindingVersion",
        "agentSurface.binding.compound.failurePolicy",
        "search.builderVersion",
        "search.scoring.quantizationStep",
        "search.scoring.metaMultiplier",
        "search.scoring.vectorScale",
        "tools.tool.nameMaxLength",
    ];

    [Fact]
    public void Every_shared_default_is_asserted_by_this_suite()
    {
        var asserted = AssertedKeys
            .OrderBy(static key => key, StringComparer.Ordinal)
            .ToList();

        var declared = Defaults
            .Select(static member => member.Key)
            .OrderBy(static key => key, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(declared, asserted);
    }

    private static string Text(string key) => Lookup(key).GetValue<string>();

    private static int Number(string key) => Lookup(key).GetValue<int>();

    private static long Number64(string key) => Lookup(key).GetValue<long>();

    private static bool Flag(string key) => Lookup(key).GetValue<bool>();

    private static JsonNode Lookup(string key) =>
        Defaults[key] ?? throw new InvalidOperationException($"defaults.json has no entry for '{key}'.");

    private static JsonObject ReadDefaults()
    {
        var path = TestRepository.Fixture("manifests", "defaults.json");
        var root = JsonNode.Parse(File.ReadAllBytes(path))?.AsObject()
            ?? throw new InvalidOperationException($"Could not parse '{path}'.");

        return root["defaults"]?.AsObject()
            ?? throw new InvalidOperationException($"'{path}' has no 'defaults' member.");
    }
}
