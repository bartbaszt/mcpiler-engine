using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Model;

public sealed class ManifestModelTests
{
    [Fact]
    public void Section_names_are_a_closed_set()
    {
        Assert.True(ManifestSectionName.IsKnown(ManifestSectionName.Server));
        Assert.True(ManifestSectionName.IsKnown(ManifestSectionName.AgentSurface));
        Assert.False(ManifestSectionName.IsKnown("agentsurface"));
        Assert.False(ManifestSectionName.IsKnown("policies"));
        Assert.False(ManifestSectionName.IsKnown(null));
        Assert.Equal(8, ManifestSectionName.All.Count);
    }

    [Fact]
    public void Only_the_vector_section_is_external_only()
    {
        Assert.Contains(ManifestSectionName.Vectors, ManifestSectionName.ExternalOnly);
        Assert.DoesNotContain(ManifestSectionName.Operations, ManifestSectionName.ExternalOnly);
    }

    [Fact]
    public void A_section_entry_is_inline_or_external_but_never_both()
    {
        var inline = ManifestSectionEntry.FromInline(new JsonObject { ["baseUrl"] = "https://api.example.com" });
        var external = ManifestSectionEntry.FromPath("sections/operations.json", "abc", 12);

        Assert.True(inline.IsInline);
        Assert.Null(inline.Path);

        Assert.False(external.IsInline);
        Assert.Null(external.Inline);
        Assert.Equal("sections/operations.json", external.Path);
        Assert.Equal("abc", external.Sha256);
        Assert.Equal(12, external.Bytes);
    }

    [Fact]
    public void An_external_section_entry_requires_a_path()
    {
        Assert.Throws<ArgumentException>(() => ManifestSectionEntry.FromPath(" "));
    }

    [Fact]
    public void A_manifest_is_sealed_only_when_it_carries_a_completeness_value()
    {
        var sections = new Dictionary<string, ManifestSectionEntry>(StringComparer.Ordinal);

        Assert.False(new ManifestRoot(new ManifestFormatVersion(0, 1), sections).IsSealed);

        Assert.True(new ManifestRoot(
            new ManifestFormatVersion(0, 1),
            sections,
            Completeness: new ManifestCompleteness(ManifestCompleteness.Sha256, "3b1f")).IsSealed);
    }

    [Fact]
    public void A_server_section_with_no_surface_is_minimal_and_synthesizes_one_default()
    {
        var server = new ServerSection("Example API");

        Assert.True(server.IsMinimal);
        Assert.Null(server.DefaultSurface);

        var synthesized = ManifestSurface.Synthesize(server.Name, ["list-pets", "get-pet"]);

        Assert.Equal("default", synthesized.Slug);
        Assert.Equal("Example API", synthesized.DisplayName);
        Assert.True(synthesized.IsDefault);
        Assert.True(synthesized.Enabled);
        Assert.Empty(synthesized.RequiredScopes);
        Assert.False(synthesized.EffectiveNavigator.Enabled);
        Assert.False(synthesized.OutputSchemas);
        Assert.Equal(
            [OperationExposure.Direct, OperationExposure.Direct],
            synthesized.Operations.Select(static entry => entry.Exposure));
    }

    [Fact]
    public void Exposure_membership_is_the_single_invocation_gate()
    {
        var surface = new ManifestSurface(
            "default",
            [
                new SurfaceOperation("list-pets", OperationExposure.Direct),
                new SurfaceOperation("delete-pet", OperationExposure.Navigator),
                new SurfaceOperation("debug-dump", OperationExposure.Hidden),
            ]);

        Assert.True(surface.InvocationAllowed("list-pets"));
        Assert.True(surface.InvocationAllowed("delete-pet"));
        Assert.False(surface.InvocationAllowed("debug-dump"));

        // An operation absent from the list is not invocable, and the absence is reported as
        // "no exposure" rather than as a default.
        Assert.Null(surface.ExposureOf("unlisted"));
        Assert.False(surface.InvocationAllowed("unlisted"));
    }

    [Fact]
    public void A_surface_slug_match_is_case_sensitive()
    {
        var surface = new ManifestSurface("default", [new SurfaceOperation("listPets", OperationExposure.Direct)]);

        Assert.True(surface.InvocationAllowed("listPets"));
        Assert.False(surface.InvocationAllowed("listpets"));
    }

    [Fact]
    public void Policy_defaults_to_the_single_origin_of_the_base_url()
    {
        var policy = new PolicySection(new Uri("https://api.example.com/v1/deep?x=1"));

        Assert.Equal(["https://api.example.com"], policy.AllowedOrigins);
    }

    [Fact]
    public void Policy_keeps_a_declared_origin_list_and_a_non_default_port()
    {
        var policy = new PolicySection(
            new Uri("https://api.example.com:8443/v1"),
            ["https://api.example.com:8443", "https://cdn.example.com"]);

        Assert.Equal(["https://api.example.com:8443", "https://cdn.example.com"], policy.AllowedOrigins);
        Assert.Equal("https://api.example.com:8443", PolicySection.OriginOf(new Uri("https://api.example.com:8443/v1")));
    }

    [Fact]
    public void Policy_exposes_every_documented_platform_default()
    {
        var policy = new PolicySection(new Uri("https://api.example.com"));

        Assert.Equal(TimeSpan.FromSeconds(10), policy.EffectiveLimits.UpstreamConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(100), policy.EffectiveLimits.UpstreamRequestTimeout);
        Assert.Equal(50L * 1024 * 1024, policy.EffectiveLimits.UpstreamResponseSizeLimitBytes);
        Assert.Equal(5, policy.EffectiveLimits.RedirectHopLimit);
        Assert.Equal(8, policy.EffectiveLimits.Concurrency);
        Assert.Equal(1L * 1024 * 1024, policy.EffectiveLimits.McpRequestSizeLimitBytes);

        Assert.Equal(64, policy.EffectiveTransformCeiling.MaxSteps);
        Assert.Equal(32, policy.EffectiveTransformCeiling.MaxDepth);
        Assert.Equal(8192, policy.EffectiveTransformCeiling.MaxNodes);
        Assert.Equal(256L * 1024, policy.EffectiveTransformCeiling.MaxOutputBytes);
        Assert.Equal(1024, policy.EffectiveTransformCeiling.MaxArrayFanout);

        Assert.Equal(100L * 1024 * 1024, policy.EffectiveCompound.MaxTotalResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(120), policy.EffectiveCompound.WorkflowTimeout);

        Assert.Equal(32, policy.EffectiveSchemaBounds.MaxDepth);
        Assert.Equal(2048, policy.EffectiveSchemaBounds.MaxNodes);
        Assert.Equal(256, policy.EffectiveSchemaBounds.MaxPropertiesPerLevel);

        Assert.Equal(TimeSpan.FromHours(24), policy.EffectiveFiles.HandleLifetime);
        Assert.Equal(100L * 1024 * 1024, policy.EffectiveFiles.UploadSizeLimitBytes);
        Assert.True(policy.EffectiveFiles.RejectMagicMismatch);
    }

    [Fact]
    public void A_credential_reference_never_discloses_an_inline_secret_in_its_description()
    {
        const string Secret = "super-secret-token";

        var inline = CredentialReference.Literal(Secret);

        Assert.DoesNotContain(Secret, inline.ToString(), StringComparison.Ordinal);
        Assert.Equal("inline:(redacted)", inline.ToString());
        Assert.Equal("fromEnv:EXAMPLE_TOKEN", CredentialReference.Env("EXAMPLE_TOKEN").ToString());
        Assert.Equal("fromFile:/run/secrets/key", CredentialReference.File("/run/secrets/key").ToString());
    }

    [Theory]
    [InlineData(CredentialScheme.Bearer, null, true)]
    [InlineData(CredentialScheme.Basic, null, true)]
    [InlineData(CredentialScheme.Header, null, true)]
    [InlineData(CredentialScheme.ApiKey, CredentialLocation.Header, true)]
    [InlineData(CredentialScheme.ApiKey, CredentialLocation.Cookie, true)]
    [InlineData(CredentialScheme.ApiKey, CredentialLocation.Query, false)]
    public void Redirect_sensitivity_is_derived_from_the_scheme_and_location(
        CredentialScheme scheme,
        CredentialLocation? location,
        bool expected)
    {
        var credential = new ManifestCredential(
            "x-api-key",
            scheme,
            "X-Api-Key",
            CredentialReference.Env("EXAMPLE"),
            location);

        Assert.Equal(expected, credential.IsRedirectSensitiveHeader);
    }

    [Fact]
    public void An_api_key_defaults_to_a_header()
    {
        var credential = new ManifestCredential(
            "x-api-key",
            CredentialScheme.ApiKey,
            "X-Api-Key",
            CredentialReference.Env("EXAMPLE"));

        Assert.Equal(CredentialLocation.Header, credential.EffectiveLocation);
    }

    [Theory]
    [InlineData("token", true)]
    [InlineData("x-api-key", true)]
    [InlineData("0", true)]
    [InlineData("a1-b2-c3", true)]
    [InlineData("Token", false)]
    [InlineData("my token", false)]
    [InlineData("-token", false)]
    [InlineData("token_", false)]
    [InlineData("token-", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void A_credential_id_accepts_only_the_documented_charset(string? id, bool expected)
        => Assert.Equal(expected, ManifestCredential.IsValidId(id));

    /// <summary>
    /// Upper case is refused rather than folded.
    /// </summary>
    /// <remarks>
    /// Folding would let two declarations that differ only by case become one id, which is
    /// exactly the ambiguity the identifier exists to remove.
    /// </remarks>
    [Fact]
    public void A_credential_id_longer_than_the_limit_is_refused()
    {
        Assert.True(ManifestCredential.IsValidId(new string('a', ManifestCredential.MaxIdLength)));
        Assert.False(ManifestCredential.IsValidId(new string('a', ManifestCredential.MaxIdLength + 1)));
    }

    /// <summary>
    /// An absent credential scope and an empty one are one representation.
    /// </summary>
    /// <remarks>
    /// The default has to be "apply nothing" rather than "apply everything", so that a
    /// binding can never acquire a credential by omission.
    /// </remarks>
    [Fact]
    public void An_absent_credential_scope_reads_as_an_empty_one()
    {
        Assert.Empty(new HttpBinding("GET /pets").CredentialRef);
        Assert.Empty(new HttpBinding("GET /pets", CredentialRef: []).CredentialRef);
        Assert.Equal(["bearer"], new HttpBinding("GET /pets", CredentialRef: ["bearer"]).CredentialRef);
    }

    [Fact]
    public void An_operation_key_must_agree_with_its_method_and_path()
    {
        Assert.True(new ManifestOperation("GET /pets", "GET", "/pets").KeyAgreesWithMethodAndPath());
        Assert.True(new ManifestOperation("GET /pets", "get", "/pets").KeyAgreesWithMethodAndPath());
        Assert.False(new ManifestOperation("GET /pets", "POST", "/pets").KeyAgreesWithMethodAndPath());
        Assert.False(new ManifestOperation("GET /pets", "GET", "/pet").KeyAgreesWithMethodAndPath());
        Assert.Equal("GET /pets", ManifestOperation.BuildKey("get", "/pets"));
    }

    [Fact]
    public void A_parameter_resolves_its_style_and_explode_defaults_per_location()
    {
        var query = new ManifestParameter("verbose", ParameterLocation.Query);
        var path = new ManifestParameter("petId", ParameterLocation.Path, Required: true);
        var declared = new ManifestParameter(
            "ids",
            ParameterLocation.Query,
            Style: ParameterStyle.SpaceDelimited,
            Explode: false);

        Assert.Equal(ParameterStyle.Form, query.EffectiveStyle);
        Assert.True(query.EffectiveExplode);

        Assert.Equal(ParameterStyle.Simple, path.EffectiveStyle);
        Assert.False(path.EffectiveExplode);

        Assert.Equal(ParameterStyle.SpaceDelimited, declared.EffectiveStyle);
        Assert.False(declared.EffectiveExplode);
    }

    [Fact]
    public void An_operation_kind_is_derived_from_the_binding_when_absent()
    {
        var http = Operation("list-pets", new HttpBinding("GET /pets"));
        var compound = Operation(
            "create-and-tag",
            new CompoundBinding([new CompoundStepEntry("create", "create-pet")]));

        Assert.Equal(AgentOperationKind.SourceBacked, http.EffectiveKind);
        Assert.Equal(AgentOperationKind.Compound, compound.EffectiveKind);

        // A declared kind is kept so the validator can compare it against the binding
        // instead of trusting either one.
        Assert.Equal(
            AgentOperationKind.CustomHttp,
            (http with { Kind = AgentOperationKind.CustomHttp }).EffectiveKind);
    }

    [Fact]
    public void A_tool_description_prefers_summary_then_description_then_name()
    {
        var binding = new HttpBinding("GET /pets");

        Assert.Equal("Lists pets", Operation("list-pets", binding, summary: "Lists pets").ToolDescription);
        Assert.Equal("Long text", Operation("list-pets", binding, description: "Long text").ToolDescription);
        Assert.Equal("List pets", Operation("list-pets", binding).ToolDescription);
    }

    [Fact]
    public void Declared_annotations_win_over_risk_and_over_the_http_method()
    {
        var operation = Operation("delete-pet", new HttpBinding("DELETE /pets/{id}")) with
        {
            Annotations = new ToolAnnotations(ReadOnly: true),
            Risk = "destructive",
        };

        var annotations = operation.EffectiveAnnotations("DELETE");

        Assert.True(annotations.ReadOnly);
        Assert.False(annotations.Destructive);
    }

    [Fact]
    public void Risk_derives_annotations_when_none_are_declared()
    {
        var operation = Operation("delete-pet", new HttpBinding("DELETE /pets/{id}")) with
        {
            Risk = "destructive,idempotent",
        };

        var annotations = operation.EffectiveAnnotations("GET");

        Assert.True(annotations.Destructive);
        Assert.True(annotations.Idempotent);
        Assert.False(annotations.ReadOnly);
    }

    [Theory]
    [InlineData("GET", true, false, true)]
    [InlineData("HEAD", true, false, true)]
    [InlineData("DELETE", false, true, true)]
    [InlineData("PUT", false, false, true)]
    [InlineData("POST", false, false, false)]
    [InlineData(null, false, false, false)]
    public void The_http_method_derives_annotations_as_a_last_resort(
        string? method,
        bool readOnly,
        bool destructive,
        bool idempotent)
    {
        var annotations = ToolAnnotations.FromMethod(method);

        Assert.Equal(readOnly, annotations.ReadOnly);
        Assert.Equal(destructive, annotations.Destructive);
        Assert.Equal(idempotent, annotations.Idempotent);
        Assert.True(annotations.OpenWorld);
    }

    [Fact]
    public void An_operation_defaults_to_no_risk_and_no_search_metadata()
    {
        var operation = Operation("list-pets", new HttpBinding("GET /pets"));

        Assert.Equal("none", operation.EffectiveRisk);
        Assert.Empty(operation.EffectiveSearch.Aliases);
        Assert.Empty(operation.EffectiveSearch.Keywords);
        Assert.Empty(operation.EffectiveSearch.ExampleIntents);

        Assert.True(operation.EffectiveOutputSchemaPolicy.Generate);
        Assert.Equal(OutputSchemaAdvertisement.Auto, operation.EffectiveOutputSchemaPolicy.Advertise);
        Assert.False(operation.EffectiveOutputSchemaPolicy.UseInternally);
    }

    [Fact]
    public void The_group_join_is_by_name_ordinal_and_case_sensitive()
    {
        var section = new AgentSurfaceSection(
            [Operation("list-pets", new HttpBinding("GET /pets")) with { Groups = ["pets"] }],
            [new OperationGroupEntry("pets", Priority: 10)]);

        Assert.NotNull(section.Group("pets"));
        Assert.Null(section.Group("Pets"));
        Assert.Equal(10, section.Group("pets")!.Priority);
    }

    [Theory]
    [InlineData("/body/name", true)]
    [InlineData("/body", true)]
    [InlineData("/parts/0/content", true)]
    [InlineData("/path/petId", true)]
    [InlineData("/status", false)]
    [InlineData("/bodyguard", false)]
    [InlineData("body", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Request_pointer_roots_are_matched_at_a_segment_boundary(string? pointer, bool expected)
    {
        Assert.Equal(expected, ManifestPointerRoots.IsRequestTarget(pointer));
    }

    [Theory]
    [InlineData("/status", true)]
    [InlineData("/headers/Location", true)]
    [InlineData("/body/id", true)]
    [InlineData("/path/petId", false)]
    [InlineData("/statuses", false)]
    public void Response_pointer_roots_are_matched_at_a_segment_boundary(string pointer, bool expected)
    {
        Assert.Equal(expected, ManifestPointerRoots.IsResponseSource(pointer));
    }

    [Fact]
    public void A_mapping_source_is_exactly_one_variant()
    {
        var argument = MappingSource.FromArgument("/name");
        var stepOutput = MappingSource.FromStepResponse("create", "/body/id");
        var constant = MappingSource.FromConstant(JsonValue.Create("new"));

        Assert.True(argument.IsArgument);
        Assert.False(argument.IsStepOutput);
        Assert.False(argument.IsConstant);

        Assert.True(stepOutput.IsStepOutput);
        Assert.Equal("create", stepOutput.FromStep);
        Assert.Equal("/body/id", stepOutput.Response);
        Assert.False(stepOutput.IsArgument);

        Assert.True(constant.IsConstant);
        Assert.False(constant.IsArgument);
    }

    [Fact]
    public void A_compound_binding_defaults_to_fail_fast_at_the_supported_version()
    {
        var binding = new CompoundBinding([new CompoundStepEntry("create", "create-pet")]);

        Assert.Equal(1, binding.BindingVersion);
        Assert.Equal(CompoundBindingVersions.Supported, binding.BindingVersion);
        Assert.Equal(CompoundFailurePolicy.FailFast, binding.FailurePolicy);
        Assert.Null(binding.MaxTotalResponseBytes);
        Assert.Null(binding.WorkflowTimeout);
        Assert.Null(binding.OutputSelection);
    }

    [Fact]
    public void A_navigator_tool_is_the_only_tool_without_an_operation()
    {
        var direct = new ManifestTool("list_pets", "Lists pets", Operation: "list-pets");
        var navigator = new ManifestTool(ManifestTool.NavigatorDiscover, "Discover operations");

        Assert.False(direct.IsNavigatorTool);
        Assert.True(navigator.IsNavigatorTool);
        Assert.StartsWith(ManifestTool.NavigatorPrefix, navigator.Name, StringComparison.Ordinal);
        Assert.Equal(128, ManifestTool.MaxNameLength);
    }

    [Fact]
    public void A_schema_is_kept_as_json_so_a_round_trip_cannot_lose_a_keyword()
    {
        var node = JsonNode.Parse("""
            { "type": "string", "format": "binary", "nullable": true,
              "contentEncoding": "base64", "contentMediaType": "image/png",
              "minimum": 1.50, "x-vendor-extension": { "keep": true } }
            """)!;

        var schema = ManifestSchema.From(node);

        Assert.Equal("string", schema.Type);
        Assert.Equal("binary", schema.Format);
        Assert.True(schema.Nullable);
        Assert.Equal("base64", schema.ContentEncoding);
        Assert.Equal("image/png", schema.ContentMediaType);
        Assert.False(schema.IsReference);
        Assert.False(schema.IsBoolean);

        // The unknown vendor keyword and the lexical numeric bound both survive, because the
        // model never re-projects the schema through a typed mirror.
        Assert.NotNull(schema.Object!["x-vendor-extension"]);
        Assert.Equal("1.50", schema.Object["minimum"]!.ToJsonString());
    }

    [Fact]
    public void A_reference_schema_reports_its_local_pointer()
    {
        var schema = ManifestSchema.From(JsonNode.Parse("""{ "$ref": "#/components/schemas/Pet" }""")!);

        Assert.True(schema.IsReference);
        Assert.Equal("#/components/schemas/Pet", schema.RefPointer);
        Assert.Null(schema.Type);
    }

    [Fact]
    public void A_boolean_schema_is_recognized()
    {
        Assert.True(ManifestSchema.From(JsonValue.Create(false)).IsBoolean);
        Assert.True(ManifestSchema.From(JsonValue.Create(true)).IsBoolean);
        Assert.Null(ManifestSchema.From(JsonValue.Create(true)).Object);
    }

    [Fact]
    public void An_absent_type_means_any_rather_than_a_default_type()
    {
        Assert.Null(ManifestSchema.From(JsonNode.Parse("{}")!).Type);
    }

    private static AgentOperationEntry Operation(
        string slug,
        ManifestBinding binding,
        string? summary = null,
        string? description = null)
        => new(
            Slug: slug,
            Name: slug == "list-pets" ? "List pets" : slug,
            Binding: binding,
            Summary: summary,
            Description: description);
}
