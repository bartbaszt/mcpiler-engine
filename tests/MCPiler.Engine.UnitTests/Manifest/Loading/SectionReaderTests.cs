using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

public sealed class SectionReaderTests
{
    private readonly List<ManifestDiagnostic> _diagnostics = [];

    private static JsonNode Json(string text) => JsonNode.Parse(text)!;

    private IReadOnlyList<string> Codes => [.. _diagnostics.Select(static d => d.Code)];

    private IReadOnlyList<string> ErrorCodes
        => [.. _diagnostics.Where(static d => d.IsError).Select(static d => d.Code)];

    private void AssertNoErrors()
    {
        var errors = _diagnostics.Where(static d => d.IsError).ToList();

        Assert.Empty(errors);
    }

    // ---- server -------------------------------------------------------------------------

    [Fact]
    public void Server_reads_a_full_surface_declaration()
    {
        var section = SectionReader.ReadServer(
            Json(
                """
                {
                  "formatVersion": 1,
                  "name": "Example API",
                  "description": "Pet inventory",
                  "version": "1.4.0",
                  "surfaces": [
                    {
                      "slug": "default",
                      "name": "Default",
                      "isDefault": true,
                      "enabled": true,
                      "requiredScopes": ["mcp:invoke"],
                      "navigator": { "enabled": true, "pageSize": 50 },
                      "outputSchemas": true,
                      "operations": [
                        { "operation": "list-pets", "exposure": "direct" },
                        { "operation": "delete-pet", "exposure": "navigator" },
                        { "operation": "purge", "exposure": "hidden" }
                      ]
                    }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.NotNull(section);
        Assert.Equal("Example API", section.Name);
        Assert.Equal("Pet inventory", section.Description);
        Assert.Equal("1.4.0", section.Version);

        var surface = Assert.Single(section.Surfaces);

        Assert.Equal("default", surface.Slug);
        Assert.Equal("Default", surface.DisplayName);
        Assert.True(surface.IsDefault);
        Assert.True(surface.Enabled);
        Assert.Equal(["mcp:invoke"], surface.RequiredScopes);
        Assert.True(surface.EffectiveNavigator.Enabled);
        Assert.Equal(50, surface.EffectiveNavigator.PageSize);
        Assert.True(surface.OutputSchemas);
        Assert.True(surface.InvocationAllowed("list-pets"));
        Assert.True(surface.InvocationAllowed("delete-pet"));
        Assert.False(surface.InvocationAllowed("purge"));
        Assert.Null(surface.ExposureOf("absent"));
    }

    [Fact]
    public void Server_accepts_the_minimal_form_that_declares_no_surface()
    {
        var section = SectionReader.ReadServer(Json("""{ "name": "Example API" }"""), _diagnostics);

        AssertNoErrors();
        Assert.NotNull(section);
        Assert.True(section.IsMinimal);
    }

    [Fact]
    public void Server_requires_a_name()
    {
        Assert.Null(SectionReader.ReadServer(Json("{}"), _diagnostics));
        Assert.Contains(ManifestDiagnosticCodes.MemberRequired, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Server_defaults_an_omitted_exposure_to_direct()
    {
        // Membership in the list is itself the grant, so the only open question is direct
        // versus navigator and both are invocable. Omission cannot widen anything.
        var section = SectionReader.ReadServer(
            Json(
                """
                {
                  "name": "Example API",
                  "surfaces": [
                    { "slug": "default", "isDefault": true, "operations": [ { "operation": "list-pets" } ] }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.Equal(OperationExposure.Direct, section!.Surfaces[0].ExposureOf("list-pets"));
    }

    [Fact]
    public void Server_refuses_a_surface_list_with_no_default()
    {
        SectionReader.ReadServer(
            Json(
                """
                {
                  "name": "Example API",
                  "surfaces": [ { "slug": "a", "operations": [ { "operation": "x" } ] } ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.NoDefaultSurface, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Server_refuses_more_than_one_default_surface()
    {
        SectionReader.ReadServer(
            Json(
                """
                {
                  "name": "Example API",
                  "surfaces": [
                    { "slug": "a", "isDefault": true, "operations": [ { "operation": "x" } ] },
                    { "slug": "b", "isDefault": true, "operations": [ { "operation": "x" } ] }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.MultipleDefaultSurfaces, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Server_refuses_a_duplicate_surface_slug()
    {
        SectionReader.ReadServer(
            Json(
                """
                {
                  "name": "Example API",
                  "surfaces": [
                    { "slug": "a", "isDefault": true, "operations": [ { "operation": "x" } ] },
                    { "slug": "a", "operations": [ { "operation": "x" } ] }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.DuplicateSurfaceSlug, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Server_refuses_the_same_operation_listed_twice_on_one_surface()
    {
        // Two entries can declare different exposures, so resolving by position would let
        // declaration order decide whether an operation is advertised.
        SectionReader.ReadServer(
            Json(
                """
                {
                  "name": "Example API",
                  "surfaces": [
                    {
                      "slug": "a",
                      "isDefault": true,
                      "operations": [
                        { "operation": "x", "exposure": "direct" },
                        { "operation": "x", "exposure": "hidden" }
                      ]
                    }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.DuplicateSurfaceOperation, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Server_warns_about_a_surface_that_exposes_nothing()
    {
        SectionReader.ReadServer(
            Json(
                """
                {
                  "name": "Example API",
                  "surfaces": [ { "slug": "a", "isDefault": true, "operations": [] } ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.Contains(ManifestDiagnosticCodes.SurfaceHasNoOperations, Codes, StringComparer.Ordinal);
    }

    [Fact]
    public void Section_format_version_is_optional_but_checked_when_present()
    {
        Assert.NotNull(SectionReader.ReadServer(Json("""{ "name": "A" }"""), _diagnostics));
        AssertNoErrors();

        var later = new List<ManifestDiagnostic>();

        SectionReader.ReadServer(Json("""{ "formatVersion": 2, "name": "A" }"""), later);

        Assert.Contains(
            ManifestDiagnosticCodes.SectionFormatVersionUnsupported,
            later.Select(static d => d.Code),
            StringComparer.Ordinal);
    }

    [Fact]
    public void Every_reader_refuses_an_unknown_member()
    {
        SectionReader.ReadServer(Json("""{ "name": "A", "nmae": "typo" }"""), _diagnostics);

        var diagnostic = Assert.Single(
            _diagnostics,
            static d => string.Equals(d.Code, ManifestDiagnosticCodes.UnknownMember, StringComparison.Ordinal));

        Assert.Equal("/nmae", diagnostic.Pointer);
        Assert.Equal(ManifestSectionName.Server, diagnostic.Section);
    }

    [Fact]
    public void A_wrongly_typed_member_is_reported_rather_than_read_as_absent()
    {
        // Reading "enabled": "false" as absent would turn a typo into a changed contract.
        SectionReader.ReadServer(
            Json(
                """
                {
                  "name": "A",
                  "surfaces": [
                    { "slug": "a", "isDefault": true, "enabled": "false", "operations": [ { "operation": "x" } ] }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.MemberTypeInvalid, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void A_section_payload_that_is_not_an_object_is_refused()
    {
        Assert.Null(SectionReader.ReadServer(Json("[]"), _diagnostics));
        Assert.Contains(ManifestDiagnosticCodes.SectionNotAnObject, ErrorCodes, StringComparer.Ordinal);
    }

    // ---- policy -------------------------------------------------------------------------

    [Fact]
    public void Policy_falls_back_to_every_platform_default()
    {
        var section = SectionReader.ReadPolicy(
            Json("""{ "baseUrl": "https://api.example.com/v1" }"""),
            _diagnostics);

        AssertNoErrors();
        Assert.NotNull(section);
        Assert.Equal(ExecutionLimits.Default, section.EffectiveLimits);
        Assert.Equal(TransformCeiling.Default, section.EffectiveTransformCeiling);
        Assert.Equal(CompoundBounds.Default, section.EffectiveCompound);
        Assert.Equal(SchemaBounds.Default, section.EffectiveSchemaBounds);
        Assert.Equal(FilePolicy.Default, section.EffectiveFiles);
        Assert.Equal(["https://api.example.com"], section.AllowedOrigins);
    }

    [Fact]
    public void Policy_reads_every_declared_bound()
    {
        var section = SectionReader.ReadPolicy(
            Json(
                """
                {
                  "baseUrl": "https://api.example.com",
                  "allowedOrigins": ["https://api.example.com", "https://cdn.example.com:8443"],
                  "limits": {
                    "upstreamConnectTimeoutSeconds": 5,
                    "upstreamRequestTimeoutSeconds": 30,
                    "upstreamResponseSizeLimitBytes": 1048576,
                    "redirectHopLimit": 0,
                    "concurrency": 2,
                    "mcpRequestSizeLimitBytes": 65536
                  },
                  "transformCeiling": {
                    "maxSteps": 8, "maxDepth": 4, "maxNodes": 64,
                    "maxOutputBytes": 1024, "maxArrayFanout": 16
                  },
                  "compound": { "maxTotalResponseBytes": 2048, "workflowTimeoutSeconds": 15 },
                  "schemaBounds": { "maxDepth": 6, "maxNodes": 128, "maxPropertiesPerLevel": 32 },
                  "files": { "handleLifetimeSeconds": 60, "uploadSizeLimitBytes": 4096, "rejectMagicMismatch": false }
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.NotNull(section);
        Assert.Equal(TimeSpan.FromSeconds(5), section.EffectiveLimits.UpstreamConnectTimeout);
        Assert.Equal(0, section.EffectiveLimits.RedirectHopLimit);
        Assert.Equal(2, section.EffectiveLimits.Concurrency);
        Assert.Equal(8, section.EffectiveTransformCeiling.MaxSteps);
        Assert.Equal(2048, section.EffectiveCompound.MaxTotalResponseBytes);
        Assert.Equal(6, section.EffectiveSchemaBounds.MaxDepth);
        Assert.False(section.EffectiveFiles.RejectMagicMismatch);
        Assert.Equal(["https://api.example.com", "https://cdn.example.com:8443"], section.AllowedOrigins);
    }

    [Theory]
    [InlineData("""{ }""")]
    [InlineData("""{ "baseUrl": "not a url" }""")]
    [InlineData("""{ "baseUrl": "ftp://api.example.com" }""")]
    [InlineData("""{ "baseUrl": "/relative" }""")]
    public void Policy_requires_an_absolute_http_base_url(string document)
    {
        Assert.Null(SectionReader.ReadPolicy(Json(document), _diagnostics));
        Assert.Contains(ManifestDiagnosticCodes.BaseUrlInvalid, ErrorCodes, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("https://api.example.com/v1")]
    [InlineData("https://api.example.com/?a=1")]
    [InlineData("not-an-origin")]
    [InlineData("ftp://api.example.com")]
    public void Policy_refuses_a_malformed_origin_rather_than_skipping_it(string origin)
    {
        // Silently dropping one entry of an allow-list leaves the operator believing a
        // perimeter they do not have.
        SectionReader.ReadPolicy(
            Json($$"""{ "baseUrl": "https://api.example.com", "allowedOrigins": ["{{origin}}"] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.OriginInvalid, ErrorCodes, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("""{ "baseUrl": "https://a.example.com", "limits": { "concurrency": 0 } }""")]
    [InlineData("""{ "baseUrl": "https://a.example.com", "limits": { "redirectHopLimit": -1 } }""")]
    [InlineData("""{ "baseUrl": "https://a.example.com", "schemaBounds": { "maxNodes": 0 } }""")]
    [InlineData("""{ "baseUrl": "https://a.example.com", "limits": { "upstreamRequestTimeoutSeconds": 0 } }""")]
    [InlineData("""{ "baseUrl": "https://a.example.com", "limits": { "upstreamRequestTimeoutSeconds": 999999 } }""")]
    public void Policy_refuses_a_bound_outside_the_permitted_range(string document)
    {
        SectionReader.ReadPolicy(Json(document), _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.LimitOutOfRange, ErrorCodes, StringComparer.Ordinal);
    }

    // ---- credentials --------------------------------------------------------------------

    [Fact]
    public void Credentials_reads_all_four_schemes()
    {
        var section = SectionReader.ReadCredentials(
            Json(
                """
                {
                  "credentials": [
                    { "scheme": "bearer", "slot": "Authorization", "value": { "fromEnv": "TOKEN" } },
                    { "scheme": "apiKey", "slot": "X-Api-Key", "location": "header", "value": { "fromEnv": "KEY" } },
                    { "scheme": "apiKey", "slot": "token", "location": "query", "value": { "fromEnv": "QKEY" } },
                    { "scheme": "header", "slot": "X-Tenant", "value": { "fromEnv": "TENANT" } },
                    { "scheme": "basic", "slot": "username", "value": { "fromEnv": "USER" } },
                    { "scheme": "basic", "slot": "password", "value": { "fromEnv": "PASS" } }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.NotNull(section);
        Assert.Equal(6, section.Credentials.Count);
        Assert.Equal(CredentialLocation.Header, section.Credentials[0].EffectiveLocation);
        Assert.True(section.Credentials[0].IsRedirectSensitiveHeader);
        Assert.False(section.Credentials[2].IsRedirectSensitiveHeader);
    }

    [Fact]
    public void Credentials_refuses_the_none_scheme_that_no_applier_branch_matches()
    {
        SectionReader.ReadCredentials(
            Json("""{ "credentials": [ { "scheme": "none", "slot": "x", "value": { "fromEnv": "E" } } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CredentialSchemeUnknown, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Credentials_refuses_a_basic_slot_that_is_neither_username_nor_password()
    {
        SectionReader.ReadCredentials(
            Json("""{ "credentials": [ { "scheme": "basic", "slot": "token", "value": { "fromEnv": "E" } } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CredentialSlotInvalid, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Credentials_refuses_a_location_on_a_scheme_that_has_none()
    {
        SectionReader.ReadCredentials(
            Json("""{ "credentials": [ { "scheme": "bearer", "slot": "Authorization", "location": "query", "value": { "fromEnv": "E" } } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CredentialLocationInvalid, ErrorCodes, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("""{ }""")]
    [InlineData("""{ "fromEnv": "A", "fromFile": "/b" }""")]
    [InlineData("""{ "fromEnv": "A", "inline": "s" }""")]
    public void Credentials_requires_exactly_one_value_source(string value)
    {
        SectionReader.ReadCredentials(
            Json($$"""{ "credentials": [ { "scheme": "bearer", "slot": "Authorization", "value": {{value}} } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CredentialReferenceAmbiguous, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Credentials_refuses_a_relative_secret_file_path()
    {
        SectionReader.ReadCredentials(
            Json("""{ "credentials": [ { "scheme": "bearer", "slot": "Authorization", "value": { "fromFile": "secrets/token" } } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CredentialReferenceUnresolved, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void An_inline_secret_is_refused_without_the_opt_in_and_never_echoed()
    {
        const string Secret = "sk-live-canary-must-not-appear";

        var section = SectionReader.ReadCredentials(
            Json($$"""{ "credentials": [ { "scheme": "bearer", "slot": "Authorization", "value": { "inline": "{{Secret}}" } } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CredentialInlineNotPermitted, ErrorCodes, StringComparer.Ordinal);
        Assert.Empty(section!.Credentials);

        foreach (var diagnostic in _diagnostics)
        {
            Assert.DoesNotContain(Secret, diagnostic.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void An_inline_secret_with_the_opt_in_is_accepted_with_a_warning_and_never_echoed()
    {
        const string Secret = "sk-live-canary-must-not-appear";

        var section = SectionReader.ReadCredentials(
            Json($$"""{ "credentials": [ { "scheme": "bearer", "slot": "Authorization", "value": { "inline": "{{Secret}}" } } ] }"""),
            _diagnostics,
            allowInlineSecrets: true);

        AssertNoErrors();
        Assert.Contains(ManifestDiagnosticCodes.CredentialInlineDiscouraged, Codes, StringComparer.Ordinal);

        var credential = Assert.Single(section!.Credentials);

        Assert.True(credential.Value.IsInline);
        Assert.Equal("inline:(redacted)", credential.Value.ToString());

        foreach (var diagnostic in _diagnostics)
        {
            Assert.DoesNotContain(Secret, diagnostic.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Credentials_leaves_destination_uniqueness_to_the_validator()
    {
        // Each of these credentials is well formed on its own; they conflict only because they
        // address the same header. Deciding that here would need a scheme-scoped identity, which
        // would miss a bearer and a basic credential both writing Authorization and would report
        // a different code than the cross-scheme case. ManifestValidator owns the invariant.
        var section = SectionReader.ReadCredentials(
            Json(
                """
                {
                  "credentials": [
                    { "scheme": "basic", "slot": "username", "value": { "fromEnv": "A" } },
                    { "scheme": "basic", "slot": "username", "value": { "fromEnv": "B" } }
                  ]
                }
                """),
            _diagnostics);

        Assert.NotNull(section);
        Assert.Equal(2, section!.Credentials.Count);
        Assert.Empty(ErrorCodes);
    }

    [Fact]
    public void Credentials_accept_a_posix_secret_path_on_every_host()
    {
        // Path.IsPathFullyQualified would reject this on Windows, so the same manifest would load
        // in the Linux container and fail when an operator validates it on a laptop.
        var section = SectionReader.ReadCredentials(
            Json(
                """
                {
                  "credentials": [
                    { "scheme": "bearer", "slot": "Authorization", "value": { "fromFile": "/run/secrets/token" } }
                  ]
                }
                """),
            _diagnostics);

        Assert.NotNull(section);
        Assert.Empty(ErrorCodes);
        Assert.Equal("/run/secrets/token", Assert.Single(section!.Credentials).Value.FromFile);
    }

    [Fact]
    public void Credentials_refuse_a_relative_secret_path()
    {
        SectionReader.ReadCredentials(
            Json(
                """
                {
                  "credentials": [
                    { "scheme": "bearer", "slot": "Authorization", "value": { "fromFile": "secrets/token" } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CredentialReferenceUnresolved, ErrorCodes, StringComparer.Ordinal);
    }

    // ---- operations ---------------------------------------------------------------------

    [Fact]
    public void Operations_reads_a_full_operation()
    {
        var section = SectionReader.ReadOperations(
            Json(
                """
                {
                  "servers": ["https://api.example.com/v1"],
                  "securitySchemes": { "bearerAuth": { "scheme": "bearer", "bearerFormat": "JWT" } },
                  "security": [ { "bearerAuth": [] } ],
                  "components": { "schemas": { "Pet": { "type": "object" } } },
                  "operations": [
                    {
                      "key": "GET /pets/{petId}",
                      "method": "GET",
                      "path": "/pets/{petId}",
                      "upstreamId": "getPetById",
                      "summary": "Get a pet",
                      "deprecated": false,
                      "tags": ["pets"],
                      "parameters": [
                        { "name": "petId", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "verbose", "in": "query", "style": "form", "explode": true,
                          "schema": { "type": "boolean" } }
                      ],
                      "responses": {
                        "200": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } } } }
                      }
                    }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.NotNull(section);
        Assert.Equal(["https://api.example.com/v1"], section.Servers);
        Assert.Equal("bearer", section.SecuritySchemes["bearerAuth"].Scheme);
        Assert.Single(section.Security);
        Assert.NotNull(section.Components);

        var operation = Assert.Single(section.Operations);

        Assert.Equal("GET /pets/{petId}", operation.Key);
        Assert.True(operation.KeyAgreesWithMethodAndPath());
        Assert.Equal("getPetById", operation.UpstreamId);
        Assert.Equal(2, operation.Parameters.Count);
        Assert.Equal(ParameterLocation.Path, operation.Parameters[0].In);
        Assert.Equal(ParameterStyle.Simple, operation.Parameters[0].EffectiveStyle);
        Assert.False(operation.Parameters[0].EffectiveExplode);
        Assert.True(operation.Parameters[1].EffectiveExplode);
        Assert.Single(operation.Responses);
    }

    [Fact]
    public void Operations_derives_an_omitted_key_from_the_method_and_path()
    {
        var section = SectionReader.ReadOperations(
            Json("""{ "operations": [ { "method": "get", "path": "/pets" } ] }"""),
            _diagnostics);

        Assert.Equal("GET /pets", Assert.Single(section!.Operations).Key);
        Assert.Equal("GET", section.Operations[0].Method);
    }

    [Fact]
    public void Operations_refuses_a_key_that_disagrees_with_the_method_and_path()
    {
        // Every binding resolves through the key, so a disagreeing key is not a cosmetic
        // inconsistency.
        SectionReader.ReadOperations(
            Json("""{ "operations": [ { "key": "POST /pets", "method": "GET", "path": "/pets" } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.KeyDisagreesWithMethodPath, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Operations_refuses_a_duplicate_execution_key()
    {
        SectionReader.ReadOperations(
            Json(
                """
                {
                  "operations": [
                    { "method": "GET", "path": "/pets" },
                    { "method": "GET", "path": "/pets" }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.DuplicateOperationKey, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Operations_refuses_the_querystring_location_that_cannot_be_serialized()
    {
        SectionReader.ReadOperations(
            Json(
                """
                {
                  "operations": [
                    { "method": "GET", "path": "/pets",
                      "parameters": [ { "name": "raw", "in": "querystring" } ] }
                  ]
                }
                """),
            _diagnostics);

        var diagnostic = Assert.Single(
            _diagnostics,
            static d => string.Equals(
                d.Code,
                ManifestDiagnosticCodes.UnsupportedParameterLocation,
                StringComparison.Ordinal));

        Assert.Contains("cannot serialize", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Operations_refuses_an_unknown_serialization_style()
    {
        SectionReader.ReadOperations(
            Json(
                """
                {
                  "operations": [
                    { "method": "GET", "path": "/pets",
                      "parameters": [ { "name": "ids", "in": "query", "style": "commaDelimited" } ] }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.UnknownParameterStyle, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Operations_accepts_a_lowercased_style_spelling()
    {
        var section = SectionReader.ReadOperations(
            Json(
                """
                {
                  "operations": [
                    { "method": "GET", "path": "/pets",
                      "parameters": [ { "name": "ids", "in": "query", "style": "spacedelimited" } ] }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.Equal(ParameterStyle.SpaceDelimited, section!.Operations[0].Parameters[0].EffectiveStyle);
    }

    [Fact]
    public void Operations_warns_when_no_response_is_declared()
    {
        SectionReader.ReadOperations(
            Json("""{ "operations": [ { "method": "GET", "path": "/pets" } ] }"""),
            _diagnostics);

        AssertNoErrors();
        Assert.Contains(ManifestDiagnosticCodes.NoResponsesDeclared, Codes, StringComparer.Ordinal);
    }

    [Fact]
    public void Operations_reads_multipart_encoding_and_keys_it_by_property_name()
    {
        var section = SectionReader.ReadOperations(
            Json(
                """
                {
                  "operations": [
                    {
                      "method": "POST",
                      "path": "/upload",
                      "requestBody": {
                        "required": true,
                        "content": {
                          "multipart/form-data": {
                            "schema": { "type": "object" },
                            "encoding": {
                              "file": { "contentType": "application/octet-stream",
                                        "headers": { "X-Part": { "type": "string" } } },
                              "meta": { "style": "form", "explode": false }
                            }
                          }
                        }
                      },
                      "responses": { "204": { } }
                    }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();

        var representation = section!.Operations[0].RequestBody!.Content["multipart/form-data"];

        Assert.Equal("file", representation.Encoding["file"].PropertyName);
        Assert.Equal("application/octet-stream", representation.Encoding["file"].ContentType);
        Assert.Single(representation.Encoding["file"].Headers);
        Assert.Equal(ParameterStyle.Form, representation.Encoding["meta"].Style);
        Assert.False(representation.Encoding["meta"].Explode);
    }

    [Fact]
    public void Operations_preserves_a_lexical_numeric_bound_and_an_unknown_keyword()
    {
        var section = SectionReader.ReadOperations(
            Json(
                """
                {
                  "operations": [
                    { "method": "GET", "path": "/pets",
                      "parameters": [
                        { "name": "limit", "in": "query",
                          "schema": { "type": "number", "minimum": 1.50, "x-vendor-hint": "keep" } }
                      ],
                      "responses": { "200": { } } }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();

        var schema = section!.Operations[0].Parameters[0].Schema!;

        Assert.Equal("1.50", schema.Object!["minimum"]!.ToJsonString());
        Assert.Equal("keep", schema.Object["x-vendor-hint"]!.GetValue<string>());
    }

    // ---- agent surface ------------------------------------------------------------------

    [Fact]
    public void AgentSurface_reads_a_full_operation()
    {
        var section = SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "groups": [ { "name": "pets", "priority": 10 } ],
                  "operations": [
                    {
                      "slug": "list-pets",
                      "kind": "source-backed",
                      "name": "List pets",
                      "summary": "Lists pets in the inventory",
                      "groups": ["pets"],
                      "tags": ["read"],
                      "inputSchema": { "type": "object" },
                      "outputSchema": null,
                      "outputSchemaPolicy": { "generate": true, "advertise": "yes", "useInternally": true },
                      "annotations": { "readOnly": true, "idempotent": true, "openWorld": true },
                      "risk": "readOnly",
                      "search": { "aliases": ["pets"], "keywords": ["inventory"], "exampleIntents": ["show my pets"] },
                      "binding": { "type": "http", "operation": "GET /pets" }
                    }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.NotNull(section);

        var group = Assert.Single(section.Groups);

        Assert.Equal("pets", group.Name);
        Assert.Equal(10, group.Priority);

        var operation = Assert.Single(section.Operations);

        Assert.Equal("list-pets", operation.Slug);
        Assert.Equal(AgentOperationKind.SourceBacked, operation.EffectiveKind);
        Assert.Equal("Lists pets in the inventory", operation.ToolDescription);
        Assert.Equal(OutputSchemaAdvertisement.Yes, operation.EffectiveOutputSchemaPolicy.Advertise);
        Assert.True(operation.EffectiveOutputSchemaPolicy.UseInternally);
        Assert.True(operation.EffectiveAnnotations().ReadOnly);
        Assert.Equal("readOnly", operation.EffectiveRisk);
        Assert.Equal(["pets"], operation.EffectiveSearch.Aliases);

        var binding = Assert.IsType<HttpBinding>(operation.Binding);

        Assert.Equal("GET /pets", binding.Operation);
        Assert.Equal("list-pets", binding.BindingId);
        Assert.Null(binding.ServerUrl);
    }

    [Fact]
    public void AgentSurface_requires_a_binding()
    {
        SectionReader.ReadAgentSurface(
            Json("""{ "operations": [ { "slug": "a", "name": "A" } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.MemberRequired, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_refuses_a_duplicate_slug()
    {
        SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    { "slug": "a", "name": "A", "binding": { "type": "http", "operation": "GET /a" } },
                    { "slug": "a", "name": "B", "binding": { "type": "http", "operation": "GET /b" } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.DuplicateAgentSlug, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_refuses_a_group_the_section_does_not_declare()
    {
        SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    { "slug": "a", "name": "A", "groups": ["pets"],
                      "binding": { "type": "http", "operation": "GET /a" } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.UnknownGroup, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_refuses_an_unknown_binding_type()
    {
        SectionReader.ReadAgentSurface(
            Json("""{ "operations": [ { "slug": "a", "name": "A", "binding": { "type": "grpc" } } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.BindingTypeUnknown, ErrorCodes, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("compound", """{ "type": "http", "operation": "GET /a" }""")]
    [InlineData("source-backed", """{ "type": "compound", "steps": [ { "stepId": "s", "operation": "b", "inputMappings": [] } ] }""")]
    public void AgentSurface_validates_the_kind_against_the_binding_shape(string kind, string binding)
    {
        SectionReader.ReadAgentSurface(
            Json($$"""{ "operations": [ { "slug": "a", "kind": "{{kind}}", "name": "A", "binding": {{binding}} } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.KindBindingMismatch, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_reads_a_transformed_binding_and_carries_the_programs_verbatim()
    {
        var section = SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    {
                      "slug": "a", "name": "A",
                      "binding": {
                        "type": "transformedHttp",
                        "base": { "operation": "POST /pets" },
                        "inputProgram": { "transformVersion": 1, "direction": "input", "base": "passthrough", "steps": [] },
                        "outputProgram": { "transformVersion": 1, "direction": "output", "base": "empty", "steps": [] }
                      }
                    }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();

        var binding = Assert.IsType<TransformedHttpBinding>(section!.Operations[0].Binding);

        Assert.Equal("POST /pets", binding.Base.Operation);
        Assert.Equal(1, binding.InputProgram!["transformVersion"]!.GetValue<int>());
        Assert.Equal("empty", binding.OutputProgram!["base"]!.GetValue<string>());
    }

    [Fact]
    public void AgentSurface_reads_a_compound_binding()
    {
        var section = SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    { "slug": "create-pet", "name": "Create", "binding": { "type": "http", "operation": "POST /pets" } },
                    { "slug": "tag-pet", "name": "Tag", "binding": { "type": "http", "operation": "PUT /pets/{petId}/tag" } },
                    {
                      "slug": "create-and-tag", "name": "Create and tag", "kind": "compound",
                      "binding": {
                        "type": "compound",
                        "bindingVersion": 1,
                        "failurePolicy": "failFast",
                        "workflowTimeoutSeconds": 30,
                        "steps": [
                          { "stepId": "create", "name": "Create pet", "operation": "create-pet",
                            "inputMappings": [ { "target": "/body/name", "argument": "/name" } ] },
                          { "stepId": "tag", "operation": "tag-pet",
                            "inputMappings": [
                              { "target": "/path/petId", "fromStep": "create", "response": "/body/id" },
                              { "target": "/body/tag", "constant": "new" }
                            ] }
                        ],
                        "outputSelection": {
                          "entries": [ { "target": "/id", "fromStep": "create", "response": "/body/id" } ]
                        }
                      }
                    }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();

        var compound = Assert.IsType<CompoundBinding>(section!.Operations[2].Binding);

        Assert.Equal(2, compound.Steps.Count);
        Assert.Equal(TimeSpan.FromSeconds(30), compound.WorkflowTimeout);
        Assert.True(compound.Steps[0].InputMappings[0].Source.IsArgument);
        Assert.True(compound.Steps[1].InputMappings[0].Source.IsStepOutput);
        Assert.True(compound.Steps[1].InputMappings[1].Source.IsConstant);
        Assert.Equal("/id", Assert.Single(compound.OutputSelection!.Entries).Target);
    }

    [Fact]
    public void AgentSurface_refuses_a_compound_step_that_targets_an_unknown_operation()
    {
        SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    { "slug": "a", "kind": "compound", "name": "A",
                      "binding": { "type": "compound",
                        "steps": [ { "stepId": "s", "operation": "absent", "inputMappings": [] } ] } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CompoundStepUnknownOperation, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_refuses_compound_nesting()
    {
        SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    { "slug": "leaf", "name": "Leaf", "binding": { "type": "http", "operation": "GET /a" } },
                    { "slug": "inner", "kind": "compound", "name": "Inner",
                      "binding": { "type": "compound",
                        "steps": [ { "stepId": "s", "operation": "leaf", "inputMappings": [] } ] } },
                    { "slug": "outer", "kind": "compound", "name": "Outer",
                      "binding": { "type": "compound",
                        "steps": [ { "stepId": "s", "operation": "inner", "inputMappings": [] } ] } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.CompoundNested, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_refuses_a_duplicate_step_identifier()
    {
        SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    { "slug": "leaf", "name": "Leaf", "binding": { "type": "http", "operation": "GET /a" } },
                    { "slug": "a", "kind": "compound", "name": "A",
                      "binding": { "type": "compound", "steps": [
                        { "stepId": "s", "operation": "leaf", "inputMappings": [] },
                        { "stepId": "s", "operation": "leaf", "inputMappings": [] }
                      ] } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.DuplicateStepId, ErrorCodes, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("self")]
    [InlineData("later")]
    [InlineData("absent")]
    public void AgentSurface_refuses_a_step_reference_that_is_not_already_declared(string reference)
    {
        // A workflow must not depend on a response that does not exist yet.
        SectionReader.ReadAgentSurface(
            Json(
                $$"""
                {
                  "operations": [
                    { "slug": "leaf", "name": "Leaf", "binding": { "type": "http", "operation": "GET /a" } },
                    { "slug": "a", "kind": "compound", "name": "A",
                      "binding": { "type": "compound", "steps": [
                        { "stepId": "self", "operation": "leaf", "inputMappings": [
                            { "target": "/body/x", "fromStep": "{{reference}}", "response": "/body/id" } ] },
                        { "stepId": "later", "operation": "leaf", "inputMappings": [] }
                      ] } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.StepReferenceUnknown, ErrorCodes, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("/status/code", "/body/id")]
    [InlineData("/bodyguard/x", "/body/id")]
    [InlineData("/body/x", "/parts/0")]
    [InlineData("/body/x", "/cookies/a")]
    public void AgentSurface_refuses_a_mapping_pointer_outside_its_permitted_scope(
        string target,
        string response)
    {
        SectionReader.ReadAgentSurface(
            Json(
                $$"""
                {
                  "operations": [
                    { "slug": "leaf", "name": "Leaf", "binding": { "type": "http", "operation": "GET /a" } },
                    { "slug": "a", "kind": "compound", "name": "A",
                      "binding": { "type": "compound", "steps": [
                        { "stepId": "one", "operation": "leaf", "inputMappings": [] },
                        { "stepId": "two", "operation": "leaf", "inputMappings": [
                            { "target": "{{target}}", "fromStep": "one", "response": "{{response}}" } ] }
                      ] } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.PointerRootNotAllowed, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_refuses_an_unsupported_compound_binding_version()
    {
        SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    { "slug": "a", "kind": "compound", "name": "A",
                      "binding": { "type": "compound", "bindingVersion": 2,
                        "steps": [ { "stepId": "s", "operation": "a", "inputMappings": [] } ] } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(
            ManifestDiagnosticCodes.CompoundBindingVersionUnsupported,
            ErrorCodes,
            StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_refuses_a_server_override_that_is_not_an_absolute_http_url()
    {
        SectionReader.ReadAgentSurface(
            Json("""{ "operations": [ { "slug": "a", "name": "A", "binding": { "type": "http", "operation": "GET /a", "serverUrl": "/relative" } } ] }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.BaseUrlInvalid, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void AgentSurface_derives_annotations_from_risk_then_from_the_method()
    {
        var section = SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    { "slug": "a", "name": "A", "risk": "destructive,mutating",
                      "binding": { "type": "http", "operation": "DELETE /a" } },
                    { "slug": "b", "name": "B", "binding": { "type": "http", "operation": "GET /b" } }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.True(section!.Operations[0].EffectiveAnnotations("DELETE").Destructive);
        Assert.False(section.Operations[0].EffectiveAnnotations("DELETE").ReadOnly);
        Assert.True(section.Operations[1].EffectiveAnnotations("GET").ReadOnly);
        Assert.True(section.Operations[1].EffectiveAnnotations("GET").Idempotent);
    }

    // ---- derivable sections -------------------------------------------------------------

    [Fact]
    public void Tools_reads_a_surface_tool_set()
    {
        var section = SectionReader.ReadTools(
            Json(
                """
                {
                  "surfaces": {
                    "default": {
                      "tools": [
                        { "name": "list_pets", "description": "Lists pets",
                          "inputSchema": { "type": "object" }, "operation": "list-pets",
                          "operationKey": "GET /pets",
                          "annotations": { "readOnly": true, "openWorld": true },
                          "sizeBytes": 128, "sizeTokens": 32 },
                        { "name": "catalogue.discover", "description": "Discover operations" }
                      ]
                    }
                  }
                }
                """),
            _diagnostics);

        AssertNoErrors();

        var tools = section!.Surfaces["default"].Tools;

        Assert.Equal(2, tools.Count);
        Assert.False(tools[0].IsNavigatorTool);
        Assert.Equal(128, tools[0].SizeBytes);
        Assert.True(tools[1].IsNavigatorTool);
    }

    [Fact]
    public void Tools_refuses_an_unbacked_tool_that_is_not_named_as_a_navigator_tool()
    {
        SectionReader.ReadTools(
            Json("""{ "surfaces": { "default": { "tools": [ { "name": "orphan", "description": "d" } ] } } }"""),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.NavigatorNameRequired, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Tools_refuses_a_duplicate_advertised_name_on_one_surface()
    {
        SectionReader.ReadTools(
            Json(
                """
                {
                  "surfaces": { "default": { "tools": [
                    { "name": "list_pets", "description": "a", "operation": "a" },
                    { "name": "list_pets", "description": "b", "operation": "b" }
                  ] } }
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.DuplicateToolName, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Search_reads_an_index_and_its_scoring_profile()
    {
        var section = SectionReader.ReadSearch(
            Json(
                """
                {
                  "builderVersion": 1,
                  "indexedFields": ["name", "summary"],
                  "scoring": {
                    "quantizationStep": 1, "metaMultiplier": 2, "vectorScale": 10000,
                    "fieldWeights": { "name": 12000, "summary": 7000 }
                  },
                  "operations": [
                    { "operation": "list-pets", "summary": "Lists pets", "risk": "readOnly",
                      "terms": { "name": ["list", "pets"], "summary": ["lists", "pets"] } }
                  ]
                }
                """),
            _diagnostics);

        AssertNoErrors();
        Assert.NotNull(section);
        Assert.Equal(["name", "summary"], section.IndexedFields);
        Assert.Equal(12000, section.EffectiveScoring.FieldWeights["name"]);

        var document = Assert.Single(section.Operations);

        Assert.Equal("list-pets", document.Operation);
        Assert.Equal(["list", "pets"], document.Terms["name"]);
    }

    [Fact]
    public void Search_discards_an_index_built_by_another_builder_version()
    {
        // A differently built index ranks differently, which is a silent relevance change
        // rather than a visible failure, so the index is dropped and rebuilt.
        Assert.Null(SectionReader.ReadSearch(Json("""{ "builderVersion": 2 }"""), _diagnostics));

        AssertNoErrors();
        // Its own code, not the derivation-mismatch code: this case recovers by rebuilding,
        // and severity has to be readable from the code alone.
        Assert.Contains(ManifestDiagnosticCodes.SearchBuilderVersionUnsupported, Codes, StringComparer.Ordinal);
    }

    // ---- reporting behavior -------------------------------------------------------------

    [Fact]
    public void A_reader_reports_every_problem_in_one_pass()
    {
        SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "unexpected": true,
                  "operations": [
                    { "slug": "a", "name": "A", "groups": ["absent"], "tags": "not-an-array",
                      "binding": { "type": "http", "operation": "GET /a" } },
                    { "slug": "a", "name": "B", "binding": { "type": "http", "operation": "GET /b" } }
                  ]
                }
                """),
            _diagnostics);

        Assert.Contains(ManifestDiagnosticCodes.UnknownMember, ErrorCodes, StringComparer.Ordinal);
        Assert.Contains(ManifestDiagnosticCodes.UnknownGroup, ErrorCodes, StringComparer.Ordinal);
        Assert.Contains(ManifestDiagnosticCodes.MemberTypeInvalid, ErrorCodes, StringComparer.Ordinal);
        Assert.Contains(ManifestDiagnosticCodes.DuplicateAgentSlug, ErrorCodes, StringComparer.Ordinal);
    }

    [Fact]
    public void Every_diagnostic_carries_its_section_and_a_location()
    {
        SectionReader.ReadOperations(
            Json("""{ "operations": [ { "method": "GET", "path": "/pets", "bogus": 1 } ] }"""),
            _diagnostics);

        var diagnostic = Assert.Single(
            _diagnostics,
            static d => string.Equals(d.Code, ManifestDiagnosticCodes.UnknownMember, StringComparison.Ordinal));

        Assert.Equal(ManifestSectionName.Operations, diagnostic.Section);
        Assert.Equal("/operations/0/bogus", diagnostic.Pointer);
    }

    [Fact]
    public void Hostile_input_echoed_into_a_diagnostic_is_truncated()
    {
        var name = new string('x', 4096);

        SectionReader.ReadServer(Json($$"""{ "name": "A", "{{name}}": 1 }"""), _diagnostics);

        var diagnostic = Assert.Single(_diagnostics);

        Assert.True(
            diagnostic.Message.Length < 512,
            $"The diagnostic echoed {diagnostic.Message.Length} characters of hostile input.");
    }
}
