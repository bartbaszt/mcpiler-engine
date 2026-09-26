using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Validation;

/// <summary>
/// ADR-0071: a cross-operation continuation must name a declared, HTTP-backed and reachable
/// target whose input schema can actually receive the mapped arguments. Engine repeats these
/// checks at load because a hand-authored manifest never passed Platform compilation.
/// </summary>
public sealed class ResponseProjectionValidationTests
{
    private static readonly ManifestFormatVersion Version = new(0, 3);

    private static AgentOutputProjection Projection(string? nextOperation, params string[] mappedTargets)
        => new(
            BodyTarget: "/data",
            Metadata: [],
            Pagination: new PaginationPolicy(
                Target: "/pagination",
                Source: new LinkHeaderPaginationSource("Link", PaginationRelation.Next),
                NextOperation: nextOperation,
                NextArguments:
                [
                    .. mappedTargets.Select(target => new PaginationArgumentMapping(
                        Target: target,
                        From: new UrlQueryPaginationArgument("cursor"),
                        As: PaginationConversion.String)),
                ],
                ExposeUrl: false,
                LinkRelations: []));

    private static ManifestDocument Build(
        IReadOnlyList<SurfaceOperation>? surfaceOperations = null,
        IReadOnlyList<AgentOperationEntry>? operations = null)
    {
        var paginating = new AgentOperationEntry(
            Slug: "list-items",
            Name: "List items",
            Binding: new HttpBinding("GET /items"),
            InputSchema: Schema("cursor"),
            OutputProjection: Projection("items-page", "/cursor"));

        var target = new AgentOperationEntry(
            Slug: "items-page",
            Name: "Items page",
            Binding: new HttpBinding("GET /page"),
            InputSchema: Schema("cursor", required: ["cursor"]));

        return new ManifestDocument(
            FormatVersion: Version,
            Server: new ServerSection(
                Name: "Example API",
                Surfaces:
                [
                    new ManifestSurface(
                        "default",
                        surfaceOperations
                            ?? [
                                new SurfaceOperation("list-items", OperationExposure.Direct),
                                new SurfaceOperation("items-page", OperationExposure.Direct),
                            ],
                        IsDefault: true),
                ]),
            Policy: new PolicySection(new Uri("https://api.example.com/v1")),
            Operations: new OperationsSection(
            [
                new ManifestOperation(Key: "GET /items", Method: "GET", Path: "/items"),
                new ManifestOperation(Key: "GET /page", Method: "GET", Path: "/page"),
            ]),
            AgentSurface: new AgentSurfaceSection(operations ?? [paginating, target]));
    }

    private static ManifestSchema Schema(string property, IReadOnlyList<string>? required = null)
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject { [property] = new JsonObject { ["type"] = "string" } },
        };

        if (required is not null)
        {
            schema["required"] = new JsonArray([.. required.Select(name => JsonValue.Create(name))]);
        }

        return ManifestSchema.From(schema);
    }

    private static IReadOnlyList<string> ErrorCodes(ManifestDocument manifest)
        => [.. ManifestValidator.Validate(manifest).Where(diagnostic => diagnostic.IsError).Select(diagnostic => diagnostic.Code)];

    [Fact]
    public void A_complete_reachable_cross_operation_policy_validates()
        => Assert.DoesNotContain(
            ErrorCodes(Build()),
            code => code.StartsWith("agent/projection-", StringComparison.Ordinal));

    [Fact]
    public void An_undeclared_target_is_refused()
    {
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items"),
                InputSchema: Schema("cursor"),
                OutputProjection: Projection("ghost", "/cursor")),
        };

        Assert.Contains(
            ManifestDiagnosticCodes.ProjectionTargetUnknown,
            ErrorCodes(Build(operations: operations)));
    }

    [Fact]
    public void A_compound_target_is_refused_as_not_http_backed()
    {
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items"),
                InputSchema: Schema("cursor"),
                OutputProjection: Projection("workflow", "/cursor")),
            new(
                Slug: "workflow",
                Name: "Workflow",
                Binding: new CompoundBinding([new CompoundStepEntry("one", "list-items")]),
                Kind: AgentOperationKind.Compound),
        };

        Assert.Contains(
            ManifestDiagnosticCodes.ProjectionTargetNotHttp,
            ErrorCodes(Build(operations: operations)));
    }

    [Fact]
    public void A_mapping_absent_from_the_target_input_schema_is_refused()
    {
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items"),
                InputSchema: Schema("cursor"),
                OutputProjection: Projection("items-page", "/missing")),
            new(
                Slug: "items-page",
                Name: "Items page",
                Binding: new HttpBinding("GET /page"),
                InputSchema: Schema("cursor")),
        };

        Assert.Contains(
            ManifestDiagnosticCodes.ProjectionMappingInvalid,
            ErrorCodes(Build(operations: operations)));
    }

    [Fact]
    public void A_required_target_input_left_unmapped_is_refused()
    {
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items"),
                InputSchema: Schema("cursor"),
                OutputProjection: Projection("items-page", "/cursor")),
            new(
                Slug: "items-page",
                Name: "Items page",
                Binding: new HttpBinding("GET /page"),
                InputSchema: Schema("cursor", required: ["cursor", "account"])),
        };

        Assert.Contains(
            ManifestDiagnosticCodes.ProjectionMappingIncomplete,
            ErrorCodes(Build(operations: operations)));
    }

    [Fact]
    public void Nested_target_pointer_is_checked_against_the_target_input_schema()
    {
        var nested = ManifestSchema.From(new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["pagination"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["cursor"] = new JsonObject { ["type"] = "string" },
                    },
                    ["required"] = new JsonArray("cursor"),
                },
            },
            ["required"] = new JsonArray("pagination"),
        });
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items"),
                OutputProjection: Projection("items-page", "/pagination/cursor")),
            new(
                Slug: "items-page",
                Name: "Items page",
                Binding: new HttpBinding("GET /page"),
                InputSchema: nested),
        };

        var codes = ErrorCodes(Build(operations: operations));

        Assert.DoesNotContain(ManifestDiagnosticCodes.ProjectionMappingInvalid, codes);
        Assert.DoesNotContain(ManifestDiagnosticCodes.ProjectionMappingIncomplete, codes);
    }

    [Fact]
    public void Escaped_nested_target_members_are_resolved_against_the_target_schema()
    {
        var targetSchema = ManifestSchema.From(new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["filters"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["a/b"] = new JsonObject
                        {
                            ["type"] = "object",
                            ["properties"] = new JsonObject { ["value"] = new JsonObject { ["type"] = "string" } },
                        },
                    },
                },
            },
        });
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items"),
                OutputProjection: Projection("items-page", "/filters/a~1b/value")),
            new(
                Slug: "items-page",
                Name: "Items page",
                Binding: new HttpBinding("GET /page"),
                InputSchema: targetSchema),
        };

        var codes = ErrorCodes(Build(operations: operations));

        Assert.DoesNotContain(ManifestDiagnosticCodes.ProjectionMappingInvalid, codes);
    }

    [Fact]
    public void A_surface_publishing_the_source_without_reaching_the_target_is_refused()
    {
        var manifest = Build(
            surfaceOperations:
            [
                new SurfaceOperation("list-items", OperationExposure.Direct),
                new SurfaceOperation("items-page", OperationExposure.Hidden),
            ]);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionTargetUnreachable, ErrorCodes(manifest));
    }

    [Fact]
    public void A_navigator_exposure_without_enabled_navigator_is_unreachable()
    {
        var manifest = Build(
            surfaceOperations:
            [
                new SurfaceOperation("list-items", OperationExposure.Direct),
                new SurfaceOperation("items-page", OperationExposure.Navigator),
            ]);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionTargetUnreachable, ErrorCodes(manifest));
    }

    [Fact]
    public void A_disabled_surface_does_not_owe_reachability()
    {
        var manifest = Build(
            surfaceOperations:
            [
                new SurfaceOperation("list-items", OperationExposure.Direct),
                new SurfaceOperation("items-page", OperationExposure.Hidden),
            ]) with
        {
            Server = new ServerSection(
                Name: "Example API",
                Surfaces:
                [
                    new ManifestSurface(
                        "retired",
                        [
                            new SurfaceOperation("list-items", OperationExposure.Direct),
                            new SurfaceOperation("items-page", OperationExposure.Hidden),
                        ],
                        Enabled: false),
                ]),
        };

        Assert.DoesNotContain(ManifestDiagnosticCodes.ProjectionTargetUnreachable, ErrorCodes(manifest));
    }

    [Fact]
    public void A_self_continuation_needs_no_target_or_reachability_checks()
    {
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items"),
                InputSchema: Schema("cursor"),
                OutputProjection: Projection("list-items", "/cursor")),
        };

        var manifest = Build(
            surfaceOperations: [new SurfaceOperation("list-items", OperationExposure.Direct)],
            operations: operations);

        Assert.DoesNotContain(
            ErrorCodes(manifest),
            code => code.StartsWith("agent/projection-", StringComparison.Ordinal));
    }

    [Fact]
    public void A_closed_output_schema_that_excludes_the_pagination_envelope_is_refused()
    {
        JsonObject outputSchema = new()
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["data"] = new JsonObject { ["type"] = "object" },
                ["pagination"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["state"] = new JsonObject
                        {
                            ["type"] = "string",
                            ["enum"] = new JsonArray("next", "end"),
                        },
                    },
                    ["additionalProperties"] = false,
                },
            },
            ["additionalProperties"] = false,
        };

        ManifestDocument manifest = WithOutputSchema(Build(), outputSchema);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionOutputSchemaInvalid, ErrorCodes(manifest));
    }

    [Fact]
    public void Pagination_next_shape_is_checked_against_the_output_schema()
    {
        JsonObject outputSchema = new()
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["data"] = new JsonObject { ["type"] = "object" },
                ["pagination"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["state"] = new JsonObject { ["type"] = "string" },
                        ["hasNext"] = new JsonObject { ["type"] = "boolean" },
                        ["next"] = new JsonObject
                        {
                            ["type"] = "object",
                            ["properties"] = new JsonObject
                            {
                                ["operation"] = new JsonObject { ["type"] = "integer" },
                                ["tool"] = new JsonObject { ["type"] = "string" },
                                ["arguments"] = new JsonObject { ["type"] = "object" },
                            },
                            ["additionalProperties"] = false,
                        },
                    },
                    ["additionalProperties"] = false,
                },
            },
            ["additionalProperties"] = false,
        };

        Assert.Contains(
            ManifestDiagnosticCodes.ProjectionOutputSchemaInvalid,
            ErrorCodes(WithOutputSchema(Build(), outputSchema)));
    }

    [Fact]
    public void An_disabled_output_schema_does_not_constrain_a_projection()
    {
        JsonObject outputSchema = new() { ["type"] = "string" };
        ManifestDocument manifest = WithOutputSchema(
            Build(),
            outputSchema,
            new OutputSchemaPolicySettings(Generate: false, Advertise: OutputSchemaAdvertisement.Yes, UseInternally: true));

        Assert.DoesNotContain(ManifestDiagnosticCodes.ProjectionOutputSchemaInvalid, ErrorCodes(manifest));
    }

    [Fact]
    public void A_required_legacy_body_member_is_refused_when_projection_writes_an_envelope()
    {
        JsonObject outputSchema = new()
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["items"] = new JsonObject { ["type"] = "array" },
            },
            ["required"] = new JsonArray("items"),
            ["additionalProperties"] = false,
        };

        Assert.Contains(
            ManifestDiagnosticCodes.ProjectionOutputSchemaInvalid,
            ErrorCodes(WithOutputSchema(Build(), outputSchema)));
    }

    [Fact]
    public void A_credential_header_selected_by_projection_is_refused_at_load()
    {
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items", CredentialRef: ["session"]),
                InputSchema: Schema("cursor"),
                OutputProjection: new AgentOutputProjection(
                    "/data",
                    [new ResponseMetadataMapping(
                        new ResponseHeaderMetadataSource("X-Session-Token", HeaderValueMode.First),
                        "/token")],
                    null)),
            new(
                Slug: "items-page",
                Name: "Items page",
                Binding: new HttpBinding("GET /page"),
                InputSchema: Schema("cursor")),
        };

        ManifestDocument manifest = Build(operations: operations) with
        {
            Credentials = new CredentialsSection(
            [
                new ManifestCredential(
                    "session",
                    CredentialScheme.Header,
                    "X-Session-Token",
                    CredentialReference.Literal("secret"),
                    CredentialLocation.Header),
            ]),
        };

        Assert.Contains(ManifestDiagnosticCodes.ProjectionHeaderSensitive, ErrorCodes(manifest));
    }

    [Fact]
    public void A_response_derived_challenge_header_is_refused_at_load()
    {
        var operations = new List<AgentOperationEntry>
        {
            new(
                Slug: "list-items",
                Name: "List items",
                Binding: new HttpBinding("GET /items", AuthenticationRef: "challenge"),
                InputSchema: Schema("cursor"),
                OutputProjection: new AgentOutputProjection(
                    "/data",
                    [new ResponseMetadataMapping(
                        new ResponseHeaderMetadataSource("X-Challenge-Session", HeaderValueMode.First),
                        "/token")],
                    null)),
            new(
                Slug: "items-page",
                Name: "Items page",
                Binding: new HttpBinding("GET /page"),
                InputSchema: Schema("cursor")),
        };

        var profile = new AuthenticationProfile(
            "challenge",
            AuthenticationKind.ChallengeSession,
            new JsonObject
            {
                ["challenge"] = new JsonObject
                {
                    ["source"] = "header",
                    ["selector"] = "X-Challenge-Session",
                },
                ["injection"] = new JsonObject
                {
                    ["location"] = "header",
                    ["name"] = "X-Challenge-Session",
                },
            },
            [],
            [],
            []);

        ManifestDocument manifest = Build(operations: operations) with
        {
            Authentication = new AuthenticationSection([profile]),
        };

        Assert.Contains(ManifestDiagnosticCodes.ProjectionHeaderSensitive, ErrorCodes(manifest));
    }

    private static ManifestDocument WithOutputSchema(
        ManifestDocument manifest,
        JsonNode schema,
        OutputSchemaPolicySettings? policy = null)
    {
        IReadOnlyList<AgentOperationEntry> operations = manifest.AgentSurface.Operations
            .Select(operation => operation.OutputProjection is null
                ? operation
                : operation with
                {
                    OutputSchema = ManifestSchema.From(schema.DeepClone()),
                    OutputSchemaPolicy = policy,
                })
            .ToArray();

        return manifest with
        {
            AgentSurface = manifest.AgentSurface with { Operations = operations },
        };
    }
}
