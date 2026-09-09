using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Validation;

public sealed class ManifestValidatorTests
{
    private static readonly ManifestFormatVersion Version = new(0, 2);

    private static ManifestOperation ListPets()
        => new(Key: "GET /pets", Method: "GET", Path: "/pets");

    private static ManifestOperation ListShops()
        => new(Key: "GET /shops", Method: "GET", Path: "/shops");

    private static AgentOperationEntry Agent(string slug, ManifestBinding binding)
        => new(Slug: slug, Name: slug, Binding: binding);

    private static ManifestDocument Build(
        ServerSection? server = null,
        PolicySection? policy = null,
        OperationsSection? operations = null,
        AgentSurfaceSection? agentSurface = null,
        CredentialsSection? credentials = null,
        JsonNode? operationsDocument = null,
        JsonNode? agentSurfaceDocument = null)
        => new(
            FormatVersion: Version,
            Server: server ?? new ServerSection(
                Name: "Example API",
                Surfaces: [new ManifestSurface("default", [new SurfaceOperation("list-pets", OperationExposure.Direct)], IsDefault: true)]),
            Policy: policy ?? new PolicySection(new Uri("https://api.example.com/v1")),
            Operations: operations ?? new OperationsSection([ListPets()]),
            AgentSurface: agentSurface ?? new AgentSurfaceSection([Agent("list-pets", new HttpBinding("GET /pets"))]),
            Credentials: credentials)
        {
            OperationsDocument = operationsDocument,
            AgentSurfaceDocument = agentSurfaceDocument,
        };

    private static IReadOnlyList<string> Codes(ManifestDocument manifest)
        => [.. ManifestValidator.Validate(manifest).Select(static d => d.Code)];

    /// <summary>
    /// Refusals only, so an advisory finding cannot change what a refusal test asserts.
    /// </summary>
    private static IReadOnlyList<string> ErrorCodes(ManifestDocument manifest)
        => [.. ManifestValidator.Validate(manifest).Where(static d => d.IsError).Select(static d => d.Code)];

    [Fact]
    public void A_consistent_manifest_produces_no_diagnostics()
        => Assert.Empty(ManifestValidator.Validate(Build()));

    // ---- surface exposure references ----------------------------------------------------

    [Fact]
    public void A_surface_exposing_an_undeclared_slug_is_refused()
    {
        ManifestDocument manifest = Build(
            server: new ServerSection(
                Name: "Example API",
                Surfaces: [new ManifestSurface("default", [new SurfaceOperation("ghost", OperationExposure.Direct)], IsDefault: true)]));

        Assert.Equal([ManifestDiagnosticCodes.SurfaceOperationUnknown], Codes(manifest));
    }

    /// <summary>
    /// A hidden entry naming an undeclared slug is refused too.
    /// </summary>
    /// <remarks>
    /// Exposure is the single invocation authority, so a hidden entry is still a statement
    /// about a specific operation. Tolerating a dangling one would make the authority's own
    /// vocabulary partly meaningless.
    /// </remarks>
    [Fact]
    public void A_hidden_entry_naming_an_undeclared_slug_is_still_refused()
    {
        ManifestDocument manifest = Build(
            server: new ServerSection(
                Name: "Example API",
                Surfaces: [new ManifestSurface("default", [new SurfaceOperation("ghost", OperationExposure.Hidden)], IsDefault: true)]));

        Assert.Equal([ManifestDiagnosticCodes.SurfaceOperationUnknown], Codes(manifest));
    }

    [Fact]
    public void Slug_matching_is_case_sensitive()
    {
        ManifestDocument manifest = Build(
            server: new ServerSection(
                Name: "Example API",
                Surfaces: [new ManifestSurface("default", [new SurfaceOperation("List-Pets", OperationExposure.Direct)], IsDefault: true)]));

        Assert.Equal([ManifestDiagnosticCodes.SurfaceOperationUnknown], Codes(manifest));
    }

    [Fact]
    public void The_diagnostic_locates_the_offending_surface_entry()
    {
        ManifestDocument manifest = Build(
            server: new ServerSection(
                Name: "Example API",
                Surfaces:
                [
                    new ManifestSurface("default", [new SurfaceOperation("list-pets", OperationExposure.Direct)], IsDefault: true),
                    new ManifestSurface("extra", [new SurfaceOperation("list-pets", OperationExposure.Direct), new SurfaceOperation("ghost", OperationExposure.Navigator)]),
                ]));

        ManifestDiagnostic diagnostic = Assert.Single(ManifestValidator.Validate(manifest));

        Assert.Equal("/surfaces/1/operations/1/operation", diagnostic.Pointer);
        Assert.Equal(ManifestSectionName.Server, diagnostic.Section);
    }

    // ---- binding execution keys ---------------------------------------------------------

    [Fact]
    public void An_http_binding_naming_an_undeclared_key_is_refused()
    {
        ManifestDocument manifest = Build(
            agentSurface: new AgentSurfaceSection([Agent("list-pets", new HttpBinding("GET /ghost"))]));

        Assert.Equal([ManifestDiagnosticCodes.BindingOperationKeyUnknown], Codes(manifest));
    }

    /// <summary>
    /// A transformed binding is resolved through its base, not through the agent operation.
    /// </summary>
    /// <remarks>
    /// A check that re-derived the executed key locally instead of going through the base is
    /// exactly how a transformation once presented a file-free key while executing a binary
    /// upload. Resolution here uses the same accessor execution will use.
    /// </remarks>
    [Fact]
    public void A_transformed_binding_is_checked_through_its_base_key()
    {
        ManifestDocument manifest = Build(
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new TransformedHttpBinding(new HttpBinding("GET /ghost"))),
            ]));

        Assert.Equal([ManifestDiagnosticCodes.BindingOperationKeyUnknown], Codes(manifest));
    }

    [Fact]
    public void A_transformed_binding_with_a_declared_base_key_is_accepted()
    {
        ManifestDocument manifest = Build(
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new TransformedHttpBinding(new HttpBinding("GET /pets"))),
            ]));

        Assert.Empty(ManifestValidator.Validate(manifest));
    }

    /// <summary>
    /// A compound binding declares no execution key of its own.
    /// </summary>
    /// <remarks>
    /// Its steps reference agent slugs in the same section, which the section reader already
    /// resolved. Inventing a key check here would report a defect that cannot exist.
    /// </remarks>
    [Fact]
    public void A_compound_binding_is_not_checked_for_an_execution_key()
    {
        ManifestDocument manifest = Build(
            server: new ServerSection(
                Name: "Example API",
                Surfaces: [new ManifestSurface("default", [new SurfaceOperation("bundle", OperationExposure.Direct)], IsDefault: true)]),
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets")),
                Agent("bundle", new CompoundBinding([new CompoundStepEntry("one", "list-pets")])),
            ]));

        Assert.Empty(ManifestValidator.Validate(manifest));
    }

    // ---- the destination perimeter ------------------------------------------------------

    [Fact]
    public void A_base_url_outside_the_perimeter_is_refused()
    {
        ManifestDocument manifest = Build(
            policy: new PolicySection(
                BaseUrl: new Uri("https://api.example.com/v1"),
                AllowedOrigins: ["https://other.example.com"]));

        Assert.Equal([ManifestDiagnosticCodes.DestinationNotAllowed], Codes(manifest));
    }

    /// <summary>
    /// The default perimeter is derived from the base URL, so it can never disagree with it.
    /// </summary>
    [Fact]
    public void An_omitted_perimeter_always_covers_the_base_url()
        => Assert.Empty(ManifestValidator.Validate(
            Build(policy: new PolicySection(new Uri("https://api.example.com/v1")))));

    [Fact]
    public void A_per_operation_server_url_outside_the_perimeter_is_refused()
    {
        ManifestDocument manifest = Build(
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets", ServerUrl: "https://attacker.example/v1")),
            ]));

        ManifestDiagnostic diagnostic = Assert.Single(ManifestValidator.Validate(manifest));

        Assert.Equal(ManifestDiagnosticCodes.DestinationNotAllowed, diagnostic.Code);
        Assert.Equal("/operations/0/binding/serverUrl", diagnostic.Pointer);
    }

    [Fact]
    public void A_per_operation_server_url_inside_the_perimeter_is_accepted()
    {
        ManifestDocument manifest = Build(
            policy: new PolicySection(
                BaseUrl: new Uri("https://api.example.com/v1"),
                AllowedOrigins: ["https://api.example.com", "https://eu.example.com"]),
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets", ServerUrl: "https://eu.example.com/v2")),
            ]));

        Assert.Empty(ManifestValidator.Validate(manifest));
    }

    /// <summary>
    /// A different port is a different origin.
    /// </summary>
    [Fact]
    public void A_server_url_on_another_port_is_outside_the_perimeter()
    {
        ManifestDocument manifest = Build(
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets", ServerUrl: "https://api.example.com:8443/v1")),
            ]));

        Assert.Equal([ManifestDiagnosticCodes.DestinationNotAllowed], Codes(manifest));
    }

    [Fact]
    public void A_server_url_on_another_scheme_is_outside_the_perimeter()
    {
        ManifestDocument manifest = Build(
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets", ServerUrl: "http://api.example.com/v1")),
            ]));

        Assert.Equal([ManifestDiagnosticCodes.DestinationNotAllowed], Codes(manifest));
    }

    [Fact]
    public void The_destination_check_runs_against_the_narrowed_perimeter()
    {
        List<ManifestDiagnostic> narrowingDiagnostics = [];

        PolicySection narrowed = PolicyNarrowing.Apply(
            new PolicySection(
                BaseUrl: new Uri("https://api.example.com/v1"),
                AllowedOrigins: ["https://api.example.com", "https://eu.example.com"]),
            new PolicyOverrides { AllowedOrigins = ["https://api.example.com"] },
            narrowingDiagnostics);

        Assert.Empty(narrowingDiagnostics);

        ManifestDocument manifest = Build(
            policy: narrowed,
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets", ServerUrl: "https://eu.example.com/v2")),
            ]));

        Assert.Equal([ManifestDiagnosticCodes.DestinationNotAllowed], Codes(manifest));
    }

    // ---- credential identity and scope --------------------------------------------------

    private static ManifestCredential Credential(
        string id,
        CredentialScheme scheme,
        string slot,
        string variable = "TOKEN",
        CredentialLocation? location = null)
        => new(id, scheme, slot, CredentialReference.Env(variable), location);

    /// <summary>
    /// One operation whose binding references the given credential ids.
    /// </summary>
    private static ManifestDocument Scoped(
        IReadOnlyList<ManifestCredential> credentials,
        params string[] refs)
        => Build(
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets", CredentialRef: refs)),
            ]),
            credentials: new CredentialsSection(credentials));

    [Fact]
    public void Two_credentials_sharing_one_id_are_refused()
    {
        ManifestDocument manifest = Scoped(
            [
                Credential("token", CredentialScheme.Bearer, "Authorization", "A"),
                Credential("token", CredentialScheme.Header, "X-Token", "B"),
            ],
            "token");

        ManifestDiagnostic diagnostic = Assert.Single(
            ManifestValidator.Validate(manifest),
            d => d.Code == ManifestDiagnosticCodes.DuplicateCredentialId);

        Assert.Equal("/credentials/1/id", diagnostic.Pointer);
        Assert.Contains("token", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("0", diagnostic.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A reference is resolved, never assumed.
    /// </summary>
    /// <remarks>
    /// A dangling reference is the failure mode that silently applies nothing, so it is
    /// refused rather than tolerated as an empty scope.
    /// </remarks>
    [Fact]
    public void A_reference_to_an_undeclared_credential_is_refused()
    {
        ManifestDocument manifest = Scoped(
            [Credential("bearer", CredentialScheme.Bearer, "Authorization")],
            "bearer",
            "ghost");

        ManifestDiagnostic diagnostic = Assert.Single(
            ManifestValidator.Validate(manifest),
            d => d.Code == ManifestDiagnosticCodes.BindingCredentialRefUnknown);

        Assert.Equal(ManifestSectionName.AgentSurface, diagnostic.Section);
        Assert.Equal("/operations/0/binding/credentialRef/1", diagnostic.Pointer);
        Assert.Contains("ghost", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("list-pets", diagnostic.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Contention is a property of one binding, not of the section.
    /// </summary>
    [Fact]
    public void One_binding_referencing_two_credentials_on_one_destination_is_refused()
    {
        ManifestDocument manifest = Scoped(
            [
                Credential("primary", CredentialScheme.Bearer, "Authorization", "A"),
                Credential("secondary", CredentialScheme.Header, "Authorization", "B"),
            ],
            "primary",
            "secondary");

        ManifestDiagnostic diagnostic = Assert.Single(
            ManifestValidator.Validate(manifest),
            d => d.Code == ManifestDiagnosticCodes.DuplicateCredentialSlot);

        Assert.Equal(ManifestSectionName.AgentSurface, diagnostic.Section);
        Assert.Contains("primary", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("secondary", diagnostic.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same two credentials on two different bindings are the point of the change.
    /// </summary>
    /// <remarks>
    /// Two upstream origins each needing their own bearer token is the configuration the
    /// section-wide rule refused while permitting the leaky single-token alternative.
    /// </remarks>
    [Fact]
    public void Two_bindings_each_referencing_its_own_credential_are_accepted()
    {
        ManifestDocument manifest = Build(
            operations: new OperationsSection([ListPets(), ListShops()]),
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets", CredentialRef: ["primary"])),
                Agent("list-shops", new HttpBinding("GET /shops", CredentialRef: ["secondary"])),
            ]),
            credentials: new CredentialsSection(
            [
                Credential("primary", CredentialScheme.Bearer, "Authorization", "A"),
                Credential("secondary", CredentialScheme.Bearer, "Authorization", "B"),
            ]));

        Assert.Empty(ManifestValidator.Validate(manifest));
    }

    /// <summary>
    /// The same name in different transports is not a collision.
    /// </summary>
    /// <remarks>
    /// An API key in a query string and a header of the same name reach the upstream service
    /// through different channels, so both are applied and neither shadows the other.
    /// </remarks>
    [Fact]
    public void The_same_name_in_a_header_and_in_a_query_is_not_a_collision()
    {
        ManifestDocument manifest = Scoped(
            [
                Credential("header-token", CredentialScheme.ApiKey, "token", "A", CredentialLocation.Header),
                Credential("query-token", CredentialScheme.ApiKey, "token", "B", CredentialLocation.Query),
            ],
            "header-token",
            "query-token");

        Assert.Empty(ManifestValidator.Validate(manifest));
    }

    /// <summary>
    /// A declared basic pair still needs both halves.
    /// </summary>
    /// <remarks>
    /// This is a declaration defect rather than a scope defect, so it stays on the section
    /// and fires whether or not any binding references the credential.
    /// </remarks>
    [Fact]
    public void A_basic_credential_needs_both_halves()
    {
        ManifestDocument manifest = Build(
            credentials: new CredentialsSection(
            [
                Credential("basic-username", CredentialScheme.Basic, ManifestCredential.BasicUsernameSlot, "USER"),
            ]));

        Assert.Equal([ManifestDiagnosticCodes.CredentialSlotInvalid], ErrorCodes(manifest));
    }

    [Fact]
    public void A_complete_basic_credential_referenced_in_full_is_accepted()
    {
        ManifestDocument manifest = Scoped(
            [
                Credential("basic-username", CredentialScheme.Basic, ManifestCredential.BasicUsernameSlot, "USER"),
                Credential("basic-password", CredentialScheme.Basic, ManifestCredential.BasicPasswordSlot, "PASS"),
            ],
            "basic-username",
            "basic-password");

        Assert.Empty(ManifestValidator.Validate(manifest));
    }

    /// <summary>
    /// Half a basic pair is not half an authorization.
    /// </summary>
    /// <remarks>
    /// Basic authentication composes one header from two slots, so a binding that reaches
    /// only one of them would send a credential no upstream service can accept.
    /// </remarks>
    [Fact]
    public void A_binding_referencing_one_half_of_a_basic_pair_is_refused()
    {
        ManifestDocument manifest = Scoped(
            [
                Credential("basic-username", CredentialScheme.Basic, ManifestCredential.BasicUsernameSlot, "USER"),
                Credential("basic-password", CredentialScheme.Basic, ManifestCredential.BasicPasswordSlot, "PASS"),
            ],
            "basic-username");

        ManifestDiagnostic diagnostic = Assert.Single(
            ManifestValidator.Validate(manifest),
            d => d.Code == ManifestDiagnosticCodes.BindingCredentialBasicIncomplete);

        Assert.Equal("/operations/0/binding/credentialRef", diagnostic.Pointer);
        Assert.Contains(ManifestCredential.BasicPasswordSlot, diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("list-pets", diagnostic.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A credential nothing references is reported without refusing the manifest.
    /// </summary>
    /// <remarks>
    /// It is almost always an authoring slip, but a manifest that refuses to load over a
    /// surplus declaration would be worse than one that serves and says so.
    /// </remarks>
    [Fact]
    public void A_credential_no_binding_references_is_a_warning()
    {
        ManifestDocument manifest = Scoped(
            [
                Credential("used", CredentialScheme.Bearer, "Authorization", "A"),
                Credential("spare", CredentialScheme.Header, "X-Spare", "B"),
            ],
            "used");

        var diagnostics = ManifestValidator.Validate(manifest);

        ManifestDiagnostic warning = Assert.Single(diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.CredentialUnreferenced, warning.Code);
        Assert.False(warning.IsError);
        Assert.Equal(ManifestSectionName.Credentials, warning.Section);
        Assert.Equal("/credentials/1/id", warning.Pointer);
        Assert.Contains("spare", warning.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The resolved scope is a set, so a repeated reference is not contention with itself.
    /// </summary>
    [Fact]
    public void A_reference_listed_twice_is_accepted()
    {
        ManifestDocument manifest = Scoped(
            [Credential("bearer", CredentialScheme.Bearer, "Authorization")],
            "bearer",
            "bearer");

        Assert.Empty(ManifestValidator.Validate(manifest));
    }

    /// <summary>
    /// Reference order is not part of the scope.
    /// </summary>
    [Fact]
    public void Reference_order_does_not_change_the_outcome()
    {
        ManifestCredential[] credentials =
        [
            Credential("header-token", CredentialScheme.ApiKey, "token", "A", CredentialLocation.Header),
            Credential("query-token", CredentialScheme.ApiKey, "token", "B", CredentialLocation.Query),
        ];

        Assert.Empty(ManifestValidator.Validate(Scoped(credentials, "header-token", "query-token")));
        Assert.Empty(ManifestValidator.Validate(Scoped(credentials, "query-token", "header-token")));
    }

    [Fact]
    public void An_absent_credentials_section_is_not_a_defect()
        => Assert.Empty(ManifestValidator.Validate(Build(credentials: null)));

    /// <summary>
    /// No credential diagnostic may disclose secret material.
    /// </summary>
    [Fact]
    public void Credential_diagnostics_never_echo_a_value()
    {
        const string Canary = "swordfish-do-not-log";

        ManifestDocument manifest = Scoped(
            [
                new ManifestCredential("primary", CredentialScheme.Bearer, "Authorization", CredentialReference.Literal(Canary)),
                new ManifestCredential("secondary", CredentialScheme.Header, "Authorization", CredentialReference.Literal(Canary)),
            ],
            "primary",
            "secondary");

        var messages = ManifestValidator.Validate(manifest).Select(static d => d.Message).ToList();

        Assert.NotEmpty(messages);
        Assert.DoesNotContain(messages, message => message.Contains(Canary, StringComparison.Ordinal));
    }

    // ---- schema references --------------------------------------------------------------

    [Fact]
    public void A_non_local_reference_in_an_operation_schema_is_refused()
    {
        JsonNode document = JsonNode.Parse(
            """
            {
              "operations": [
                {
                  "key": "GET /pets",
                  "method": "GET",
                  "path": "/pets",
                  "parameters": [
                    { "name": "filter", "in": "query", "schema": { "$ref": "https://example.com/Pet" } }
                  ]
                }
              ]
            }
            """)!;

        ManifestDocument manifest = Build(
            operations: new OperationsSection(
            [
                ListPets() with
                {
                    Parameters =
                    [
                        new ManifestParameter(
                            "filter",
                            ParameterLocation.Query,
                            Schema: ManifestSchema.From(JsonNode.Parse("""{ "$ref": "https://example.com/Pet" }""")!)),
                    ],
                },
            ]),
            operationsDocument: document);

        Assert.Equal([ManifestDiagnosticCodes.RefNotLocal], Codes(manifest));
    }

    [Fact]
    public void A_resolvable_local_reference_is_accepted()
    {
        JsonNode document = JsonNode.Parse(
            """
            {
              "components": { "schemas": { "Pet": { "type": "object" } } },
              "operations": []
            }
            """)!;

        ManifestDocument manifest = Build(
            operations: new OperationsSection(
            [
                ListPets() with
                {
                    Parameters =
                    [
                        new ManifestParameter(
                            "filter",
                            ParameterLocation.Query,
                            Schema: ManifestSchema.From(JsonNode.Parse("""{ "$ref": "#/components/schemas/Pet" }""")!)),
                    ],
                },
            ]),
            operationsDocument: document);

        Assert.Empty(ManifestValidator.Validate(manifest));
    }

    /// <summary>
    /// The resolution bound comes from the policy section, which is what makes this check
    /// cross-section rather than a section-local concern.
    /// </summary>
    [Fact]
    public void A_narrowed_schema_bound_refuses_a_schema_the_default_bound_accepts()
    {
        JsonNode document = JsonNode.Parse(
            """
            { "components": { "schemas": { "Pet": { "type": "object" } } }, "operations": [] }
            """)!;

        ManifestSchema deep = ManifestSchema.From(JsonNode.Parse(
            """
            { "type": "object", "properties": { "a": { "type": "object", "properties": {
              "b": { "type": "object", "properties": { "c": { "type": "string" } } } } } } }
            """)!);

        OperationsSection operations = new(
        [
            ListPets() with
            {
                Parameters = [new ManifestParameter("filter", ParameterLocation.Query, Schema: deep)],
            },
        ]);

        Assert.Empty(ManifestValidator.Validate(Build(
            operations: operations,
            operationsDocument: document)));

        ManifestDocument bounded = Build(
            policy: new PolicySection(
                BaseUrl: new Uri("https://api.example.com/v1"),
                SchemaBounds: SchemaBounds.Default with { MaxDepth = 2 }),
            operations: operations,
            operationsDocument: document);

        Assert.Equal([ManifestDiagnosticCodes.SchemaBoundExceeded], Codes(bounded));
    }

    [Fact]
    public void An_agent_input_schema_reference_is_validated_against_its_own_section()
    {
        JsonNode agentDocument = JsonNode.Parse("""{ "operations": [] }""")!;

        ManifestDocument manifest = Build(
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /pets")) with
                {
                    InputSchema = ManifestSchema.From(JsonNode.Parse("""{ "$ref": "#/components/schemas/Missing" }""")!),
                },
            ]),
            agentSurfaceDocument: agentDocument);

        ManifestDiagnostic diagnostic = Assert.Single(ManifestValidator.Validate(manifest));

        Assert.Equal(ManifestDiagnosticCodes.RefUnresolvable, diagnostic.Code);
        Assert.Equal(ManifestSectionName.AgentSurface, diagnostic.Section);
        Assert.Equal("/operations/0/inputSchema", diagnostic.Pointer);
    }

    [Fact]
    public void Request_body_and_response_schemas_are_both_validated()
    {
        JsonNode document = JsonNode.Parse("""{ "operations": [] }""")!;
        ManifestSchema dangling = ManifestSchema.From(JsonNode.Parse("""{ "$ref": "#/nowhere" }""")!);

        ManifestDocument manifest = Build(
            operations: new OperationsSection(
            [
                ListPets() with
                {
                    RequestBody = new ManifestRequestBody(
                        new Dictionary<string, ManifestMediaType>
                        {
                            ["application/json"] = new("application/json", Schema: dangling),
                        }),
                    Responses = new Dictionary<string, ManifestResponse>
                    {
                        ["200"] = new(new Dictionary<string, ManifestMediaType>
                        {
                            ["application/json"] = new("application/json", Schema: dangling),
                        }),
                    },
                },
            ]),
            operationsDocument: document);

        var diagnostics = ManifestValidator.Validate(manifest);

        Assert.Equal(2, diagnostics.Count);
        Assert.All(diagnostics, d => Assert.Equal(ManifestDiagnosticCodes.RefUnresolvable, d.Code));
        Assert.Contains(diagnostics, d => d.Pointer!.Contains("requestBody", StringComparison.Ordinal));
        Assert.Contains(diagnostics, d => d.Pointer!.Contains("responses", StringComparison.Ordinal));
    }

    /// <summary>
    /// A media type contains a slash, which is the JSON Pointer escape character's neighbour.
    /// </summary>
    [Fact]
    public void A_media_type_in_a_pointer_is_escaped()
    {
        JsonNode document = JsonNode.Parse("""{ "operations": [] }""")!;

        ManifestDocument manifest = Build(
            operations: new OperationsSection(
            [
                ListPets() with
                {
                    Responses = new Dictionary<string, ManifestResponse>
                    {
                        ["200"] = new(new Dictionary<string, ManifestMediaType>
                        {
                            ["application/json"] = new(
                                "application/json",
                                Schema: ManifestSchema.From(JsonNode.Parse("""{ "$ref": "#/nowhere" }""")!)),
                        }),
                    },
                },
            ]),
            operationsDocument: document);

        ManifestDiagnostic diagnostic = Assert.Single(ManifestValidator.Validate(manifest));

        Assert.Contains("application~1json", diagnostic.Pointer!, StringComparison.Ordinal);
    }

    // ---- all findings, not the first ----------------------------------------------------

    /// <summary>
    /// Independent defects are all reported in one pass.
    /// </summary>
    /// <remarks>
    /// For a hand-authored manifest the validator is the authoring tool, so stopping at the
    /// first defect would turn writing one into a guessing loop.
    /// </remarks>
    [Fact]
    public void Four_independent_defects_are_reported_together()
    {
        ManifestDocument manifest = Build(
            server: new ServerSection(
                Name: "Example API",
                Surfaces: [new ManifestSurface("default", [new SurfaceOperation("ghost", OperationExposure.Direct)], IsDefault: true)]),
            policy: new PolicySection(
                BaseUrl: new Uri("https://api.example.com/v1"),
                AllowedOrigins: ["https://other.example.com"]),
            agentSurface: new AgentSurfaceSection(
            [
                Agent("list-pets", new HttpBinding("GET /ghost", CredentialRef: ["primary", "secondary"])),
            ]),
            credentials: new CredentialsSection(
            [
                Credential("primary", CredentialScheme.Bearer, "Authorization", "A"),
                Credential("secondary", CredentialScheme.Bearer, "Authorization", "B"),
            ]));

        var diagnostics = ManifestValidator.Validate(manifest);

        Assert.Equal(
            [
                ManifestDiagnosticCodes.SurfaceOperationUnknown,
                ManifestDiagnosticCodes.BindingOperationKeyUnknown,
                ManifestDiagnosticCodes.DestinationNotAllowed,
                ManifestDiagnosticCodes.DuplicateCredentialSlot,
            ],
            diagnostics.Select(static d => d.Code));
        Assert.Equal(4, diagnostics.Select(static d => d.Pointer).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Every_produced_code_is_in_the_published_catalogue()
    {
        ManifestDocument manifest = Build(
            server: new ServerSection(
                Name: "Example API",
                Surfaces: [new ManifestSurface("default", [new SurfaceOperation("ghost", OperationExposure.Direct)], IsDefault: true)]),
            agentSurface: new AgentSurfaceSection([Agent("list-pets", new HttpBinding("GET /ghost"))]));

        var diagnostics = ManifestValidator.Validate(manifest);

        Assert.NotEmpty(diagnostics);
        Assert.All(diagnostics, d => Assert.Contains(d.Code, ManifestDiagnosticCodes.All));
    }

    /// <summary>
    /// A structural cross-section defect is always a refusal.
    /// </summary>
    /// <remarks>
    /// A dangling reference between sections leaves the runtime without an answer, so it
    /// cannot be advisory. The one advisory cross-section finding is credential
    /// reachability, which reports a surplus declaration rather than a missing answer.
    /// </remarks>
    [Fact]
    public void A_structural_cross_section_defect_is_an_error()
    {
        ManifestDocument manifest = Build(
            server: new ServerSection(
                Name: "Example API",
                Surfaces: [new ManifestSurface("default", [new SurfaceOperation("ghost", OperationExposure.Direct)], IsDefault: true)]));

        Assert.All(ManifestValidator.Validate(manifest), d => Assert.True(d.IsError));
    }
}
