using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Projection;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Projection;

/// <summary>
/// The response-projection evaluator: selected metadata, the fixed ceilings, the normalized
/// pagination states and the refusal paths that must not become execution failures.
/// </summary>
/// <remarks>
/// One evaluation over a bounded response, no transport. The corpus expectations in
/// <c>tests/fixtures/response-projection</c> are replayed by the product path in the later
/// cross-repository task; these cases pin the individual decisions the corpus aggregates.
/// </remarks>
public sealed class ResponseProjectionEvaluatorTests
{
    private static readonly IReadOnlySet<string> NoSensitiveHeaders = new HashSet<string>(StringComparer.Ordinal);

    private static readonly Uri Effective = new("https://api.example/metadata?sig=1");

    private static Dictionary<string, string[]> Headers(params (string Name, string[] Values)[] entries)
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        foreach ((string name, string[] values) in entries)
        {
            headers[name] = values;
        }

        return headers;
    }

    private static JsonObject Arguments(params (string Name, JsonNode? Value)[] entries)
    {
        var arguments = new JsonObject();

        foreach ((string name, JsonNode? value) in entries)
        {
            arguments[name] = value;
        }

        return arguments;
    }

    [Fact]
    public void Selected_first_and_all_values_are_projected_and_an_unselected_header_is_absent()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [
                new ResponseMetadataMapping(
                    new ResponseHeaderMetadataSource("etag", HeaderValueMode.First), "/metadata/etag"),
                new ResponseMetadataMapping(
                    new ResponseHeaderMetadataSource("x-label", HeaderValueMode.All), "/metadata/labels"),
                new ResponseMetadataMapping(
                    new ResponseHeaderMetadataSource("server", HeaderValueMode.First), "/metadata/server"),
            ]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection,
            206,
            Headers(("ETag", ["v1", "v2"]), ("X-Label", ["red", "blue"])),
            Effective,
            new JsonObject { ["ok"] = true },
            rawBody: null,
            Arguments(),
            NoSensitiveHeaders,
            resolveTarget: null);

        Assert.Empty(outcome.Diagnostics);

        var value = Assert.IsType<JsonObject>(outcome.Value);
        var metadata = Assert.IsType<JsonObject>(value["metadata"]);

        Assert.Equal("v1", metadata["etag"]!.GetValue<string>());
        Assert.Equal(2, Assert.IsType<JsonArray>(metadata["labels"]).Count);
        Assert.False(metadata.ContainsKey("server"));
    }

    [Fact]
    public void Status_is_numeric_and_independent_of_the_header_budget()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [
                new ResponseMetadataMapping(new StatusCodeMetadataSource(), "/metadata/status"),
            ]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 429, Headers(("Retry-After", ["30"]), ("X-Unused", ["x"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        Assert.Equal(429,
            Assert.IsType<JsonObject>(outcome.Value)["metadata"]!["status"]!.GetValue<int>());
    }

    [Fact]
    public void A_missing_selected_header_omits_its_target_and_fails_nothing()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [new ResponseMetadataMapping(
                new ResponseHeaderMetadataSource("x-missing", HeaderValueMode.First), "/metadata/missing")]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        Assert.Empty(outcome.Diagnostics);
        Assert.False(Assert.IsType<JsonObject>(outcome.Value)["metadata"] is JsonObject metadata
            && metadata.ContainsKey("missing"));
    }

    [Fact]
    public void A_hard_denied_header_is_refused_and_its_value_never_appears()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [new ResponseMetadataMapping(
                new ResponseHeaderMetadataSource("set-cookie", HeaderValueMode.First), "/metadata/cookies")]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("Set-Cookie", ["session=secret"]), ("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.HeaderSensitive);
        Assert.DoesNotContain("secret", outcome.Value!.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_connector_sensitive_header_is_refused_even_though_it_is_not_hard_denied()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [new ResponseMetadataMapping(
                new ResponseHeaderMetadataSource("x-tenant-key", HeaderValueMode.First), "/metadata/key")]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Tenant-Key", ["tenant-secret"]), ("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(),
            new HashSet<string>(StringComparer.Ordinal) { "x-tenant-key" },
            resolveTarget: null);

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.HeaderSensitive);
        Assert.DoesNotContain("tenant-secret", outcome.Value!.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_value_containing_a_control_character_is_refused()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [new ResponseMetadataMapping(
                new ResponseHeaderMetadataSource("x-note", HeaderValueMode.First), "/metadata/note")]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Note", ["line\r\nbreak"]), ("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.HeaderInvalidValue);
        Assert.DoesNotContain("break", outcome.Value!.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_value_over_the_per_value_ceiling_is_omitted()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [new ResponseMetadataMapping(
                new ResponseHeaderMetadataSource("x-large", HeaderValueMode.First), "/metadata/large")]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200,
            Headers(("X-Large", [new string('a', ResponseProjectionLimits.MaxHeaderValueBytes + 1)]), ("ETag", ["v"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.HeaderOversized);
    }

    [Fact]
    public void More_values_than_the_per_header_ceiling_is_refused()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [new ResponseMetadataMapping(
                new ResponseHeaderMetadataSource("x-label", HeaderValueMode.All), "/metadata/labels")]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200,
            Headers(("X-Label", [.. Enumerable.Repeat("x", ResponseProjectionLimits.MaxHeaderValues + 1)]), ("ETag", ["v"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.HeaderOversized);
    }

    [Fact]
    public void The_raw_header_aggregate_drops_header_mappings_but_keeps_status()
    {
        int chunk = (ResponseProjectionLimits.MaxRawHeaderBytes / 3) + 1;
        var projection = new AgentOutputProjection(
            "/data",
            [
                new ResponseMetadataMapping(new StatusCodeMetadataSource(), "/metadata/status"),
                new ResponseMetadataMapping(
                    new ResponseHeaderMetadataSource("x-a", HeaderValueMode.First), "/metadata/a"),
                new ResponseMetadataMapping(
                    new ResponseHeaderMetadataSource("x-b", HeaderValueMode.First), "/metadata/b"),
                new ResponseMetadataMapping(
                    new ResponseHeaderMetadataSource("x-c", HeaderValueMode.First), "/metadata/c"),
            ]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200,
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["X-A"] = [new string('a', chunk)],
                ["X-B"] = [new string('b', chunk)],
                ["X-C"] = [new string('c', chunk)],
            },
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        var metadata = Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["metadata"]);

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.HeaderOversized);
        Assert.True(metadata.ContainsKey("status"));
        Assert.False(metadata.ContainsKey("a"));
        Assert.False(metadata.ContainsKey("b"));
    }

    [Fact]
    public void A_non_success_status_yields_unavailable_pagination_while_metadata_survives()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [new ResponseMetadataMapping(
                new ResponseHeaderMetadataSource("retry-after", HeaderValueMode.First), "/metadata/retryAfter")],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                NextOperation: null,
                [new PaginationArgumentMapping(
                    "/cursor", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 429,
            Headers(("Retry-After", ["30"]), ("X-Next-Cursor", ["c1"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.NonSuccessStatus);
        Assert.Equal("30", Assert.IsType<JsonObject>(outcome.Value)["metadata"]!["retryAfter"]!.GetValue<string>());
        Assert.Equal("unavailable", Assert.IsType<JsonObject>(outcome.Value)["pagination"]!["state"]!.GetValue<string>());
    }

    [Fact]
    public void A_valid_cursor_at_end_of_collection_is_end()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                NextOperation: null,
                [new PaginationArgumentMapping(
                    "/cursor", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("ETag", ["v"]), ("Server", ["s"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        var pagination = Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["pagination"]);

        Assert.Equal("end", pagination["state"]!.GetValue<string>());
        Assert.False(pagination["hasNext"]!.GetValue<bool>());
        Assert.Empty(outcome.Diagnostics);
    }

    [Fact]
    public void A_same_operation_cursor_produces_exact_next_arguments()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                NextOperation: null,
                [
                    new PaginationArgumentMapping(
                        "/account", new CurrentArgumentPaginationArgument("/account"), PaginationConversion.String),
                    new PaginationArgumentMapping(
                        "/cursor", new ExtractedPaginationArgument(), PaginationConversion.String),
                ],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Next-Cursor", ["c2"]), ("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(("account", "acme")), NoSensitiveHeaders,
            new SelfResolver("list_items"));

        var next = Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["pagination"])["next"]!;
        var arguments = Assert.IsType<JsonObject>(next["arguments"]);

        Assert.Equal("list_items", next["operation"]!.GetValue<string>());
        Assert.Equal("list_items", next["tool"]!.GetValue<string>());
        Assert.Equal("acme", arguments["account"]!.GetValue<string>());
        Assert.Equal("c2", arguments["cursor"]!.GetValue<string>());
    }

    [Fact]
    public void Nested_target_arguments_are_assembled_with_rfc6901_segments()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/pagination/cursor", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Next-Cursor", ["c-nested"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders,
            new SelfResolver("list_items_page"));

        var next = Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["pagination"])["next"]!;
        var arguments = Assert.IsType<JsonObject>(next["arguments"]);
        var pagination = Assert.IsType<JsonObject>(arguments["pagination"]);

        Assert.Equal("c-nested", pagination["cursor"]!.GetValue<string>());
        Assert.Empty(outcome.Diagnostics);
    }

    [Fact]
    public void Numeric_object_members_use_the_target_schema_instead_of_becoming_arrays()
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["filters"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["0"] = new JsonObject
                        {
                            ["type"] = "object",
                            ["properties"] = new JsonObject { ["value"] = new JsonObject { ["type"] = "string" } },
                        },
                    },
                },
            },
        };
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/filters/0/value", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Next-Cursor", ["c-nested"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders,
            new SelfResolver("list_items_page", schema));

        var arguments = Assert.IsType<JsonObject>(
            Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["pagination"])["next"]!["arguments"]!);
        var filters = Assert.IsType<JsonObject>(arguments["filters"]);
        Assert.Equal("c-nested", Assert.IsType<JsonObject>(filters["0"])["value"]!.GetValue<string>());
    }

    [Fact]
    public void Array_members_use_the_target_schema_when_assembled_from_a_missing_container()
    {
        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["rows"] = new JsonObject
                {
                    ["type"] = "array",
                    ["items"] = new JsonObject
                    {
                        ["type"] = "object",
                        ["properties"] = new JsonObject { ["value"] = new JsonObject { ["type"] = "string" } },
                    },
                },
            },
        };
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/rows/0/value", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Next-Cursor", ["c-nested"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders,
            new SelfResolver("list_items_page", schema));

        var arguments = Assert.IsType<JsonObject>(
            Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["pagination"])["next"]!["arguments"]!);
        var rows = Assert.IsType<JsonArray>(arguments["rows"]);
        Assert.Equal("c-nested", Assert.IsType<JsonObject>(rows[0])["value"]!.GetValue<string>());
    }

    [Fact]
    public void Escaped_target_segments_address_object_members_by_their_decoded_names()
    {
        var schema = new JsonObject
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
        };
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/filters/a~1b/value", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Next-Cursor", ["c-nested"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders,
            new SelfResolver("list_items_page", schema));

        var arguments = Assert.IsType<JsonObject>(
            Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["pagination"])["next"]!["arguments"]!);
        var filters = Assert.IsType<JsonObject>(arguments["filters"]);
        Assert.Equal("c-nested", Assert.IsType<JsonObject>(filters["a/b"])["value"]!.GetValue<string>());
    }

    [Fact]
    public void A_navigator_only_target_is_wrapped_in_the_navigator_payload()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/cursor", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Next-Cursor", ["c3"]), ("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders,
            new NavigatorResolver());

        var next = Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["pagination"])["next"]!;
        var arguments = Assert.IsType<JsonObject>(next["arguments"]);

        Assert.Equal("catalogue.invoke", next["tool"]!.GetValue<string>());
        Assert.Equal("list_items_page", arguments["operationKey"]!.GetValue<string>());
        Assert.Equal("c3", Assert.IsType<JsonObject>(arguments["arguments"])["cursor"]!.GetValue<string>());
    }

    [Fact]
    public void An_unreachable_target_is_unavailable_rather_than_emitted()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                "hidden_target",
                [new PaginationArgumentMapping(
                    "/cursor", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Next-Cursor", ["c4"]), ("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, resolveTarget: null);

        Assert.Equal("unavailable",
            Assert.IsType<JsonObject>(outcome.Value)["pagination"]!["state"]!.GetValue<string>());
        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.ArgumentUnmappable);
    }

    [Fact]
    public void A_json_pointer_extraction_reads_the_raw_body_while_the_envelope_holds_the_final_one()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new JsonPointerPaginationSource("/paging/nextCursor", JsonPointerInterpretation.Value),
                NextOperation: null,
                [new PaginationArgumentMapping(
                    "/cursor", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("ETag", ["v"]), ("Server", ["s"])), Effective,
            new JsonObject { ["items"] = new JsonArray() },
            new JsonObject { ["paging"] = new JsonObject { ["nextCursor"] = "k9" } },
            Arguments(), NoSensitiveHeaders, new SelfResolver("body_cursor_items"));

        var pagination = Assert.IsType<JsonObject>(Assert.IsType<JsonObject>(outcome.Value)["pagination"]);
        var arguments = Assert.IsType<JsonObject>(pagination["next"]!["arguments"]);

        Assert.Equal("k9", arguments["cursor"]!.GetValue<string>());
        Assert.False(Assert.IsType<JsonObject>(outcome.Value["data"])!.ContainsKey("paging"));
    }

    [Fact]
    public void A_link_source_parses_a_quoted_parameter_and_resolves_relative_to_the_final_uri()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new LinkHeaderPaginationSource("link", PaginationRelation.Next),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/cursor", new UrlQueryPaginationArgument("cursor"), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200,
            Headers(("Link", ["<items?cursor=c5>; title=\"one, two\"; rel=\"next\""]), ("ETag", ["v"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders,
            new UrlResolver("https://api.example/items?cursor=c5"));

        var arguments = Assert.IsType<JsonObject>(
            Assert.IsType<JsonObject>(outcome.Value)["pagination"]!["next"]!["arguments"]);

        Assert.Equal("c5", arguments["cursor"]!.GetValue<string>());
    }

    [Fact]
    public void A_relative_link_that_does_not_match_the_target_request_is_unavailable()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new LinkHeaderPaginationSource("link", PaginationRelation.Next),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/cursor", new UrlQueryPaginationArgument("cursor"), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("Link", ["<wrong/path?cursor=c6>; rel=next"]), ("ETag", ["v"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders,
            new UrlResolver(null));

        Assert.Equal("unavailable",
            Assert.IsType<JsonObject>(outcome.Value)["pagination"]!["state"]!.GetValue<string>());
        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.UrlUnrepresentable);
    }

    [Fact]
    public void A_cross_origin_link_is_refused()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new LinkHeaderPaginationSource("link", PaginationRelation.Next),
                NextOperation: null,
                [new PaginationArgumentMapping(
                    "/cursor", new UrlQueryPaginationArgument("cursor"), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200,
            Headers(("Link", ["<https://other.example/items?cursor=c7>; rel=next"]), ("ETag", ["v"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, new SelfResolver("x"));

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.LinkCrossOrigin);
    }

    [Fact]
    public void A_link_with_user_info_is_refused()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new LinkHeaderPaginationSource("link", PaginationRelation.Next),
                NextOperation: null,
                [new PaginationArgumentMapping(
                    "/cursor", new UrlQueryPaginationArgument("cursor"), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200,
            Headers(("Link", ["<https://user:pass@api.example/items?cursor=c8>; rel=next"]), ("ETag", ["v"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, new SelfResolver("x"));

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.LinkCredentialsRefused);
        Assert.DoesNotContain("pass", outcome.Value!.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Duplicate_next_relations_are_ambiguous()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new LinkHeaderPaginationSource("link", PaginationRelation.Next),
                NextOperation: null,
                [new PaginationArgumentMapping(
                    "/cursor", new UrlQueryPaginationArgument("cursor"), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200,
            Headers(("Link", ["<items?cursor=a>; rel=next", "<items?cursor=b>; rel=next"]), ("ETag", ["v"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, new SelfResolver("x"));

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.LinkAmbiguousNext);
    }

    [Fact]
    public void An_anchor_resolving_elsewhere_is_a_context_mismatch()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new LinkHeaderPaginationSource("link", PaginationRelation.Next),
                NextOperation: null,
                [new PaginationArgumentMapping(
                    "/cursor", new UrlQueryPaginationArgument("cursor"), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200,
            Headers(("Link", ["<items?cursor=c9>; rel=next; anchor=\"/different\""]), ("ETag", ["v"])),
            Effective, new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, new SelfResolver("x"));

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.LinkContextMismatch);
    }

    [Fact]
    public void A_sensitive_pagination_source_is_unavailable()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("authorization", PaginationScalarType.String),
                NextOperation: null,
                [new PaginationArgumentMapping(
                    "/cursor", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("Authorization", ["Bearer secret"]), ("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders, new SelfResolver("x"));

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.ValueSensitive);
        Assert.DoesNotContain("secret", outcome.Value!.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public void An_oversized_continuation_url_is_unavailable()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new JsonPointerPaginationSource("/nextUrl", JsonPointerInterpretation.Url),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/cursor", new UrlQueryPaginationArgument("cursor"), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        string url = "https://api.example/items?cursor=" + new string('a', ResponseProjectionLimits.MaxContinuationUrlBytes);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("ETag", ["v"]), ("Server", ["s"])), Effective,
            new JsonObject(), new JsonObject { ["nextUrl"] = url }, Arguments(), NoSensitiveHeaders,
            new UrlResolver(url));

        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.MetadataOversized);
    }

    [Fact]
    public void An_absent_body_is_omitted_while_metadata_is_projected()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [new ResponseMetadataMapping(new StatusCodeMetadataSource(), "/metadata/status")]);

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("ETag", ["v"]), ("Server", ["s"])), Effective,
            finalBody: null,
            rawBody: null,
            Arguments(),
            NoSensitiveHeaders,
            resolveTarget: null,
            hasFinalBody: false);

        var value = Assert.IsType<JsonObject>(outcome.Value);

        Assert.False(value.ContainsKey("data"));
        Assert.Equal(200, Assert.IsType<JsonObject>(value["metadata"])["status"]!.GetValue<int>());
    }

    [Fact]
    public void Arguments_the_target_schema_refuses_are_unavailable_rather_than_emitted()
    {
        var projection = new AgentOutputProjection(
            "/data",
            [],
            new PaginationPolicy(
                "/pagination",
                new ResponseHeaderPaginationSource("x-next-cursor", PaginationScalarType.String),
                "list_items_page",
                [new PaginationArgumentMapping(
                    "/cursor", new ExtractedPaginationArgument(), PaginationConversion.String)],
                ExposeUrl: false,
                LinkRelations: []));

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection, 200, Headers(("X-Next-Cursor", ["c10"]), ("ETag", ["v"])), Effective,
            new JsonObject(), rawBody: null, Arguments(), NoSensitiveHeaders,
            new RefusingArgumentsResolver());

        Assert.Equal("unavailable",
            Assert.IsType<JsonObject>(outcome.Value)["pagination"]!["state"]!.GetValue<string>());
        Assert.Contains(outcome.Diagnostics, diagnostic => diagnostic.Code == ResponseProjectionCodes.ArgumentUnmappable);
        Assert.DoesNotContain("c10", outcome.Value!.ToJsonString(), StringComparison.Ordinal);
    }

    /// <summary>A resolver that always refuses the mapped arguments against the target schema.</summary>
    private sealed class RefusingArgumentsResolver : IContinuationResolver
    {
        public ContinuationTarget? Resolve(string slug, ICollection<ExecutionDiagnostic> _)
            => new(slug, slug, NavigatorOnly: false);

        public bool ValidateArguments(
            ContinuationTarget _, JsonObject _1, ICollection<ExecutionDiagnostic> diagnostics)
        {
            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.ArgumentUnmappable));
            return false;
        }

        public bool ValidateUrl(ContinuationTarget _, JsonObject _1, string _2, ICollection<ExecutionDiagnostic> _3)
            => true;
    }

    /// <summary>A resolver that reports a self-continuation as a Direct callable.</summary>
    private sealed class SelfResolver(string slug, JsonNode? inputSchema = null) : IContinuationResolver
    {
        public ContinuationTarget? Resolve(string _1, ICollection<ExecutionDiagnostic> _2)
            => new(slug, slug, NavigatorOnly: false, InputSchema: inputSchema);

        public bool ValidateArguments(ContinuationTarget _, JsonObject _1, ICollection<ExecutionDiagnostic> _2)
            => true;

        public bool ValidateUrl(ContinuationTarget _, JsonObject _1, string _2, ICollection<ExecutionDiagnostic> _3)
            => true;
    }

    /// <summary>A resolver that reports a Navigator-only target.</summary>
    private sealed class NavigatorResolver : IContinuationResolver
    {
        public ContinuationTarget? Resolve(string slug, ICollection<ExecutionDiagnostic> _)
            => new(slug, ManifestTool.NavigatorInvoke, NavigatorOnly: true);

        public bool ValidateArguments(ContinuationTarget _, JsonObject _1, ICollection<ExecutionDiagnostic> _2)
            => true;

        public bool ValidateUrl(ContinuationTarget _, JsonObject _1, string _2, ICollection<ExecutionDiagnostic> _3)
            => true;
    }

    /// <summary>A resolver whose URL check succeeds only against one expected URL.</summary>
    private sealed class UrlResolver(string? expected) : IContinuationResolver
    {
        public ContinuationTarget? Resolve(string slug, ICollection<ExecutionDiagnostic> _)
            => new(slug, slug, NavigatorOnly: false);

        public bool ValidateArguments(ContinuationTarget _, JsonObject _1, ICollection<ExecutionDiagnostic> _2)
            => true;

        public bool ValidateUrl(
            ContinuationTarget _, JsonObject _1, string url, ICollection<ExecutionDiagnostic> diagnostics)
        {
            if (expected is not null && string.Equals(url, expected, StringComparison.Ordinal))
            {
                return true;
            }

            diagnostics.Add(new ExecutionDiagnostic(ResponseProjectionCodes.UrlUnrepresentable));
            return false;
        }
    }
}
