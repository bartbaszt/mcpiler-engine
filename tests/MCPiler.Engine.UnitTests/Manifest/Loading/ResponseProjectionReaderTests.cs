using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

/// <summary>
/// ADR-0071: the optional <c>outputProjection</c> member is a closed, fail-closed vocabulary.
/// A hand-authored manifest that misspells a kind, exposes a sensitive header or overlaps a
/// target is refused at load instead of serving a policy nobody configured.
/// </summary>
public sealed class ResponseProjectionReaderTests
{
    private static ManifestReadResult Read(string projection)
        => ManifestReader.Read(InMemoryManifestSource.FromText(
            $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Example API" } },
                "policy": { "inline": { "baseUrl": "https://api.example.com" } },
                "operations": { "inline": { "operations": [
                    { "key": "GET /items", "method": "GET", "path": "/items" } ] } },
                "agentSurface": { "inline": { "operations": [
                    { "slug": "list-items", "name": "List items",
                      "inputSchema": { "type": "object", "properties": {
                          "cursor": { "type": "string" } } },
                      "outputProjection": {{projection}},
                      "binding": { "type": "http", "operation": "GET /items" } } ] } }
              }
            }
            """));

    private static IReadOnlyList<string> ErrorCodes(ManifestReadResult result)
        => [.. result.Errors.Select(static diagnostic => diagnostic.Code)];

    private static AgentOutputProjection Projection(ManifestReadResult result)
        => Assert.Single(result.Manifest!.AgentSurface.Operations).OutputProjection!;

    private const string ValidProjection = """
    {
      "bodyTarget": "/data",
      "metadata": [
        { "source": { "kind": "responseHeader", "name": "ETag", "valueMode": "first" },
          "target": "/metadata/etag" },
        { "source": { "kind": "statusCode" }, "target": "/metadata/status" }
      ],
      "pagination": {
        "target": "/pagination",
        "source": { "kind": "responseHeader", "name": "X-Next-Cursor", "scalarType": "string" },
        "nextArguments": [
          { "target": "/cursor", "from": { "kind": "extractedValue" }, "as": "string" } ]
      }
    }
    """;

    [Fact]
    public void A_valid_projection_reads_and_canonicalizes_the_header_name()
    {
        ManifestReadResult result = Read(ValidProjection);

        Assert.Empty(result.Errors);
        AgentOutputProjection projection = Projection(result);

        Assert.Equal("/data", projection.BodyTarget);
        Assert.Equal(2, projection.Metadata.Count);
        Assert.Equal("etag", Assert.IsType<ResponseHeaderMetadataSource>(projection.Metadata[0].Source).Name);
        Assert.IsType<StatusCodeMetadataSource>(projection.Metadata[1].Source);
        Assert.Equal(
            "x-next-cursor",
            Assert.IsType<ResponseHeaderPaginationSource>(projection.Pagination!.Source).Name);
    }

    [Fact]
    public void An_operation_without_a_projection_reads_with_no_policy()
    {
        ManifestReadResult result = ManifestReader.Read(InMemoryManifestSource.FromText(
            """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Example API" } },
                "policy": { "inline": { "baseUrl": "https://api.example.com" } },
                "operations": { "inline": { "operations": [
                    { "key": "GET /items", "method": "GET", "path": "/items" } ] } },
                "agentSurface": { "inline": { "operations": [
                    { "slug": "list-items", "name": "List items",
                      "binding": { "type": "http", "operation": "GET /items" } } ] } }
              }
            }
            """));

        Assert.Empty(result.Errors);
        Assert.Null(Assert.Single(result.Manifest!.AgentSurface.Operations).OutputProjection);
    }

    [Fact]
    public void An_unknown_projection_member_is_refused()
    {
        ManifestReadResult result = Read("""{ "bodyTarget": "/data", "wildcard": true }""");

        Assert.Contains(ManifestDiagnosticCodes.UnknownMember, ErrorCodes(result));
    }

    [Fact]
    public void An_unknown_source_kind_is_refused()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "metadata": [ { "source": { "kind": "regex", "pattern": ".*" }, "target": "/metadata/x" } ]
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionUnknownValue, ErrorCodes(result));
    }

    [Fact]
    public void An_unknown_value_mode_is_refused()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "metadata": [ { "source": { "kind": "responseHeader", "name": "ETag", "valueMode": "comma" },
                         "target": "/metadata/etag" } ]
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionUnknownValue, ErrorCodes(result));
    }

    [Fact]
    public void A_hard_denied_header_is_refused_for_projection_and_pagination()
    {
        ManifestReadResult projected = Read("""
        {
          "bodyTarget": "/data",
          "metadata": [ { "source": { "kind": "responseHeader", "name": "Set-Cookie", "valueMode": "all" },
                         "target": "/metadata/cookies" } ]
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionHeaderSensitive, ErrorCodes(projected));

        ManifestReadResult paginated = Read("""
        {
          "bodyTarget": "/data",
          "pagination": {
            "target": "/pagination",
            "source": { "kind": "responseHeader", "name": "authorization", "scalarType": "string" },
            "nextArguments": [] }
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionHeaderSensitive, ErrorCodes(paginated));
    }

    [Fact]
    public void A_non_ascii_header_name_is_refused()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "metadata": [ { "source": { "kind": "responseHeader", "name": "X-Ładunek", "valueMode": "first" },
                         "target": "/metadata/header" } ]
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionHeaderNameInvalid, ErrorCodes(result));
    }

    [Fact]
    public void A_root_or_malformed_pointer_is_refused()
    {
        ManifestReadResult root = Read("""{ "bodyTarget": "" }""");
        Assert.Contains(ManifestDiagnosticCodes.ProjectionPointerInvalid, ErrorCodes(root));

        ManifestReadResult escape = Read("""{ "bodyTarget": "/data~2" }""");
        Assert.Contains(ManifestDiagnosticCodes.ProjectionPointerInvalid, ErrorCodes(escape));
    }

    [Fact]
    public void Overlapping_targets_are_refused()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "metadata": [
            { "source": { "kind": "statusCode" }, "target": "/metadata" },
            { "source": { "kind": "responseHeader", "name": "etag", "valueMode": "first" },
              "target": "/metadata/etag" } ]
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionTargetOverlap, ErrorCodes(result));
    }

    [Fact]
    public void A_pagination_target_overlapping_the_body_target_is_refused()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "pagination": {
            "target": "/data",
            "source": { "kind": "responseHeader", "name": "x-next-cursor", "scalarType": "string" },
            "nextArguments": [] }
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionTargetOverlap, ErrorCodes(result));
    }

    [Fact]
    public void A_url_component_source_without_a_url_source_is_refused()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "pagination": {
            "target": "/pagination",
            "source": { "kind": "responseHeader", "name": "x-next-cursor", "scalarType": "string" },
            "nextArguments": [
              { "target": "/cursor", "from": { "kind": "urlQuery", "name": "cursor" }, "as": "string" } ] }
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionUrlSourceRequired, ErrorCodes(result));
    }

    [Fact]
    public void A_link_source_with_a_relation_other_than_next_is_refused_in_v1()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "pagination": {
            "target": "/pagination",
            "source": { "kind": "linkHeader", "header": "Link", "relation": "prev" },
            "nextArguments": [] }
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionShapeInvalid, ErrorCodes(result));
    }

    [Fact]
    public void Preserve_json_from_a_header_source_is_refused()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "pagination": {
            "target": "/pagination",
            "source": { "kind": "responseHeader", "name": "x-next-cursor", "scalarType": "string" },
            "nextArguments": [
              { "target": "/cursor", "from": { "kind": "extractedValue" }, "as": "preserveJson" } ] }
        }
        """);

        Assert.Contains(ManifestDiagnosticCodes.ProjectionUnknownValue, ErrorCodes(result));
    }

    [Fact]
    public void A_json_pointer_source_may_preserve_json_and_map_url_components()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "pagination": {
            "target": "/pagination",
            "source": { "kind": "jsonPointer", "pointer": "/nextUrl", "interpretation": "url" },
            "nextArguments": [
              { "target": "/cursor", "from": { "kind": "urlQuery", "name": "cursor" }, "as": "string" },
              { "target": "/snapshot", "from": { "kind": "extractedValue" }, "as": "preserveJson" } ] }
        }
        """);

        Assert.Empty(result.Errors);
        Assert.IsType<JsonPointerPaginationSource>(Projection(result).Pagination!.Source);
    }

    [Fact]
    public void A_literal_argument_reads_its_value()
    {
        ManifestReadResult result = Read("""
        {
          "bodyTarget": "/data",
          "pagination": {
            "target": "/pagination",
            "source": { "kind": "responseHeader", "name": "x-next-cursor", "scalarType": "string" },
            "nextOperation": "list-items",
            "nextArguments": [
              { "target": "/cursor", "from": { "kind": "extractedValue" }, "as": "string" },
              { "target": "/tenant", "from": { "kind": "literal", "value": "acme" }, "as": "string" } ] }
        }
        """);

        Assert.Empty(result.Errors);
        var literal = Assert.IsType<LiteralPaginationArgument>(
            Projection(result).Pagination!.NextArguments[1].From);

        Assert.Equal("acme", literal.Value!.GetValue<string>());
    }

    [Fact]
    public void An_unsupported_section_version_is_refused_by_name()
    {
        ManifestReadResult result = ManifestReader.Read(InMemoryManifestSource.FromText(
            """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Example API" } },
                "policy": { "inline": { "baseUrl": "https://api.example.com" } },
                "operations": { "inline": { "operations": [
                    { "key": "GET /items", "method": "GET", "path": "/items" } ] } },
                "agentSurface": { "inline": { "formatVersion": 3, "operations": [
                    { "slug": "list-items", "name": "List items",
                      "binding": { "type": "http", "operation": "GET /items" } } ] } }
              }
            }
            """));

        Assert.Contains(ManifestDiagnosticCodes.SectionFormatVersionUnsupported, ErrorCodes(result));
    }
}
