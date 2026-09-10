using System;
using System.Collections.Generic;
using System.Linq;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Whether a response body is a file or a value, and which declaration answers that.
/// </summary>
public sealed class ResponseClassificationTests
{
    private static readonly (string MediaType, bool Binary)[] MediaTypeRows =
    [
        ("application/octet-stream", true),
        ("application/pdf", true),
        ("application/zip", true),
        ("application/gzip", true),
        ("application/x-tar", true),
        ("application/x-7z-compressed", true),
        ("image/png", true),
        ("image/svg+xml", false),
        ("audio/mpeg", true),
        ("video/mp4", true),
        ("application/json", false),
        ("application/json; charset=utf-8", false),
        ("APPLICATION/JSON", false),
        ("application/problem+json", false),
        ("application/atom+xml", false),
        ("application/xml", false),
        ("application/yaml", false),
        ("application/x-yaml", false),
        ("application/javascript", false),
        ("application/x-www-form-urlencoded", false),
        ("text/plain", false),
        ("text/csv", false),
        ("application/jsonx", false),
        ("application/vnd.example.thing", false),
        ("", false),
    ];

    public static TheoryData<string, bool> MediaTypes()
    {
        var data = new TheoryData<string, bool>();
        foreach (var (mediaType, binary) in MediaTypeRows)
        {
            data.Add(mediaType, binary);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(MediaTypes))]
    public void A_media_type_is_binary_exactly_when_it_has_no_useful_textual_reading(string mediaType, bool expected)
        => Assert.Equal(expected, ResponseClassification.IsBinaryMediaType(mediaType));

    [Fact]
    public void The_media_type_table_is_populated_and_states_both_outcomes()
    {
        Assert.Equal(MediaTypeRows.Length, MediaTypes().Count);
        Assert.Contains(true, MediaTypeRows.Select(row => row.Binary).ToList());
        Assert.Contains(false, MediaTypeRows.Select(row => row.Binary).ToList());
    }

    [Fact]
    public void A_structured_suffix_outranks_a_binary_looking_prefix()
    {
        // image/svg+xml is a document. Classifying it by its top-level type would hand a caller
        // a downloadable file where the contract promised a parseable one.
        Assert.False(ResponseClassification.IsBinaryMediaType("image/svg+xml"));
        Assert.True(ResponseClassification.IsBinaryMediaType("image/png"));
    }

    [Fact]
    public void An_unrecognized_type_is_read_as_a_value_rather_than_a_file()
    {
        // The default matters: a vendor subtype nobody enumerated is far more often a document
        // than a download, and defaulting the other way would turn every unknown structured
        // type into a file handle.
        Assert.False(ResponseClassification.IsBinaryMediaType("application/vnd.example.thing"));
    }

    [Fact]
    public void The_observed_type_outranks_every_declaration()
    {
        var operation = Operation(("200", "application/pdf"));

        // The contract is a claim made before the request. The header is a statement about the
        // bytes that followed it.
        Assert.False(ResponseClassification.IsBinaryResponse(operation, 200, "application/json"));
        Assert.True(ResponseClassification.IsBinaryResponse(operation, 200, "application/pdf"));
    }

    [Fact]
    public void With_nothing_observed_the_declaration_for_the_observed_status_answers()
    {
        var operation = Operation(("200", "application/pdf"), ("400", "application/problem+json"));

        Assert.True(ResponseClassification.IsBinaryResponse(operation, 200, null));
        Assert.False(ResponseClassification.IsBinaryResponse(operation, 400, null));
    }

    [Fact]
    public void A_declaration_under_an_unrelated_status_is_never_consulted()
    {
        var operation = Operation(("200", "application/pdf"));

        // 404 has no declaration and there is no default. A classifier reading the operation
        // rather than the answer would store an error page as a download.
        Assert.False(ResponseClassification.IsBinaryResponse(operation, 404, null));
    }

    [Fact]
    public void The_default_declaration_answers_only_when_the_status_has_none()
    {
        var operation = Operation(("200", "application/json"), ("default", "application/pdf"));

        Assert.False(ResponseClassification.IsBinaryResponse(operation, 200, null));
        Assert.True(ResponseClassification.IsBinaryResponse(operation, 503, null));
    }

    [Fact]
    public void An_operation_with_no_declarations_and_nothing_observed_reads_as_a_value()
    {
        Assert.False(ResponseClassification.IsBinaryResponse(Operation(), 200, null));
        Assert.False(ResponseClassification.IsBinaryResponse(null, 200, null));
    }

    [Fact]
    public void A_blank_observed_type_falls_through_to_the_contract_rather_than_deciding()
    {
        var operation = Operation(("200", "application/pdf"));

        // An upstream that sent no Content-Type has said nothing, and treating "nothing" as a
        // textual answer would ignore a declaration that does apply.
        Assert.True(ResponseClassification.IsBinaryResponse(operation, 200, "   "));
    }

    private static ManifestOperation Operation(params (string Status, string MediaType)[] declarations)
    {
        var responses = new Dictionary<string, ManifestResponse>(StringComparer.Ordinal);

        foreach (var (status, mediaType) in declarations)
        {
            responses[status] = new ManifestResponse(new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal)
            {
                [mediaType] = new(mediaType),
            });
        }

        return new ManifestOperation("GET /thing", "GET", "/thing", Responses: responses);
    }
}
