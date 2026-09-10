using System;
using System.Linq;
using System.Text;

using MCPiler.Engine.Execution;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Declared media type against content signature: match, conflict, and the cases where nothing
/// is comparable.
/// </summary>
/// <remarks>
/// The third answer is the one worth pinning. A check that reported a match whenever it had
/// nothing to compare would let the rejecting policy pass every payload whose declared type
/// carries no signature, while reading in code as though it were enforcing something.
/// </remarks>
public sealed class ContentSignatureTests
{
    private static readonly (string Declared, string Essence)[] EssenceRows =
    [
        ("application/json", "application/json"),
        ("application/json; charset=utf-8", "application/json"),
        ("APPLICATION/JSON", "application/json"),
        ("  application/json  ", "application/json"),
        ("multipart/form-data; boundary=abc", "multipart/form-data"),
        ("", ""),
        ("   ", ""),
    ];

    public static TheoryData<string, string> Essences()
    {
        var data = new TheoryData<string, string>();
        foreach (var (declared, essence) in EssenceRows)
        {
            data.Add(declared, essence);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Essences))]
    public void A_media_type_reduces_to_its_essence(string declared, string expected)
        => Assert.Equal(expected, ContentSignature.Essence(declared));

    [Fact]
    public void The_essence_table_is_populated_and_covers_both_a_value_and_an_absence()
    {
        Assert.Equal(EssenceRows.Length, Essences().Count);
        Assert.Contains(string.Empty, EssenceRows.Select(row => row.Essence).ToList());
        Assert.Contains("application/json", EssenceRows.Select(row => row.Essence).ToList());
    }

    [Fact]
    public void A_null_media_type_compares_nothing()
        => Assert.Equal(SignatureVerdict.Undefined, ContentSignature.Evaluate(null, [1, 2, 3]));

    [Fact]
    public void A_type_with_no_defined_signature_compares_nothing()
    {
        // Reporting a match here would claim a comparison that had no content, and the
        // rejecting policy would then be enforcing nothing for the most common declared type
        // of all.
        Assert.Equal(
            SignatureVerdict.Undefined,
            ContentSignature.Evaluate("application/octet-stream", [0x00, 0x01]));

        Assert.Equal(
            SignatureVerdict.Undefined,
            ContentSignature.Evaluate("application/vnd.example.thing", [0x00]));
    }

    [Theory]
    [InlineData("application/pdf", new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D, 0x31 })]
    [InlineData("image/png", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00 })]
    [InlineData("image/jpeg", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 })]
    [InlineData("image/gif", new byte[] { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 })]
    [InlineData("application/zip", new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14 })]
    [InlineData("application/gzip", new byte[] { 0x1F, 0x8B, 0x08 })]
    public void Content_beginning_the_declared_way_matches(string declared, byte[] probe)
        => Assert.Equal(SignatureVerdict.Match, ContentSignature.Evaluate(declared, probe));

    [Theory]
    [InlineData("application/pdf")]
    [InlineData("image/png")]
    [InlineData("image/jpeg")]
    [InlineData("application/zip")]
    [InlineData("application/gzip")]
    public void Content_that_does_not_begin_the_declared_way_conflicts(string declared)
        => Assert.Equal(
            SignatureVerdict.Conflict,
            ContentSignature.Evaluate(declared, Encoding.UTF8.GetBytes("plain text, not a binary header")));

    [Fact]
    public void A_signature_longer_than_the_payload_conflicts_rather_than_matching_a_prefix()
    {
        // Two of the eight PNG bytes. A comparison that stopped at the shorter length would
        // treat a truncated header as a match.
        Assert.Equal(SignatureVerdict.Conflict, ContentSignature.Evaluate("image/png", [0x89, 0x50]));
        Assert.Equal(SignatureVerdict.Conflict, ContentSignature.Evaluate("image/png", []));
    }

    [Theory]
    [InlineData("text/plain")]
    [InlineData("text/csv")]
    [InlineData("application/json")]
    [InlineData("application/problem+json")]
    [InlineData("application/xml")]
    [InlineData("application/atom+xml")]
    [InlineData("application/yaml")]
    [InlineData("application/x-yaml")]
    [InlineData("application/javascript")]
    [InlineData("application/x-www-form-urlencoded")]
    public void A_textual_type_matches_textual_content(string declared)
        => Assert.Equal(
            SignatureVerdict.Match,
            ContentSignature.Evaluate(declared, Encoding.UTF8.GetBytes("{\"ok\":true}")));

    [Fact]
    public void A_textual_type_conflicts_with_an_embedded_nul()
    {
        // A textual type has no magic bytes but it does have a shape. A NUL is not something a
        // JSON, XML, YAML or text payload contains, so it contradicts the declaration even
        // though nothing about the first byte does.
        Assert.Equal(
            SignatureVerdict.Conflict,
            ContentSignature.Evaluate("application/json", [.. Encoding.UTF8.GetBytes("{\"a\":"), 0x00, .. Encoding.UTF8.GetBytes("1}")]));
    }

    [Fact]
    public void A_type_that_merely_resembles_a_textual_one_is_not_treated_as_textual()
    {
        // application/jsonx is a different media type. Treating it as textual would apply a
        // shape rule the declaration never asked for.
        Assert.Equal(
            SignatureVerdict.Undefined,
            ContentSignature.Evaluate("application/jsonx", [0x00]));

        Assert.Equal(
            SignatureVerdict.Undefined,
            ContentSignature.Evaluate("application/json-patch", [0x00]));
    }

    [Fact]
    public void A_declared_type_with_parameters_is_judged_by_its_essence()
        => Assert.Equal(
            SignatureVerdict.Match,
            ContentSignature.Evaluate("image/png; quality=high", [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]));

    [Fact]
    public void The_probe_length_is_enough_for_every_declared_signature()
    {
        // Stated so that adding a longer signature than the probe fails here rather than
        // silently conflicting on every payload of that type.
        Assert.True(ContentSignature.ProbeLength >= 8);
    }
}
