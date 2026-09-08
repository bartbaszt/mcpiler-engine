using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using MCPiler.Engine.Manifest.Validation;
using Xunit;
using EngineManifest = MCPiler.Engine.Manifest;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// The published format documentation restates rules the readers enforce, so it is a
/// second statement of one contract and can drift from the first. That cannot be removed
/// here — describing the format to a reader who is not this Engine is the whole point of
/// the document — so what is removed instead is the silence: the document is reconciled
/// against the code it describes, and a code added without being documented fails the
/// build rather than someone's expectations at runtime.
/// </summary>
public class PublishedDocumentationTests
{
    private const string DocumentPath = "docs/manifest.md";

    /// <summary>A diagnostic code as the document presents it: first cell of a table row.</summary>
    private static readonly Regex DocumentedCode = new(
        @"^\|\s*`([a-z]+/[a-z0-9-]+)`\s*\|",
        RegexOptions.Multiline | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(5));

    private static string Document() => File.ReadAllText(TestRepository.Absolute(DocumentPath));

    private static IReadOnlySet<string> DocumentedCodes()
        => DocumentedCode.Matches(Document())
            .Select(match => match.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void The_document_exists_where_the_schemas_and_fixtures_can_reference_it()
    {
        Assert.True(File.Exists(TestRepository.Absolute(DocumentPath)), DocumentPath);
    }

    [Fact]
    public void Every_diagnostic_code_is_documented()
    {
        var documented = DocumentedCodes();
        var missing = ManifestDiagnosticCodes.All
            .Where(code => !documented.Contains(code))
            .OrderBy(code => code, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"{DocumentPath} documents no meaning for: {string.Join(", ", missing)}. "
                + "A code an operator can see is part of the public contract; add a row to its group table.");
    }

    [Fact]
    public void Every_documented_code_exists()
    {
        var unknown = DocumentedCodes()
            .Where(code => !ManifestDiagnosticCodes.All.Contains(code))
            .OrderBy(code => code, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unknown.Count == 0,
            $"{DocumentPath} documents codes this Engine cannot emit: {string.Join(", ", unknown)}. "
                + "A documented code that never fires sends an operator looking for the wrong problem.");
    }

    [Fact]
    public void Every_diagnostic_group_has_its_own_table()
    {
        var text = Document();
        var missing = ManifestDiagnosticCodes.Groups
            .Where(group => !text.Contains($"### `{group}` ", StringComparison.Ordinal))
            .OrderBy(group => group, StringComparer.Ordinal)
            .ToList();

        Assert.True(missing.Count == 0, $"Undocumented diagnostic groups: {string.Join(", ", missing)}");
    }

    /// <summary>
    /// Set equality, not containment in either direction. A code documented as advisory
    /// while it actually refuses the manifest is worse than an undocumented one: it tells
    /// an operator the deployment will serve when it will not.
    /// </summary>
    [Fact]
    public void The_severity_exceptions_are_exactly_the_warning_set()
    {
        var text = Document();
        var start = text.IndexOf("always warnings", StringComparison.Ordinal);
        Assert.True(start > 0, "The document no longer states which codes are warnings.");

        var paragraph = text[start..];
        paragraph = paragraph[..paragraph.IndexOf("### `", StringComparison.Ordinal)];

        var listed = Regex.Matches(
                paragraph,
                @"`([a-z]+/[a-z0-9-]+)`",
                RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(5))
            .Select(match => match.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            ManifestDiagnosticCodes.AlwaysWarning.OrderBy(code => code, StringComparer.Ordinal),
            listed.OrderBy(code => code, StringComparer.Ordinal));
    }

    [Fact]
    public void The_supported_format_version_is_stated_and_current()
    {
        var text = Document();
        Assert.Contains(
            $"Supported by this Engine: **{EngineManifest.ManifestFormatSupport.SupportedRange}**",
            text,
            StringComparison.Ordinal);
        Assert.Contains(
            $"Current format version: **{EngineManifest.ManifestFormatSupport.Maximum}**",
            text,
            StringComparison.Ordinal);
    }

    [Fact]
    public void The_minimal_example_is_the_fixture_rather_than_a_retyped_copy()
    {
        var fixture = File.ReadAllText(TestRepository.Fixture("manifests", "minimal", "manifest.json"))
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .TrimEnd();
        var text = Document().Replace("\r\n", "\n", StringComparison.Ordinal);

        Assert.Contains(fixture, text, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_referenced_repository_path_resolves()
    {
        // Links are relative to engine/docs/, so they are resolved from there rather than
        // from the repository root: a link that does not resolve is a broken promise in a
        // document a reader outside this repository will follow.
        var directory = Path.GetDirectoryName(TestRepository.Absolute(DocumentPath))!;
        var links = Regex.Matches(
            Document(),
            @"\]\((\.\.?/[^)#]+)\)",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));

        Assert.NotEmpty(links);
        foreach (Match link in links)
        {
            var target = Path.GetFullPath(Path.Combine(directory, link.Groups[1].Value));
            Assert.True(
                File.Exists(target) || Directory.Exists(target),
                $"{DocumentPath} links to {link.Groups[1].Value}, which does not exist.");
        }
    }
}
