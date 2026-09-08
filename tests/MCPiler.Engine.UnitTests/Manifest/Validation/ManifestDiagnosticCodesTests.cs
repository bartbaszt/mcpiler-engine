using System.Reflection;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Validation;

public sealed class ManifestDiagnosticCodesTests
{
    [Fact]
    public void Every_declared_code_is_listed_in_the_published_set()
    {
        // Without this, adding a code and forgetting the set would produce a diagnostic that
        // no consumer can discover and no test can enumerate.
        var missing = DeclaredCodeFields()
            .Where(static member => !ManifestDiagnosticCodes.All.Contains(ValueOf(member)))
            .Select(static member => member.Name)
            .ToList();

        Assert.Empty(missing);
    }

    [Fact]
    public void The_published_set_contains_no_code_without_a_declaration()
    {
        var declared = DeclaredCodeFields().Select(ValueOf).ToHashSet(StringComparer.Ordinal);
        var orphans = ManifestDiagnosticCodes.All.Where(code => !declared.Contains(code)).ToList();

        Assert.Empty(orphans);
    }

    [Fact]
    public void Every_code_is_unique()
    {
        var duplicates = DeclaredCodeFields()
            .GroupBy(ValueOf, StringComparer.Ordinal)
            .Where(static group => group.Count() > 1)
            .Select(static group => group.Key)
            .ToList();

        Assert.Empty(duplicates);
    }

    [Fact]
    public void Every_code_uses_the_group_slash_kebab_case_shape()
    {
        foreach (var code in ManifestDiagnosticCodes.All)
        {
            var parts = code.Split('/');

            Assert.Equal(2, parts.Length);
            Assert.Contains(parts[0], ManifestDiagnosticCodes.Groups);
            Assert.Matches("^[a-z0-9]+(-[a-z0-9]+)*$", parts[1]);
        }
    }

    [Fact]
    public void Every_always_warning_code_is_a_real_code()
    {
        var unknown = ManifestDiagnosticCodes.AlwaysWarning
            .Where(static code => !ManifestDiagnosticCodes.All.Contains(code))
            .ToList();

        Assert.Empty(unknown);
    }

    [Fact]
    public void Every_group_prefix_is_used_by_at_least_one_code()
    {
        var used = ManifestDiagnosticCodes.All
            .Select(static code => code.Split('/')[0])
            .ToHashSet(StringComparer.Ordinal);

        var unused = ManifestDiagnosticCodes.Groups.Where(group => !used.Contains(group)).ToList();

        Assert.Empty(unused);
    }

    [Fact]
    public void The_echo_rule_truncates_hostile_input_and_marks_it()
    {
        var hostile = new string('a', DiagnosticText.MaxEchoedLength + 1);
        var echoed = DiagnosticText.Echo(hostile);

        Assert.Equal(DiagnosticText.MaxEchoedLength + DiagnosticText.TruncationMarker.Length, echoed.Length);
        Assert.EndsWith(DiagnosticText.TruncationMarker, echoed, StringComparison.Ordinal);
    }

    [Fact]
    public void The_echo_rule_leaves_a_short_value_intact()
    {
        Assert.Equal("policy", DiagnosticText.Echo("policy"));
        Assert.Equal(
            new string('a', DiagnosticText.MaxEchoedLength),
            DiagnosticText.Echo(new string('a', DiagnosticText.MaxEchoedLength)));
        Assert.Equal("(none)", DiagnosticText.Echo(null));
    }

    [Fact]
    public void The_catalogue_covers_every_documented_area()
    {
        // A missing group here means an area of the format has no way to report a problem,
        // which shows up in the field as a bare "manifest invalid".
        Assert.Equal(12, ManifestDiagnosticCodes.Groups.Count);
        Assert.True(ManifestDiagnosticCodes.All.Count >= 50);
    }

    private static IReadOnlyList<FieldInfo> DeclaredCodeFields()
        => [.. typeof(ManifestDiagnosticCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(static member => member is { IsLiteral: true, IsInitOnly: false })
            .Where(static member => member.FieldType == typeof(string))];

    private static string ValueOf(FieldInfo member) => (string)member.GetRawConstantValue()!;
}
