using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Canonical;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Canonical;

/// <summary>
/// Pins the canonical writer to the shared byte contract in <c>tests/fixtures/canonical</c>.
/// </summary>
/// <remarks>
/// The identical fixture set and the identical expected digests are also asserted by the
/// MCPiler Platform test suite. Engine cannot reference Platform code, so this duplicated
/// fixture is the only mechanism that stops the two independent writers from drifting.
/// A digest change here is a manifest-format-version-level change, never a test fix.
/// </remarks>
public sealed class CanonicalByteContractTests
{
    private static readonly string FixtureDirectory = TestRepository.Fixture("canonical");

    public static TheoryData<string> Fixtures()
    {
        var data = new TheoryData<string>();

        foreach (var path in Directory
            .GetFiles(FixtureDirectory, "*.input.json")
            .OrderBy(static p => p, StringComparer.Ordinal))
        {
            data.Add(Path.GetFileName(path));
        }

        return data;
    }

    [Fact]
    public void Fixture_directory_is_present_and_not_empty()
    {
        Assert.True(
            Directory.Exists(FixtureDirectory),
            $"Missing canonical fixture directory '{FixtureDirectory}'.");

        Assert.NotEmpty(Directory.GetFiles(FixtureDirectory, "*.input.json"));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Canonical_bytes_match_the_committed_expected_output(string fixtureName)
    {
        var inputPath = Path.Combine(FixtureDirectory, fixtureName);
        var expectedPath = inputPath.Replace(".input.json", ".canonical.json", StringComparison.Ordinal);

        Assert.True(File.Exists(expectedPath), $"Missing expected output '{expectedPath}'.");

        var node = CanonicalJson.Parse(File.ReadAllBytes(inputPath));
        var actual = CanonicalJson.Serialize(node);
        var expected = File.ReadAllBytes(expectedPath);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Canonical_digest_and_length_match_the_committed_expectation(string fixtureName)
    {
        var expectation = ReadExpectation(fixtureName);

        var node = CanonicalJson.Parse(File.ReadAllBytes(Path.Combine(FixtureDirectory, fixtureName)));
        var bytes = CanonicalJson.Serialize(node);

        Assert.Equal(expectation.CanonicalBytes, bytes.Length);
        Assert.Equal(expectation.Sha256, CanonicalJson.ComputeHash(bytes));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Canonicalizing_the_canonical_form_is_a_no_op(string fixtureName)
    {
        var expectedPath = Path
            .Combine(FixtureDirectory, fixtureName)
            .Replace(".input.json", ".canonical.json", StringComparison.Ordinal);

        var canonical = File.ReadAllBytes(expectedPath);
        var reserialized = CanonicalJson.Serialize(CanonicalJson.Parse(canonical));

        Assert.Equal(canonical, reserialized);
    }

    [Fact]
    public void Every_expected_entry_has_a_fixture_and_every_fixture_has_an_expected_entry()
    {
        var expected = ReadExpectationRoot()
            .Select(static member => member.Key)
            .OrderBy(static name => name, StringComparer.Ordinal)
            .ToList();

        var actual = Directory
            .GetFiles(FixtureDirectory, "*.input.json")
            .Select(static path => Path.GetFileName(path))
            .OrderBy(static name => name, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Committed_canonical_files_contain_no_line_break()
    {
        // A CRLF conversion would silently change every digest. The fixture directory
        // disables end-of-line normalization; this asserts the committed state matches.
        foreach (var path in Directory.GetFiles(FixtureDirectory, "*.canonical.json"))
        {
            var bytes = File.ReadAllBytes(path);

            Assert.DoesNotContain((byte)'\n', bytes);
            Assert.DoesNotContain((byte)'\r', bytes);
        }
    }

    private static (int CanonicalBytes, string Sha256) ReadExpectation(string fixtureName)
    {
        var entry = ReadExpectationRoot()[fixtureName]
            ?? throw new InvalidOperationException(
                $"expected-canonical.json has no entry for '{fixtureName}'.");

        return (
            entry["canonicalBytes"]!.GetValue<int>(),
            entry["sha256"]!.GetValue<string>());
    }

    private static JsonObject ReadExpectationRoot()
    {
        var path = Path.Combine(FixtureDirectory, "expected-canonical.json");
        var root = CanonicalJson.Parse(File.ReadAllBytes(path))?.AsObject()
            ?? throw new InvalidOperationException($"Could not parse '{path}'.");

        var algorithm = root["algorithm"]?.GetValue<string>();
        Assert.Equal("sha256", algorithm);

        return root["fixtures"]!.AsObject();
    }
}
