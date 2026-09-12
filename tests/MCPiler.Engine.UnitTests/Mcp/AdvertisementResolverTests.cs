using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Mcp;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>The session-local half of output-schema advertisement.</summary>
public sealed class AdvertisementResolverTests
{
    public static TheoryData<OutputSchemaAdvertisement, string, bool, bool> Cases()
    {
        TheoryData<OutputSchemaAdvertisement, string, bool, bool> cases = new();

        foreach (OutputSchemaAdvertisement mode in Enum.GetValues<OutputSchemaAdvertisement>())
        {
            foreach (string revision in new[] { "2025-03-26", "2025-06-18", "2026-07-28" })
            {
                foreach (bool capability in new[] { false, true })
                {
                    bool expected = capability && mode switch
                    {
                        OutputSchemaAdvertisement.No => false,
                        OutputSchemaAdvertisement.Auto => revision is not "2025-03-26",
                        OutputSchemaAdvertisement.Yes => true,
                        _ => false,
                    };

                    cases.Add(mode, revision, capability, expected);
                }
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Advertisement_matches_the_closed_matrix(
        OutputSchemaAdvertisement mode,
        string revision,
        bool capability,
        bool expected)
        => Assert.Equal(
            expected,
            AdvertisementResolver.Resolve(mode, schemaIsModelled: true, capability, revision));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("newest")]
    [InlineData("2025-6-18")]
    public void Auto_fails_closed_without_a_negotiated_date_revision(string? revision)
        => Assert.False(AdvertisementResolver.Resolve(
            OutputSchemaAdvertisement.Auto,
            schemaIsModelled: true,
            manifestAllowsOutputSchemas: true,
            revision));

    [Fact]
    public void Yes_never_widens_a_manifest_capability_and_needs_a_schema()
    {
        Assert.False(AdvertisementResolver.Resolve(
            OutputSchemaAdvertisement.Yes,
            schemaIsModelled: true,
            manifestAllowsOutputSchemas: false,
            negotiatedRevision: null));
        Assert.False(AdvertisementResolver.Resolve(
            OutputSchemaAdvertisement.Yes,
            schemaIsModelled: false,
            manifestAllowsOutputSchemas: true,
            negotiatedRevision: null));
        Assert.True(AdvertisementResolver.Resolve(
            OutputSchemaAdvertisement.Yes,
            schemaIsModelled: true,
            manifestAllowsOutputSchemas: true,
            negotiatedRevision: null));
    }
}
