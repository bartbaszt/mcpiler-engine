using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Model;

public sealed class VocabularyTests
{
    [Theory]
    [InlineData("direct", OperationExposure.Direct)]
    [InlineData("navigator", OperationExposure.Navigator)]
    [InlineData("hidden", OperationExposure.Hidden)]
    [InlineData("DIRECT", OperationExposure.Direct)]
    public void Reads_exposure_case_insensitively(string wire, OperationExposure expected)
    {
        Assert.True(Vocabulary.TryReadExposure(wire, out var value));
        Assert.Equal(expected, value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" direct")]
    [InlineData("directt")]
    [InlineData("exposed")]
    [InlineData("0")]
    public void Refuses_an_unrecognized_exposure_instead_of_defaulting(string? wire)
    {
        Assert.False(Vocabulary.TryReadExposure(wire, out _));
    }

    [Fact]
    public void Refuses_the_querystring_parameter_location()
    {
        // The intermediate model has this location but the request compiler cannot execute
        // it, so admitting it would create an authorable-but-unexecutable construct.
        Assert.False(Vocabulary.TryReadParameterLocation("querystring", out _));
    }

    // The request compiler switches over this enum exhaustively and carries no refusal branch for a
    // location it cannot serialize, because there is none: the impossibility is a property of the
    // vocabulary rather than a runtime check. That only stays true while the enum is exactly these
    // four, so the enum is what gets asserted. Adding a fifth member without a compiler arm is a
    // build error; adding one with an arm has to be a deliberate decision, and this test is where it
    // announces itself.
    [Fact]
    public void The_parameter_locations_are_exactly_the_four_a_request_can_carry()
    {
        Assert.Equal(
            [ParameterLocation.Query, ParameterLocation.Header, ParameterLocation.Path, ParameterLocation.Cookie],
            Enum.GetValues<ParameterLocation>());
    }

    [Theory]
    [InlineData("spaceDelimited", ParameterStyle.SpaceDelimited)]
    [InlineData("spacedelimited", ParameterStyle.SpaceDelimited)]
    [InlineData("pipeDelimited", ParameterStyle.PipeDelimited)]
    [InlineData("deepObject", ParameterStyle.DeepObject)]
    public void Reads_a_style_in_both_the_canonical_and_the_lowercase_spelling(
        string wire,
        ParameterStyle expected)
    {
        // The existing request compiler compares lowercased style names, so a manifest
        // authored against that spelling must keep working.
        Assert.True(Vocabulary.TryReadParameterStyle(wire, out var value));
        Assert.Equal(expected, value);
    }

    [Fact]
    public void Refuses_the_none_credential_scheme_because_no_branch_applies_it()
    {
        // "none" appears in Platform doc comments but the applier never matches it, so it
        // would be a silent no-op rather than "no authentication".
        Assert.False(Vocabulary.TryReadCredentialScheme("none", out _));
    }

    [Theory]
    [InlineData("basic", CredentialScheme.Basic)]
    [InlineData("bearer", CredentialScheme.Bearer)]
    [InlineData("apiKey", CredentialScheme.ApiKey)]
    [InlineData("header", CredentialScheme.Header)]
    public void Reads_every_credential_scheme_the_applier_switches_on(
        string wire,
        CredentialScheme expected)
    {
        Assert.True(Vocabulary.TryReadCredentialScheme(wire, out var value));
        Assert.Equal(expected, value);
    }

    [Fact]
    public void Round_trips_every_value_of_every_closed_vocabulary()
    {
        AssertRoundTrip(Enum.GetValues<OperationExposure>(), Vocabulary.Write, Vocabulary.TryReadExposure);
        AssertRoundTrip(Enum.GetValues<ParameterLocation>(), Vocabulary.Write, Vocabulary.TryReadParameterLocation);
        AssertRoundTrip(Enum.GetValues<ParameterStyle>(), Vocabulary.Write, Vocabulary.TryReadParameterStyle);
        AssertRoundTrip(Enum.GetValues<AgentOperationKind>(), Vocabulary.Write, Vocabulary.TryReadOperationKind);
        AssertRoundTrip(Enum.GetValues<OutputSchemaAdvertisement>(), Vocabulary.Write, Vocabulary.TryReadAdvertisement);
        AssertRoundTrip(Enum.GetValues<CredentialScheme>(), Vocabulary.Write, Vocabulary.TryReadCredentialScheme);
        AssertRoundTrip(Enum.GetValues<CredentialLocation>(), Vocabulary.Write, Vocabulary.TryReadCredentialLocation);
        AssertRoundTrip(Enum.GetValues<CompoundFailurePolicy>(), Vocabulary.Write, Vocabulary.TryReadFailurePolicy);
    }

    [Fact]
    public void Exposes_the_accepted_spellings_so_a_diagnostic_can_list_them()
    {
        Assert.Equal(["direct", "navigator", "hidden"], Vocabulary.ExposureNames);
        Assert.Equal(["query", "header", "path", "cookie"], Vocabulary.ParameterLocationNames);
        Assert.Equal(["source-backed", "custom-http", "compound"], Vocabulary.OperationKindNames);
        Assert.Equal(["basic", "bearer", "apiKey", "header"], Vocabulary.CredentialSchemeNames);
    }

    [Theory]
    [InlineData(ParameterLocation.Path, ParameterStyle.Simple)]
    [InlineData(ParameterLocation.Query, ParameterStyle.Form)]
    [InlineData(ParameterLocation.Header, ParameterStyle.Simple)]
    [InlineData(ParameterLocation.Cookie, ParameterStyle.Form)]
    public void Applies_the_documented_default_style(ParameterLocation location, ParameterStyle expected)
    {
        Assert.Equal(expected, Vocabulary.DefaultStyle(location));
    }

    // The rule is the style, not the location. A cookie parameter's default style is form, so it
    // explodes by default exactly as a query parameter does; asserting the location-independence
    // directly is what keeps a future revision from reintroducing a query-only special case.
    [Theory]
    [InlineData(ParameterLocation.Query, ParameterStyle.Form, true)]
    [InlineData(ParameterLocation.Query, ParameterStyle.SpaceDelimited, false)]
    [InlineData(ParameterLocation.Query, ParameterStyle.DeepObject, false)]
    [InlineData(ParameterLocation.Path, ParameterStyle.Simple, false)]
    [InlineData(ParameterLocation.Path, ParameterStyle.Matrix, false)]
    [InlineData(ParameterLocation.Path, ParameterStyle.Form, true)]
    [InlineData(ParameterLocation.Header, ParameterStyle.Simple, false)]
    [InlineData(ParameterLocation.Header, ParameterStyle.Form, true)]
    [InlineData(ParameterLocation.Cookie, ParameterStyle.Form, true)]
    [InlineData(ParameterLocation.Cookie, ParameterStyle.Simple, false)]
    public void Applies_the_documented_default_explode(
        ParameterLocation location,
        ParameterStyle style,
        bool expected)
    {
        Assert.Equal(expected, Vocabulary.DefaultExplode(location, style));
    }

    private static void AssertRoundTrip<T>(
        T[] values,
        Func<T, string> write,
        TryRead<T> read)
        where T : struct, Enum
    {
        foreach (var value in values)
        {
            var wire = write(value);

            Assert.True(read(wire, out var parsed), $"'{wire}' did not round-trip for {typeof(T).Name}.");
            Assert.Equal(value, parsed);
        }
    }

    private delegate bool TryRead<T>(string? wire, out T value)
        where T : struct, Enum;
}
