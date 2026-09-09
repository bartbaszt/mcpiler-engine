using MCPiler.Engine.Execution;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Covers the encoding rule directly, because every serialized parameter value passes through it and a
/// golden case can only show the composed result. Rows 6 and 7 of the change's adversarial matrix.
/// </summary>
public sealed class PercentEncodingTests
{
    [Theory]
    [InlineData("abcXYZ019")]
    [InlineData("-._~")]
    public void The_unreserved_set_is_never_encoded(string value)
    {
        Assert.Equal(value, PercentEncoding.Encode(value, allowReserved: false));
        Assert.Equal(value, PercentEncoding.Encode(value, allowReserved: true));
    }

    [Fact]
    public void A_reserved_character_is_encoded_unless_the_parameter_allows_it()
    {
        const string reserved = ":/?#[]@!$&'()*+,;=";

        Assert.Equal(reserved, PercentEncoding.Encode(reserved, allowReserved: true));

        var encoded = PercentEncoding.Encode(reserved, allowReserved: false);

        Assert.DoesNotContain(':', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.Equal(
            "%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D",
            encoded);
    }

    [Fact]
    public void A_space_is_encoded_in_both_modes_because_it_is_neither_unreserved_nor_reserved()
    {
        Assert.Equal("a%20b", PercentEncoding.Encode("a b", allowReserved: false));
        Assert.Equal("a%20b", PercentEncoding.Encode("a b", allowReserved: true));
    }

    [Fact]
    public void A_percent_sign_is_encoded_so_an_already_encoded_value_cannot_be_mistaken_for_one()
    {
        // Double encoding is the correct behaviour: the caller supplies a value, not a fragment of a
        // URL. Preserving a literal %20 would make "a%20b" and "a b" indistinguishable on the wire.
        Assert.Equal("a%2520b", PercentEncoding.Encode("a%20b", allowReserved: false));
    }

    [Fact]
    public void The_hexadecimal_digits_are_upper_case()
    {
        var encoded = PercentEncoding.Encode("~\u00ff", allowReserved: false);

        Assert.Equal("~%C3%BF", encoded);
    }

    [Fact]
    public void A_non_ascii_character_expands_to_one_triplet_per_utf8_byte()
    {
        // U+00E9 is two UTF-8 bytes, U+4E2D is three.
        Assert.Equal("%C3%A9", PercentEncoding.Encode("\u00e9", allowReserved: false));
        Assert.Equal("%E4%B8%AD", PercentEncoding.Encode("\u4e2d", allowReserved: false));
    }

    [Fact]
    public void A_combining_sequence_is_encoded_without_being_normalised()
    {
        // "e" + COMBINING ACUTE ACCENT must not be folded to the precomposed U+00E9. Two values that
        // a human reads as one must stay distinguishable, because the upstream may treat them as
        // different keys.
        var decomposed = PercentEncoding.Encode("e\u0301", allowReserved: false);
        var precomposed = PercentEncoding.Encode("\u00e9", allowReserved: false);

        Assert.Equal("e%CC%81", decomposed);
        Assert.Equal("%C3%A9", precomposed);
        Assert.NotEqual(decomposed, precomposed);
    }

    [Fact]
    public void A_surrogate_pair_is_replaced_rather_than_encoded()
    {
        // CHARACTERIZATION OF A DEFECT, not a statement of intent.
        //
        // U+1F600 GRINNING FACE is one code point carried by the surrogate pair D83D DE00, and its
        // UTF-8 form is F0 9F 98 80, so the correct output is "%F0%9F%98%80". The encoder iterates
        // UTF-16 code units and encodes each one on its own, so each half of the pair is handed to
        // the UTF-8 encoder as an unpaired surrogate and is substituted with U+FFFD. Every code point
        // above the basic multilingual plane - emoji, the CJK extensions, musical and historic
        // scripts - is therefore corrupted irreversibly on the wire.
        //
        // The behaviour is recorded rather than corrected because the correction changes outbound
        // request bytes and needs its own requirement and goldens. Both implementations carry it
        // identically, so parity is unaffected.
        Assert.Equal("%EF%BF%BD%EF%BF%BD", PercentEncoding.Encode("\U0001F600", allowReserved: false));
    }

    [Fact]
    public void A_basic_multilingual_plane_character_is_unaffected_by_that_defect()
    {
        // The boundary of the defect: anything reachable by a single UTF-16 code unit is correct.
        Assert.Equal("%EF%AC%80", PercentEncoding.Encode("\uFB00", allowReserved: false));
    }
}
