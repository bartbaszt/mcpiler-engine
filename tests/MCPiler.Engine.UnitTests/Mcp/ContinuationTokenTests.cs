using MCPiler.Engine.Mcp.Navigator;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>
/// The token that continues a page, and the lists it refuses to continue.
/// </summary>
public sealed class ContinuationTokenTests
{
    private const string Identity = "0123456789abcdef";
    private const string Other = "fedcba9876543210";

    [Fact]
    public void A_token_returns_the_position_it_was_issued_for()
    {
        Assert.True(ContinuationToken.TryRedeem(ContinuationToken.Issue(42, Identity), Identity, out int offset));
        Assert.Equal(42, offset);
    }

    [Fact]
    public void A_token_issued_for_another_list_is_refused()
    {
        // The whole reason the identity travels. Accepted here, the caller would resume at a
        // position computed over a different ranking and never learn that it had.
        Assert.False(ContinuationToken.TryRedeem(ContinuationToken.Issue(3, Identity), Other, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a token")]
    [InlineData("!!!!")]
    [InlineData("dg==")]
    public void An_unreadable_token_is_refused_rather_than_treated_as_the_first_page(string token)
    {
        Assert.False(ContinuationToken.TryRedeem(token, Identity, out _));
    }

    [Fact]
    public void A_token_carrying_a_negative_position_is_refused()
    {
        string forged = Encode("v1:-1:" + Identity);

        // Indexing backwards would hand back results the caller already has, which is exactly
        // the duplication a continuation token exists to prevent.
        Assert.False(ContinuationToken.TryRedeem(forged, Identity, out _));
    }

    [Fact]
    public void A_token_from_an_unknown_encoding_is_refused()
    {
        Assert.False(ContinuationToken.TryRedeem(Encode("v2:1:" + Identity), Identity, out _));
    }

    [Fact]
    public void A_token_travels_as_url_safe_text()
    {
        // Tokens ride in JSON arguments and in whatever a client logs. Padding and the two
        // characters base64 borrows from URLs make a token that some hop will re-encode.
        for (int offset = 0; offset < 64; offset++)
        {
            string token = ContinuationToken.Issue(offset, Identity);

            Assert.DoesNotContain("+", token, StringComparison.Ordinal);
            Assert.DoesNotContain("/", token, StringComparison.Ordinal);
            Assert.DoesNotContain("=", token, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_identity_of_a_list_depends_on_all_three_of_its_parts()
    {
        string baseline = ContinuationToken.Identify("pets", "full", "fingerprint");

        Assert.NotEqual(baseline, ContinuationToken.Identify("cats", "full", "fingerprint"));
        Assert.NotEqual(baseline, ContinuationToken.Identify("pets", "read", "fingerprint"));
        Assert.NotEqual(baseline, ContinuationToken.Identify("pets", "full", "other"));
    }

    [Fact]
    public void An_absent_query_and_an_empty_query_identify_the_same_list()
    {
        // Both list everything, so a token issued under one has to work under the other.
        Assert.Equal(
            ContinuationToken.Identify(null, "full", "fingerprint"),
            ContinuationToken.Identify(string.Empty, "full", "fingerprint"));
    }

    private static string Encode(string text)
        => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(text))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
