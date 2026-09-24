using MCPiler.Engine.Execution;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

public sealed class UpstreamUriRedactorTests
{
    [Fact]
    public void Redaction_preserves_ordinary_query_structure_and_masks_encoded_sensitive_names()
    {
        const string firstCanary = "CANARY-oauth-token-one";
        const string secondCanary = "CANARY-oauth-token-two";
        var uri = new Uri(
            $"https://api.example.test/thing?search=blue%20sky&oauth_token={firstCanary}&%6Fauth_signature={secondCanary}&oauth_token={secondCanary}",
            UriKind.Absolute);

        Uri redacted = UpstreamUriRedactor.Redact(
            uri,
            ["oauth_token", "oauth_signature"]);

        Assert.Contains("search=blue%20sky", redacted.Query, StringComparison.Ordinal);
        Assert.Equal(3, redacted.Query.Split("%5BREDACTED%5D", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain(firstCanary, redacted.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(secondCanary, redacted.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Redaction_without_sensitive_names_returns_the_same_uri()
    {
        var uri = new Uri("https://api.example.test/thing?search=normal", UriKind.Absolute);

        Assert.Same(uri, UpstreamUriRedactor.Redact(uri, []));
    }
}
