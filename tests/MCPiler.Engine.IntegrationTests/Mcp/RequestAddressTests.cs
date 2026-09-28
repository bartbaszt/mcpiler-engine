using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Mcp;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

public sealed class RequestAddressTests
{
    [Fact]
    public void Percent_encoded_request_target_is_preserved_for_authorization_but_not_resolution()
    {
        DefaultHttpContext context = new();
        context.Request.Path = "/api/full";
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = "/api/%66ull?trace=1";

        SurfaceEndpoint route = new(address: null);

        Assert.Equal("/api/full", RequestAddress.Resolve(context, route));
        Assert.Equal("/api/%66ull", route.ResolveAuthorizationResourcePath(context));
    }

    [Fact]
    public void Absolute_form_raw_target_preserves_the_escaped_path()
    {
        DefaultHttpContext context = new();
        context.Request.Path = "/api/full/";
        context.Features.Get<IHttpRequestFeature>()!.RawTarget =
            "https://mcp.example.com/api/%66ull/?trace=1";

        SurfaceEndpoint route = new(address: null);

        Assert.Equal("/api/full", RequestAddress.Resolve(context, route));
        Assert.Equal("/api/%66ull/", route.ResolveAuthorizationResourcePath(context));
    }

    [Fact]
    public void Transfer_suffix_must_be_literal_in_the_raw_request_target()
    {
        DefaultHttpContext context = new();
        context.Request.Path = "/api/full/files/upload";
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = "/api/full/%66iles/upload";

        Assert.False(RequestAddress.TryResolveCanonicalTransfer(context, out _, out _));
    }

    [Fact]
    public void Transfer_parent_may_preserve_percent_encoding_when_suffix_is_literal()
    {
        DefaultHttpContext context = new();
        context.Request.Path = "/api/full/files/upload";
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = "/api/%66ull/files/upload";

        Assert.True(RequestAddress.TryResolveCanonicalTransfer(
            context,
            out var decoded,
            out var raw));
        Assert.Equal("/api/full", decoded.ParentAddress);
        Assert.Equal("/api/%66ull", raw.ParentAddress);
    }

    [Fact]
    public void Protected_resource_metadata_publishes_the_raw_percent_encoded_resource()
    {
        DefaultHttpContext context = new();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("mcp.example.com");
        context.Request.Path = "/.well-known/oauth-protected-resource/api/full";
        context.Features.Get<IHttpRequestFeature>()!.RawTarget =
            "/.well-known/oauth-protected-resource/api/%66ull";

        var metadata = SurfaceMetadata.Build(
            context,
            new HostAuthorizationOptions("https://issuer.example", HostTokenValidation.Jwks));

        Assert.Equal("https://mcp.example.com/api/%66ull", metadata.Resource);
    }

    [Theory]
    [InlineData("/.well-known/oauth-protected-resourc%65/api/full")]
    [InlineData("/.WELL-KNOWN/oauth-protected-resource/api/full")]
    public void Protected_resource_metadata_refuses_noncanonical_protocol_prefix(string rawTarget)
    {
        DefaultHttpContext context = new();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("mcp.example.com");
        context.Request.Path = "/.well-known/oauth-protected-resource/api/full";
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = rawTarget;

        Assert.Throws<InvalidOperationException>(() => SurfaceMetadata.Build(
            context,
            new HostAuthorizationOptions("https://issuer.example", HostTokenValidation.Jwks)));
    }
}
