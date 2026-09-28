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
}
