using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace MCPiler.Engine.IntegrationTests;

/// <summary>
/// Proves the test instrument before anything is asserted through it.
/// </summary>
/// <remarks>
/// A loopback host that silently fails to start, or that keeps listening after disposal, would
/// make every later test in this suite report something other than what it claims to measure.
/// These tests exist so that failure is attributed here rather than to the code under test.
/// </remarks>
public sealed class LoopbackHostTests
{
    [Fact]
    public async Task The_host_answers_on_its_bound_address()
    {
        var token = TestContext.Current.CancellationToken;
        var body = Encoding.UTF8.GetBytes("""{"ok":true}""");
        await using var host = await LoopbackHost.StartAsync(200, "application/json", body, token);

        using var client = new HttpClient();
        using var response = await client.GetAsync(host.Address, token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(body, await response.Content.ReadAsByteArrayAsync(token));
    }

    [Fact]
    public async Task The_bound_address_is_loopback_on_an_ephemeral_port()
    {
        var token = TestContext.Current.CancellationToken;
        await using var host = await LoopbackHost.StartAsync(204, "text/plain", [], token);

        Assert.Equal("127.0.0.1", host.Address.Host);
        Assert.NotEqual(0, host.Address.Port);
        Assert.Equal(Uri.UriSchemeHttp, host.Address.Scheme);
    }

    [Fact]
    public async Task The_localhost_address_reaches_the_same_listener()
    {
        // The two addresses are the same endpoint named two ways, and several later tests depend
        // on that being true: an origin comparison sees a hostname while an address policy sees a
        // literal. If this ever fails, the assumption under those tests has failed, not this one.
        var token = TestContext.Current.CancellationToken;
        var body = Encoding.UTF8.GetBytes("reached");
        await using var host = await LoopbackHost.StartAsync(200, "text/plain", body, token);

        Assert.Equal(host.Address.Port, host.LocalhostAddress.Port);
        Assert.Equal("localhost", host.LocalhostAddress.Host);

        using var client = new HttpClient();
        using var response = await client.GetAsync(host.LocalhostAddress, token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("reached", await response.Content.ReadAsStringAsync(token));
    }

    [Fact]
    public async Task The_handler_observes_the_request_it_was_sent()
    {
        var token = TestContext.Current.CancellationToken;
        string? observedPath = null;
        string? observedHeader = null;

        await using var host = await LoopbackHost.StartAsync(
            context =>
            {
                observedPath = context.Request.Path + context.Request.QueryString;
                observedHeader = context.Request.Headers["X-Probe"];
                context.Response.StatusCode = 200;
                return Task.CompletedTask;
            },
            token);

        using var client = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(host.Address, "/items?page=2"));
        request.Headers.Add("X-Probe", "yes");
        using var response = await client.SendAsync(request, token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/items?page=2", observedPath);
        Assert.Equal("yes", observedHeader);
    }

    [Fact]
    public async Task A_disposed_host_stops_answering()
    {
        var token = TestContext.Current.CancellationToken;
        var host = await LoopbackHost.StartAsync(200, "text/plain", Encoding.UTF8.GetBytes("up"), token);
        var address = host.Address;
        await host.DisposeAsync();

        using var client = new HttpClient();
        var failure = await Record.ExceptionAsync(() => client.GetAsync(address, token));

        // A host that kept listening after disposal would serve the previous test's handler to
        // whichever test happened to receive the recycled port.
        Assert.IsType<HttpRequestException>(failure);
    }
}
