using System;
using System.Net;
using System.Net.Http;
using System.Threading;

using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Outbound;

/// <summary>
/// Client construction from a governing policy, and reuse keyed on the policy's values.
/// </summary>
/// <remarks>
/// The configuration is asserted on the handler directly rather than inferred from an exchange.
/// An exchange can only show that a setting had no visible effect on that exchange, which is
/// exactly what a wrong setting looks like until the day it matters.
/// </remarks>
public sealed class UpstreamClientFactoryTests
{
    private static readonly OutboundLimits Tight = OutboundLimits.Default with
    {
        ConnectTimeout = TimeSpan.FromSeconds(3),
        MaxConnectionsPerServer = 2,
    };

    [Fact]
    public void The_shipped_handler_disables_automatic_redirects()
    {
        using var handler = UpstreamClientFactory.CreateSocketsHandler(Tight, new OutboundConnectionPolicy());

        // The perimeter has to be re-checked at every hop. A handler that followed redirects
        // itself would already have connected before anything could refuse the destination.
        Assert.False(handler.AllowAutoRedirect);
    }

    [Fact]
    public void The_shipped_handler_decompresses_so_the_ceiling_counts_decoded_bytes()
    {
        using var handler = UpstreamClientFactory.CreateSocketsHandler(Tight, new OutboundConnectionPolicy());

        Assert.Equal(DecompressionMethods.GZip | DecompressionMethods.Deflate, handler.AutomaticDecompression);
    }

    [Fact]
    public void The_shipped_handler_takes_its_connect_timeout_and_connection_ceiling_from_the_policy()
    {
        using var handler = UpstreamClientFactory.CreateSocketsHandler(Tight, new OutboundConnectionPolicy());

        Assert.Equal(TimeSpan.FromSeconds(3), handler.ConnectTimeout);
        Assert.Equal(2, handler.MaxConnectionsPerServer);
    }

    [Fact]
    public void The_shipped_handler_opens_its_sockets_through_the_outbound_policy()
    {
        using var handler = UpstreamClientFactory.CreateSocketsHandler(Tight, new OutboundConnectionPolicy());

        // Without this the handler resolves and connects on its own, and address containment
        // has no place to happen at all.
        Assert.NotNull(handler.ConnectCallback);
    }

    [Fact]
    public void A_client_carries_no_deadline_of_its_own()
    {
        using var factory = new UpstreamClientFactory(_ => new StubHandler());

        var client = factory.Client(Tight);

        // The exchange budget is the caller's token. A client timeout would be a second
        // mechanism for one cause, and one cause with two mechanisms produces two
        // classifications for the same fault.
        Assert.Equal(Timeout.InfiniteTimeSpan, client.Timeout);
    }

    [Fact]
    public void A_client_announces_the_engine_user_agent()
    {
        using var factory = new UpstreamClientFactory(_ => new StubHandler());

        var client = factory.Client(Tight);

        Assert.Equal(UpstreamClientFactory.UserAgent, client.DefaultRequestHeaders.UserAgent.ToString());
    }

    [Fact]
    public void The_same_policy_value_is_served_by_one_client()
    {
        using var factory = new UpstreamClientFactory(_ => new StubHandler());

        // A distinct but equal value, not the same instance: the key is what the policy says,
        // not which object said it.
        var first = factory.Client(OutboundLimits.Default with { MaxConnectionsPerServer = 4 });
        var second = factory.Client(OutboundLimits.Default with { MaxConnectionsPerServer = 4 });

        Assert.Same(first, second);
        Assert.Equal(1, factory.CachedClientCount);
    }

    [Fact]
    public void A_changed_policy_value_is_a_different_client()
    {
        using var factory = new UpstreamClientFactory(_ => new StubHandler());

        var original = factory.Client(OutboundLimits.Default);
        var narrowed = factory.Client(OutboundLimits.Default with { ConnectTimeout = TimeSpan.FromSeconds(1) });

        // Keyed on a name instead, a limit edit would take effect on the next restart rather
        // than on the next execution.
        Assert.NotSame(original, narrowed);
        Assert.Equal(2, factory.CachedClientCount);
    }

    [Fact]
    public void A_superseded_client_is_released()
    {
        using var factory = new UpstreamClientFactory(_ => new StubHandler());

        var superseded = factory.Client(OutboundLimits.Default);
        var current = OutboundLimits.Default with { MaxConnectionsPerServer = 16 };
        factory.Client(current);

        var released = factory.ReleaseOtherThan(current);

        Assert.Equal(1, released);
        Assert.Equal(1, factory.CachedClientCount);

        // Released rather than merely forgotten: a client left alive holds open connections
        // configured by values the operator has already changed.
        Assert.Throws<ObjectDisposedException>(() => superseded.Timeout = TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void A_disposed_factory_refuses_to_hand_out_a_client()
    {
        var factory = new UpstreamClientFactory(_ => new StubHandler());
        factory.Client(OutboundLimits.Default);
        factory.Dispose();

        Assert.Throws<ObjectDisposedException>(() => factory.Client(OutboundLimits.Default));
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}
