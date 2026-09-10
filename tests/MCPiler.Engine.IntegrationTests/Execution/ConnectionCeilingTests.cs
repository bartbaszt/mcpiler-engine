using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using Microsoft.AspNetCore.Http;
using MCPiler.Engine.Execution.Outbound;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// The connection ceiling bounds concurrent connections, not merely a handler property.
/// </summary>
/// <remarks>
/// <para>
/// Both implementations assert that the configured ceiling reaches
/// <c>SocketsHttpHandler.MaxConnectionsPerServer</c>, and the shared client-policy corpus asserts they
/// configure it identically. Neither shows that the number does anything. A property assertion cannot
/// distinguish a ceiling that is enforced from one that is set on a handler nothing sends through - and
/// that is exactly the shape of defect a configuration test is supposed to catch.
/// </para>
/// <para>
/// This test therefore saturates it: it issues more concurrent requests than the ceiling against a host
/// that counts how many are in flight at once, and asserts the observed maximum never exceeds the
/// configured value while every request still completes. The ceiling belongs to the transport stack, so
/// proving it on one side is enough; the corpus carries the claim that the other side configures the
/// same number.
/// </para>
/// <para>
/// Loopback is a denied range for the shipped outbound policy, so the address judgement is substituted.
/// The connection pooling under test is the real one: the same handler, the same connect callback, real
/// sockets.
/// </para>
/// </remarks>
public sealed class ConnectionCeilingTests
{
    private const int Ceiling = 2;
    private const int Requests = 8;

    private static readonly TimeSpan Occupancy = TimeSpan.FromMilliseconds(150);

    [Fact]
    public async Task Concurrent_requests_never_exceed_the_configured_connection_ceiling()
    {
        var inFlight = 0;
        var observedPeak = 0;

        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                var current = Interlocked.Increment(ref inFlight);

                // A plain compare-and-swap loop rather than a lock: the peak is the only thing this
                // records, and a lock here would serialize the very concurrency being measured.
                int seen;
                do
                {
                    seen = Volatile.Read(ref observedPeak);
                }
                while (current > seen
                    && Interlocked.CompareExchange(ref observedPeak, current, seen) != seen);

                try
                {
                    // Held open long enough that a connection cannot be returned to the pool and
                    // reused before its siblings have had the chance to ask for one.
                    await Task.Delay(Occupancy, context.RequestAborted).ConfigureAwait(false);
                    await context.Response.WriteAsync("ok", context.RequestAborted).ConfigureAwait(false);
                }
                finally
                {
                    Interlocked.Decrement(ref inFlight);
                }
            },
            TestContext.Current.CancellationToken).ConfigureAwait(true);

        using var factory = new UpstreamClientFactory(new OutboundConnectionPolicy(_ => false));

        var client = factory.Client(new OutboundLimits(
            ConnectTimeout: TimeSpan.FromSeconds(5),
            MaxConnectionsPerServer: Ceiling,
            RedirectHopLimit: 0));

        var target = new Uri(host.Address, "/hold");

        var responses = await Task.WhenAll(
            Enumerable.Range(0, Requests).Select(async _ =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, target);
                using var response = await client
                    .SendAsync(request, HttpCompletionOption.ResponseContentRead, TestContext.Current.CancellationToken)
                    .ConfigureAwait(false);

                return (int)response.StatusCode;
            })).ConfigureAwait(true);

        // Every request completed, so the ceiling queued them rather than refusing them.
        Assert.Equal(Requests, responses.Length);
        Assert.All(responses, status => Assert.Equal(200, status));

        // The point of the test. A ceiling that reached no socket would show a peak of Requests.
        Assert.True(
            observedPeak <= Ceiling,
            $"The upstream saw {observedPeak} simultaneous requests under a ceiling of {Ceiling}, so the "
                + "configured connection limit is not bounding concurrent connections.");

        // A peak of one would mean the requests never overlapped at all and the assertion above passed
        // for the wrong reason - a serialized run satisfies any ceiling.
        Assert.True(
            observedPeak > 1,
            "The upstream never saw two requests at once, so this run proves nothing about a ceiling. "
                + "Either the occupancy window is too short or the requests did not overlap.");
    }
}
