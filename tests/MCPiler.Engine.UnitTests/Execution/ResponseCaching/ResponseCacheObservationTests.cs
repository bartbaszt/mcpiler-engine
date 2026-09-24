using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.ResponseCaching;

/// <summary>
/// The recent-decision buffer holds two independent bounds and counts only what it retains.
/// </summary>
/// <remarks>
/// The counts a snapshot reports are derived from the retained decisions rather than kept as
/// separate counters, so this class also proves they cannot outlive the window they describe.
/// That is the difference between a bounded inspection surface and an unbounded event log with
/// a display limit bolted on.
/// </remarks>
public sealed class ResponseCacheObservationTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 23, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void At_most_one_thousand_decisions_are_retained()
    {
        ResponseCacheObservationBuffer buffer = new();
        FakeTimeProvider clock = new(Start);

        for (int index = 0; index < 1500; index++)
        {
            clock.Set(Start.AddSeconds(index));
            buffer.Record(Decision(clock, ResponseCacheDecisionKind.Miss, ResponseCacheExecution.Upstream));
        }

        ResponseCacheObservation observation = buffer.Snapshot("/api", clock);

        Assert.Equal(ResponseCacheObservationBuffer.MaxDecisions, observation.Recent.Count);

        // The oldest five hundred were discarded, so the first retained decision is number 500
        // and the newest is number 1499. A ring that trimmed the newest instead would satisfy a
        // count assertion and destroy exactly the evidence an operator is looking for.
        Assert.Equal(Start.AddSeconds(500), observation.Recent[0].ObservedAtUtc);
        Assert.Equal(Start.AddSeconds(1499), observation.Recent[^1].ObservedAtUtc);
    }

    [Fact]
    public void A_decision_older_than_one_hour_is_discarded()
    {
        ResponseCacheObservationBuffer buffer = new();
        FakeTimeProvider clock = new(Start);

        buffer.Record(Decision(clock, ResponseCacheDecisionKind.Hit, ResponseCacheExecution.Cached));

        clock.Advance(TimeSpan.FromMinutes(59));
        buffer.Record(Decision(clock, ResponseCacheDecisionKind.Miss, ResponseCacheExecution.Upstream));

        Assert.Equal(2, buffer.Snapshot("/api", clock).Recent.Count);

        // One second past the window the first decision ages out on read, without any sweep and
        // without another record to trigger trimming.
        clock.Advance(TimeSpan.FromMinutes(1).Add(TimeSpan.FromSeconds(1)));
        ResponseCacheObservation aged = buffer.Snapshot("/api", clock);

        Assert.Single(aged.Recent);
        Assert.Equal(ResponseCacheDecisionKind.Miss, aged.Recent[0].Kind);
    }

    [Fact]
    public void A_hit_or_joined_waiter_is_not_counted_as_an_upstream_send()
    {
        ResponseCacheObservationBuffer buffer = new();
        FakeTimeProvider clock = new(Start);

        buffer.Record(Decision(clock, ResponseCacheDecisionKind.Miss, ResponseCacheExecution.Upstream) with
        {
            FlightRole = ResponseCacheFlightRole.Producer,
        });
        buffer.Record(Decision(clock, ResponseCacheDecisionKind.Miss, ResponseCacheExecution.Cached) with
        {
            FlightRole = ResponseCacheFlightRole.Joined,
        });
        buffer.Record(Decision(clock, ResponseCacheDecisionKind.Hit, ResponseCacheExecution.Cached));
        buffer.Record(Decision(clock, ResponseCacheDecisionKind.Bypass, ResponseCacheExecution.Upstream, disabled: true));

        ResponseCacheObservation observation = buffer.Snapshot("/api", clock);

        Assert.Equal(4, observation.Recent.Count);

        // Three invocations consulted the cache; the bypass did not. Only the single producer
        // reached the upstream, so two of the four invocations consumed a shared or stored
        // response without a second call.
        Assert.Equal(3, observation.Invocations);
        Assert.Equal(2, observation.UpstreamSends);
    }

    [Fact]
    public void The_counts_describe_only_the_retained_window()
    {
        ResponseCacheObservationBuffer buffer = new();
        FakeTimeProvider clock = new(Start);

        for (int index = 0; index < 300; index++)
        {
            buffer.Record(Decision(clock, ResponseCacheDecisionKind.Miss, ResponseCacheExecution.Upstream));
        }

        clock.Advance(TimeSpan.FromHours(2));
        buffer.Record(Decision(clock, ResponseCacheDecisionKind.Hit, ResponseCacheExecution.Cached));

        ResponseCacheObservation observation = buffer.Snapshot("/api", clock);

        // Every decision from two hours ago aged out with its count. A retained counter would
        // here report three hundred upstream sends for a window that holds one hit.
        Assert.Single(observation.Recent);
        Assert.Equal(1, observation.Invocations);
        Assert.Equal(0, observation.UpstreamSends);
    }

    private static ResponseCacheDecision Decision(
        FakeTimeProvider clock,
        ResponseCacheDecisionKind kind,
        ResponseCacheExecution execution,
        bool disabled = false)
        => new(
            clock.GetUtcNow(),
            "list-pets",
            kind,
            execution,
            disabled ? ResponseCacheDecisionReason.Disabled : ResponseCacheDecisionReason.LiveSend,
            "0123456789ab",
            300,
            null,
            null,
            ResponseCacheFlightRole.None,
            null,
            false);

    /// <summary>An injectable clock the buffer is measured against.</summary>
    private sealed class FakeTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        internal void Advance(TimeSpan by) => _now += by;

        internal void Set(DateTimeOffset at) => _now = at;
    }
}
