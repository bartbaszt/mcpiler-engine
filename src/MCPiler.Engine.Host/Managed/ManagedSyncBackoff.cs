namespace MCPiler.Engine.Host.Managed;

/// <summary>
/// The bounded exponential backoff a managed worker uses between failed polls.
/// </summary>
/// <remarks>
/// <para>
/// Backoff is the difference between a Platform that is briefly unreachable and a Platform that
/// is down: a fixed retry interval turns an outage into a request flood that keeps the outage
/// going, while an unbounded one leaves a recovered Platform unread for as long as the last
/// failure implied.
/// </para>
/// <para>
/// Jitter exists because every Engine of one deployment backs off on the same schedule. Without
/// it, a Platform restart is followed by synchronized retries from every process, which is the
/// load the backoff was supposed to avoid.
/// </para>
/// </remarks>
internal sealed class ManagedSyncBackoff
{
    private readonly TimeSpan _initial;
    private readonly TimeSpan _maximum;
    private readonly double _factor;
    private readonly Func<double> _jitter;
    private TimeSpan _current;

    /// <summary>Creates a backoff sequence.</summary>
    /// <param name="initial">The first delay; also the reset value.</param>
    /// <param name="maximum">The delay the sequence never exceeds.</param>
    /// <param name="factor">How much each failure multiplies the delay.</param>
    /// <param name="jitter">
    /// Supplies a value in <c>[0, 1)</c> used to spread retries; defaults to a shared generator.
    /// </param>
    public ManagedSyncBackoff(
        TimeSpan initial,
        TimeSpan maximum,
        double factor = 2.0,
        Func<double>? jitter = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(initial, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximum, initial);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(factor, 1.0);

        _initial = initial;
        _maximum = maximum;
        _factor = factor;
        _jitter = jitter ?? Random.Shared.NextDouble;
        _current = initial;
    }

    /// <summary>The delay the next retry would use, without advancing the sequence.</summary>
    public TimeSpan Peek() => _current;

    /// <summary>Returns the next delay and advances the sequence toward the maximum.</summary>
    public TimeSpan Next()
    {
        TimeSpan delay = _current;

        double scaled = _current.TotalMilliseconds * _factor;
        _current = scaled >= _maximum.TotalMilliseconds
            ? _maximum
            : TimeSpan.FromMilliseconds(scaled);

        // Jitter is applied to the returned delay, not to the stored one, so the sequence still
        // reaches the maximum in a bounded number of failures rather than depending on a draw.
        double fraction = Math.Clamp(_jitter(), 0.0, 1.0);

        return delay * (0.5 + (fraction / 2.0));
    }

    /// <summary>Returns to the initial delay after a successful exchange.</summary>
    public void Reset() => _current = _initial;
}
