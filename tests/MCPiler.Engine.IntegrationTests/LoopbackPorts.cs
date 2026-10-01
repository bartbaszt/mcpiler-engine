using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace MCPiler.Engine.IntegrationTests;

/// <summary>
/// Reserves loopback ports for the hosts a test starts through the product's own listen options.
/// </summary>
/// <remarks>
/// <para>
/// The authority has to exist before the host starts: the managed worker advertises it and the host
/// validates it against <c>AllowedHosts</c>. It therefore cannot be discovered by binding to port zero
/// and reading the assignment back afterwards, which forces a reserve-then-release step. Asking the
/// operating system for an ephemeral port made that number the most contended one on a shared runner:
/// every outbound connection the test process and its siblings make is assigned from the same dynamic
/// range, so a port reserved by one test was regularly taken by an unrelated connection before the
/// host bound it. The result was <c>IOException: Failed to bind to address ...: address already in
/// use</c> failing a test whose behavior had nothing to do with the network, and the failing test
/// differed between runs.
/// </para>
/// <para>
/// Reservations therefore come from a range below the dynamic ports of every platform this runs on
/// (Windows 49152-65535, Linux 32768-60999), scanned sequentially from a per-process offset, and a
/// port is only handed out once it has actually been bound and released successfully. A port already
/// handed out is never handed out twice in the same process. This does not make the remaining window
/// impossible - another test process whose offset overlaps can still take a port between the check
/// and the host's bind - so the scan skips a port that cannot be bound and keeps going instead of
/// returning the first answer, which is the behavior that let one unlucky host fail a whole run.
/// </para>
/// </remarks>
internal static class LoopbackPorts
{
    /// <summary>First port of the reserved range, below every dynamic range this suite runs on.</summary>
    private const int RangeStart = 20000;

    /// <summary>One past the last port of the reserved range.</summary>
    private const int RangeEnd = 40000;

    /// <summary>How many ports one process may examine before the range is reported exhausted.</summary>
    private const int Attempts = 512;

    private static readonly object Gate = new();

    private static readonly HashSet<int> HandedOut = [];

    private static int _next = WindowStart();

    /// <summary>
    /// A per-process offset, so two test processes sharing a runner start their scans far enough
    /// apart that their reservations rarely overlap. It is an offset, not a guarantee, which is why
    /// the scan tolerates a port that is already taken.
    /// </summary>
    private static int WindowStart() => RangeStart + (Environment.ProcessId % (RangeEnd - RangeStart));

    /// <summary>
    /// Reserves and returns a loopback port the caller may bind. Throws rather than returning a
    /// number it could not confirm, because a caller that received an unusable port would report the
    /// failure somewhere far from its cause.
    /// </summary>
    internal static int Reserve()
    {
        lock (Gate)
        {
            for (var attempt = 0; attempt < Attempts; attempt++)
            {
                var port = _next;
                _next = _next + 1 == RangeEnd ? RangeStart : _next + 1;

                if (!HandedOut.Add(port) || !IsBindable(port))
                {
                    continue;
                }

                return port;
            }

            throw new InvalidOperationException(
                $"No loopback port in [{RangeStart}, {RangeEnd}) could be reserved after {Attempts} attempts.");
        }
    }

    private static bool IsBindable(int port)
    {
        try
        {
            using var probe = new TcpListener(IPAddress.Loopback, port);
            probe.Start();
            probe.Stop();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}