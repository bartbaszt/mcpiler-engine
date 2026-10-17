using System.Diagnostics;
using System.Text;
using System.Threading.Channels;
using MCPiler.Engine.Host.Cli;

namespace MCPiler.Engine.IntegrationTests.Cli;

/// <summary>
/// Executes the actual Engine entry point in a distinct operating-system process. Every child
/// is bounded and reaped, including on assertion failure or cancellation. Credentials and
/// OAuth callback material must never be passed as arguments to this helper.
/// </summary>
internal sealed class EngineCliProcess : IAsyncDisposable
{
    private static readonly TimeSpan ExitBudget = TimeSpan.FromSeconds(20);
    private const int MaximumCapturedCharacters = 64 * 1024;
    private readonly Process _process;
    private readonly object _outputGate = new();
    private readonly StringBuilder _stdout = new();
    private readonly StringBuilder _stderr = new();
    private readonly Channel<string> _stderrLines = Channel.CreateBounded<string>(new BoundedChannelOptions(256)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = false,
        SingleWriter = true,
    });
    private readonly Task _stdoutPump;
    private readonly Task _stderrPump;

    private EngineCliProcess(Process process)
    {
        _process = process;
        // Drain both streams for the entire process lifetime, including while waiting for a marker.
        // Marker consumption must never hide already-emitted diagnostics from later assertions.
        _stdoutPump = PumpAsync(process.StandardOutput, _stdout);
        _stderrPump = PumpAsync(process.StandardError, _stderr, _stderrLines.Writer);
    }

    internal bool HasExited => _process.HasExited;

    internal async Task<string> WaitForStderrLineAsync(string marker, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(ExitBudget);
        await foreach (string line in _stderrLines.Reader.ReadAllAsync(deadline.Token))
        {
            if (line.Contains(marker, StringComparison.Ordinal))
            {
                return line;
            }
        }

        throw new InvalidOperationException("Engine process exited before emitting its startup marker.");
    }

    internal static EngineCliProcess Start(params string[] args)
    {
        string entryPoint = typeof(HostCommands).Assembly.Location;
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        start.ArgumentList.Add(entryPoint);
        foreach (string arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        return new EngineCliProcess(Process.Start(start)
            ?? throw new InvalidOperationException("The Engine child process did not start."));
    }

    internal async Task<EngineCliOutcome> CompleteAsync(CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(ExitBudget);

        try
        {
            await _process.WaitForExitAsync(deadline.Token);
            await Task.WhenAll(_stdoutPump, _stderrPump).WaitAsync(deadline.Token);
            lock (_outputGate)
            {
                return new EngineCliOutcome(_process.ExitCode, _stdout.ToString(), _stderr.ToString());
            }
        }
        catch
        {
            Kill();
            throw;
        }
    }

    internal static async Task<EngineCliOutcome> RunAsync(CancellationToken cancellationToken, params string[] args)
    {
        await using var child = Start(args);
        return await child.CompleteAsync(cancellationToken);
    }

    /// <summary>Force an abrupt owner crash for later lease-recovery integration tests.</summary>
    internal async Task KillAndReapAsync(CancellationToken cancellationToken)
    {
        Kill();
        await _process.WaitForExitAsync(cancellationToken);
        await Task.WhenAll(_stdoutPump, _stderrPump).WaitAsync(cancellationToken);
    }

    private async Task PumpAsync(StreamReader stream, StringBuilder capture, ChannelWriter<string>? lines = null)
    {
        try
        {
            // The pump belongs to the child process, not to an individual xUnit assertion.
            // Killing/reaping the process closes the stream and ends this read naturally.
            while (await stream.ReadLineAsync(CancellationToken.None) is { } line)
            {
                lock (_outputGate)
                {
                    int remaining = MaximumCapturedCharacters - capture.Length;
                    if (remaining > 0)
                    {
                        capture.Append(line.AsSpan(0, Math.Min(remaining, line.Length)));
                        if (capture.Length < MaximumCapturedCharacters)
                        {
                            capture.AppendLine();
                        }
                    }
                }

                lines?.TryWrite(line);
            }
        }
        finally
        {
            lines?.TryComplete();
        }
    }

    private void Kill()
    {
        if (!_process.HasExited)
        {
            try
            {
                _process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // The child exited between the state check and Kill.
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        Kill();
        try
        {
            using var deadline = new CancellationTokenSource(ExitBudget);
            await _process.WaitForExitAsync(deadline.Token);
            await Task.WhenAll(_stdoutPump, _stderrPump).WaitAsync(deadline.Token);
        }
        finally
        {
            _process.Dispose();
        }
    }
}

internal sealed record EngineCliOutcome(int ExitCode, string Stdout, string Stderr);
