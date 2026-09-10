using System;
using System.Collections.Generic;
using System.IO;

using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Configuration;

/// <summary>
/// What an operator sees when the process will not start.
/// </summary>
public sealed class StartupReportTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-report-" + Guid.NewGuid().ToString("N"));

    public StartupReportTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    /// <summary>
    /// A configuration refusal exits distinctly from a crash.
    /// </summary>
    /// <remarks>
    /// An orchestrator that cannot tell the two apart restarts a misconfigured process
    /// forever, and the restart loop looks like instability rather than like a setting
    /// nobody fixed.
    /// </remarks>
    [Fact]
    public void A_refusal_exits_with_the_configuration_code_and_not_the_failure_code()
    {
        RuntimeStartResult refused = EngineRuntime.Start(new RuntimeOptions([], _root));

        Assert.False(refused.Started);
        Assert.Equal(ExitCodes.Configuration, StartupReport.ExitCode(refused));
        Assert.NotEqual(ExitCodes.Failure, StartupReport.ExitCode(refused));
        Assert.NotEqual(ExitCodes.Success, StartupReport.ExitCode(refused));
    }

    /// <summary>
    /// Every refusal is printed, not only the first.
    /// </summary>
    /// <remarks>
    /// Reporting one at a time makes an operator learn their configuration one deployment per
    /// mistake. Two bad mounts here would otherwise cost two restarts to discover.
    /// </remarks>
    [Fact]
    public void Every_refusal_appears_in_the_report()
    {
        MountRequest first = new("/one", Path.Combine(_root, "absent-one"));
        MountRequest second = new("/two", Path.Combine(_root, "absent-two"));

        RuntimeStartResult refused = EngineRuntime.Start(new RuntimeOptions([first, second], _root));

        Assert.False(refused.Started);
        Assert.True(refused.Refusals.Count >= 2, $"Expected a refusal per mount, saw {refused.Refusals.Count}.");

        string report = StartupReport.Render(refused);

        foreach (StartupRefusal refusal in refused.Refusals)
        {
            Assert.Contains(refusal.Code, report, StringComparison.Ordinal);
        }

        Assert.Contains("/one", report, StringComparison.Ordinal);
        Assert.Contains("/two", report, StringComparison.Ordinal);
        Assert.Contains("will not start", report, StringComparison.Ordinal);
    }

    [Fact]
    public void A_report_of_a_started_process_names_every_mount_and_exits_zero()
    {
        string manifest = Path.Combine(_root, "api");
        Directory.CreateDirectory(manifest);
        File.WriteAllText(Path.Combine(manifest, "manifest.json"), Minimal);

        string store = Path.Combine(_root, "files");
        Directory.CreateDirectory(store);

        RuntimeStartResult started = EngineRuntime.Start(new RuntimeOptions([new MountRequest("/api", manifest)], store));

        Assert.True(started.Started, StartupReport.Render(started));
        Assert.Equal(ExitCodes.Success, StartupReport.ExitCode(started));

        string report = StartupReport.Render(started);
        Assert.Contains("mounted /api", report, StringComparison.Ordinal);
        Assert.Contains("Example API", report, StringComparison.Ordinal);
    }

    private const string Minimal = """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": { "inline": { "name": "Example API" } },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": {
                "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "list-pets",
                    "name": "List pets",
                    "binding": { "type": "http", "operation": "GET /pets" }
                  }
                ]
              }
            }
          }
        }
        """;
}
