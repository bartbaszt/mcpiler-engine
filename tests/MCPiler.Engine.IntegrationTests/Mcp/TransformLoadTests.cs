using System.IO;

using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// A Manifest carrying an invalid transformation program never reaches a listener.
/// </summary>
/// <remarks>
/// The unit tests prove the gate decides correctly. What matters here is that the decision is
/// wired to the process: the mount is refused, the refusal names which Manifest, and an
/// operator reading the startup report sees the program's own reason rather than a category.
/// A gate nothing calls is documentation.
/// </remarks>
public sealed class TransformLoadTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("mcpiler-transform-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Store()
    {
        string store = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(store);
        return store;
    }

    /// <summary>A transformed binding wrapping a stated program document.</summary>
    private static string Manifest(string program) => """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "surfaces": [
                  { "slug": "full", "isDefault": true, "operations": [ { "operation": "list-pets" } ] }
                ]
              }
            },
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
                    "binding": {
                      "type": "transformedHttp",
                      "base": { "operation": "GET /pets" },
                      "inputProgram": __PROGRAM__
                    }
                  }
                ]
              }
            }
          }
        }
        """.Replace("__PROGRAM__", program, StringComparison.Ordinal);

    /// <summary>A well-formed envelope at the format's default bounds, wrapping stated steps.</summary>
    private static string Program(string steps) => """
        {
          "transformVersion": 1,
          "direction": "input",
          "base": "passthrough",
          "limits": {
            "maxSteps": 64,
            "maxDepth": 32,
            "maxNodes": 8192,
            "maxOutputBytes": 262144,
            "maxArrayFanout": 1024
          },
          "steps": __STEPS__
        }
        """.Replace("__STEPS__", steps, StringComparison.Ordinal);

    [Fact]
    public void A_manifest_carrying_an_invalid_program_refuses_the_mount()
    {
        string path = ServedManifests.Write(
            _root,
            "bad-program",
            Manifest(Program("""[ { "op": "eval", "script": "1" } ]""")));

        RuntimeStartResult result = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", path)], Store()));

        Assert.False(result.Started);
        Assert.Empty(result.Mounts);

        StartupRefusal refusal = Assert.Single(
            result.Refusals,
            candidate => string.Equals(candidate.Code, "binding/transform-invalid", StringComparison.Ordinal));

        Assert.Equal(path, refusal.Manifest);

        // The operator surface carries the program grammar's own reason and the step. One
        // manifest code covers every way a program can be wrong, so without these the report
        // would say only that something somewhere is invalid.
        string report = StartupReport.Render(result);

        Assert.Contains(path, report, StringComparison.Ordinal);
        Assert.Contains("E_UNKNOWN_OPERATION", report, StringComparison.Ordinal);
        Assert.Contains("Step 0", report, StringComparison.Ordinal);
        Assert.NotEqual(0, StartupReport.ExitCode(result));
    }

    [Fact]
    public void A_manifest_carrying_a_valid_program_mounts()
    {
        string path = ServedManifests.Write(
            _root,
            "good-program",
            Manifest(Program(
                """[ { "op": "copy", "source": "/state", "target": "/query/status", "onMissing": "skip" } ]""")));

        RuntimeStartResult result = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", path)], Store()));

        Assert.True(result.Started);
        Assert.Empty(result.Refusals);
    }

    /// <summary>
    /// A program that would only fail once something invoked it fails at load instead.
    /// </summary>
    /// <remarks>
    /// The bounds are inside the format's defaults and the pointers are well-rooted, so nothing
    /// about reading the document refuses it. Only the static estimate does, and computing it
    /// at load is what turns an intermittent tool fault into a deployment error.
    /// </remarks>
    [Fact]
    public void A_program_whose_static_estimate_is_unservable_is_refused_at_load()
    {
        string path = ServedManifests.Write(
            _root,
            "heavy-program",
            Manifest(Program("""
                [
                  {
                    "op": "mapArray",
                    "source": "/rows",
                    "target": "/body/rows",
                    "maxItems": 64,
                    "onMissing": "skip",
                    "steps": [
                      {
                        "op": "mapArray",
                        "source": "/cells",
                        "target": "/cells",
                        "maxItems": 64,
                        "onMissing": "skip",
                        "steps": [ { "op": "copy", "source": "/raw", "target": "/value", "onMissing": "skip" } ]
                      }
                    ]
                  }
                ]
                """)));

        RuntimeStartResult result = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", path)], Store()));

        Assert.False(result.Started);
        Assert.Contains(
            result.Refusals,
            refusal => string.Equals(refusal.Code, "binding/transform-invalid", StringComparison.Ordinal));
    }
}
