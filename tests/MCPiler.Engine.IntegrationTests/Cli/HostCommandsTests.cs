using System;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Cli;

/// <summary>
/// The operator surface end to end: what each verb reports and what it exits with.
/// </summary>
public sealed class HostCommandsTests : IDisposable
{
    private const string Identity = "mcpiler-engine test (manifest format 0.2)";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-cli-" + Guid.NewGuid().ToString("N"));

    public HostCommandsTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task Version_states_the_build_and_the_format_range()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(["version"], Identity, TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains(Identity, outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// A mistyped verb and a wrong deployment exit differently.
    /// </summary>
    /// <remarks>
    /// One code for both would leave an automated caller unable to tell "you asked for
    /// something that does not exist" from "what you asked for is real and your Manifest is
    /// wrong". The first is a script bug; the second must not be retried.
    /// </remarks>
    [Fact]
    public async Task An_unknown_verb_a_refused_configuration_and_a_success_exit_differently()
    {
        CommandOutcome unknown = await HostCommands.RunAsync(["deploy"], Identity, TestContext.Current.CancellationToken);
        CommandOutcome refused = await HostCommands.RunAsync(["serve"], Identity, TestContext.Current.CancellationToken);
        CommandOutcome ok = await HostCommands.RunAsync(["version"], Identity, TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Usage, unknown.ExitCode);
        Assert.Equal(ExitCodes.Configuration, refused.ExitCode);
        Assert.Equal(ExitCodes.Success, ok.ExitCode);

        Assert.Equal(3, new[] { unknown.ExitCode, refused.ExitCode, ok.ExitCode }.Distinct().Count());
    }

    [Fact]
    public async Task Serve_with_a_file_store_but_no_manifest_mount_is_refused_by_name()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["serve", "--file-store-root", Store()],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("--mount", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("Manifest", outcome.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Default_serve_with_no_options_names_the_missing_manifest_mount()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["serve"],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("--mount", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("Manifest", outcome.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unknown_verb_prints_what_the_host_can_do()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(["deploy"], Identity, TestContext.Current.CancellationToken);

        Assert.Contains("'deploy'", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("inspect", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("files sweep", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// The preview is the thing that would be served, not a second derivation of it.
    /// </summary>
    /// <remarks>
    /// A preview computed on its own path can agree today and drift tomorrow, and the drift
    /// is invisible precisely because the preview is what an operator trusts. Asserting the
    /// fingerprint the runtime derived appears verbatim in the preview binds the two.
    /// </remarks>
    [Fact]
    public async Task Inspect_reports_the_surface_the_runtime_derived()
    {
        string manifest = Manifest("api");
        string store = Store();

        RuntimeStartResult started = EngineRuntime.Start(new RuntimeOptions([new MountRequest("/api", manifest)], store));
        Assert.True(started.Started);

        MountedSurface surface = Assert.Single(Assert.Single(started.Mounts).Surfaces);

        CommandOutcome outcome = await HostCommands.RunAsync(
            ["inspect", "--mount", "/api=" + manifest, "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("fingerprint=" + surface.Fingerprint, outcome.Output, StringComparison.Ordinal);

        foreach (string tool in surface.ToolNames)
        {
            Assert.Contains("tool " + tool, outcome.Output, StringComparison.Ordinal);
        }

        Assert.NotEmpty(surface.ToolNames);
    }

    [Fact]
    public async Task Inspect_reports_the_operator_channel_presence_without_the_secret()
    {
        string store = Store();
        string secret = Path.Combine(_root, "operator-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(secret, "operator-secret-canary-value\n");

        CommandOutcome absent = await HostCommands.RunAsync(
            ["inspect", "--mount", "/api=" + Manifest("api"), "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        // Absent configuration is the safe default, and the report says so.
        Assert.Contains("response-cache operator channel: absent", absent.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("operator-secret-canary-value", absent.Output, StringComparison.Ordinal);

        CommandOutcome present = await HostCommands.RunAsync(
            [
                "inspect",
                "--mount", "/api=" + Manifest("api"),
                "--file-store-root", store,
                "--" + HostConfiguration.ResponseCacheOperatorSecretFileKey, secret,
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Contains("response-cache operator channel: configured", present.Output, StringComparison.Ordinal);

        // Configured is stated as presence only; the secret never appears in the report.
        Assert.DoesNotContain("operator-secret-canary-value", present.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_opens_no_listener_and_says_so()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["inspect", "--mount", "/api=" + Manifest("api"), "--file-store-root", Store()],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Contains("opened no listener", outcome.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_and_serve_agree_on_the_refusal_when_a_manifest_will_not_load()
    {
        string absent = Path.Combine(_root, "missing");
        string store = Store();

        CommandOutcome inspect = await HostCommands.RunAsync(
            ["inspect", "--mount", "/api=" + absent, "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        CommandOutcome serve = await HostCommands.RunAsync(
            ["serve", "--mount", "/api=" + absent, "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, inspect.ExitCode);
        Assert.Equal(serve.ExitCode, inspect.ExitCode);
        Assert.Equal(serve.Output, inspect.Output);
    }

    [Fact]
    public async Task Files_list_reports_metadata_and_never_content()
    {
        string store = Store();
        FileHandleReference issued = await IssueAsync(store, "the-canary-payload");

        CommandOutcome outcome = await HostCommands.RunAsync(
            ["files", "list", "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains(issued.Id, outcome.Output, StringComparison.Ordinal);
        Assert.Contains("sha256=" + issued.ContentHash, outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("the-canary-payload", outcome.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Files_show_reports_an_unknown_handle_as_unknown()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["files", "show", new string('a', 64), "--file-store-root", Store()],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
        Assert.Contains("No handle", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// An expired handle is reported as expired, not as absent.
    /// </summary>
    /// <remarks>
    /// The two call for different responses. Expiry is the store working as configured;
    /// absence means the operator is holding an identifier the store never issued. Collapsing
    /// them would send someone hunting a data-loss bug that is a lifetime setting.
    /// </remarks>
    [Fact]
    public async Task Files_show_reports_expiry_rather_than_absence()
    {
        string store = Store();
        FileHandleReference issued = await IssueAsync(store, "payload", TimeSpan.FromMilliseconds(1));

        await Task.Delay(30, TestContext.Current.CancellationToken);

        CommandOutcome outcome = await HostCommands.RunAsync(
            ["files", "show", issued.Id, "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("state=expired", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("No handle", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// What the sweep says it reclaimed is what the next listing no longer shows.
    /// </summary>
    [Fact]
    public async Task Files_sweep_reports_exactly_what_a_later_list_no_longer_shows()
    {
        string store = Store();
        FileHandleReference expiring = await IssueAsync(store, "short", TimeSpan.FromMilliseconds(1));
        FileHandleReference surviving = await IssueAsync(store, "long", TimeSpan.FromHours(1));

        await Task.Delay(30, TestContext.Current.CancellationToken);

        CommandOutcome swept = await HostCommands.RunAsync(
            ["files", "sweep", "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, swept.ExitCode);
        Assert.Contains("reclaimed " + expiring.Id + " expired", swept.Output, StringComparison.Ordinal);
        Assert.Contains("reclaimed 1", swept.Output, StringComparison.Ordinal);

        CommandOutcome listed = await HostCommands.RunAsync(
            ["files", "list", "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.DoesNotContain(expiring.Id, listed.Output, StringComparison.Ordinal);
        Assert.Contains(surviving.Id, listed.Output, StringComparison.Ordinal);
    }

    /// <summary>Listing does not reclaim; only the sweep does.</summary>
    [Fact]
    public async Task Listing_an_expired_handle_leaves_it_where_it_is()
    {
        string store = Store();
        FileHandleReference expiring = await IssueAsync(store, "short", TimeSpan.FromMilliseconds(1));

        await Task.Delay(30, TestContext.Current.CancellationToken);

        CommandOutcome first = await HostCommands.RunAsync(
            ["files", "list", "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        CommandOutcome second = await HostCommands.RunAsync(
            ["files", "list", "--file-store-root", store],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Contains(expiring.Id, first.Output, StringComparison.Ordinal);
        Assert.Equal(first.Output, second.Output);
    }

    [Fact]
    public async Task An_unusable_file_store_root_is_a_configuration_refusal()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["files", "list", "--file-store-root", Path.Combine(_root, "nowhere")],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
    }

    [Fact]
    public void A_shutdown_deadline_reports_the_abandoned_count_and_tool_names()
    {
        using var progress = new StringWriter();

        HostCommands.ReportDrain(progress, new DrainReport(["list-pets", "get-pet"]));

        string output = progress.ToString();
        Assert.Contains("abandoned 2 invocation(s)", output, StringComparison.Ordinal);
        Assert.Contains("list-pets", output, StringComparison.Ordinal);
        Assert.Contains("get-pet", output, StringComparison.Ordinal);
    }

    private static async Task<FileHandleReference> IssueAsync(string root, string payload, TimeSpan? lifetime = null)
    {
        var store = new FileHandleStore(FileHandleStoreOptions.For(root) with
        {
            HandleLifetime = lifetime ?? TimeSpan.FromHours(24),
        });

        using var content = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(payload));

        return await store.IssueAsync(content, "note.txt", "text/plain", "cli", TestContext.Current.CancellationToken);
    }

    private string Store()
    {
        string store = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(store);
        return store;
    }

    private string Manifest(string name)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), MinimalManifest);
        return directory;
    }

    /// <summary>
    /// A protected mount with no configured issuer is a configuration outcome.
    /// </summary>
    /// <remarks>
    /// The manifest declares a scope and no <c>authenticationRequired</c>, so the mount is
    /// protected by the member's default. The listener refuses before it exists, and that
    /// refusal reaching the operator as a crash (an unhandled exception and a non-configuration
    /// exit code) makes an ordinary setup mistake look like a defect in Engine.
    /// </remarks>
    [Fact]
    public async Task A_scoped_mount_without_an_issuer_is_refused_with_the_configuration_code()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["serve", "--file-store-root", Store(), "--mount", "/api=" + ScopedManifest("scoped")],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("issuer", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("Unhandled exception", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// Inspection answers both questions: what would be exposed, and whether it would run.
    /// </summary>
    /// <remarks>
    /// The mount path an inspection runs cannot see the host-side pairing rule, because that
    /// rule depends on configuration rather than on the Manifest. An inspection that printed
    /// only the surfaces would tell an operator everything about a configuration that would
    /// refuse to start.
    /// </remarks>
    [Fact]
    public async Task Inspect_reports_that_serving_a_protected_mount_without_an_issuer_would_be_refused()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["inspect", "--file-store-root", Store(), "--mount", "/api=" + ScopedManifest("scoped")],
            Identity,
            TestContext.Current.CancellationToken);

        // The inspection itself succeeded: it described a loadable mount.
        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("requires authorization", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("would be refused", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("auth/issuer-missing", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("issuer", outcome.Output, StringComparison.Ordinal);

        // And it still described what would be served, rather than replacing that with the refusal.
        Assert.Contains("fingerprint=", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same inspection with an issuer configured reports no refusal.
    /// </summary>
    /// <remarks>
    /// Without this, the previous test would pass just as well against an inspection that always
    /// printed the refusal line.
    /// </remarks>
    [Fact]
    public async Task Inspect_reports_no_refusal_when_the_mount_is_configured_with_an_issuer()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--file-store-root", Store(),
                "--mount", "/api=" + ScopedManifest("scoped"),
                "--issuer", "https://issuer.example",
                "--token-validation", "introspection",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("requires authorization", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("would be refused", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>An open mount inspects without any refusal, with no issuer configured.</summary>
    [Fact]
    public async Task Inspect_reports_an_open_mount_without_a_refusal()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["inspect", "--file-store-root", Store(), "--mount", "/api=" + OpenManifest("open")],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("served without authorization", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("would be refused", outcome.Output, StringComparison.Ordinal);
    }

    private string OpenManifest(string name)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), OpenManifestText);
        return directory;
    }

    /// <summary>
    /// A validation mode the issuer cannot support refuses to start, naming the setting.
    /// </summary>
    /// <remarks>
    /// An issuer that publishes no introspection endpoint can never vouch for a token, so every
    /// protected request would be refused with the one answer a client cannot tell apart from its
    /// own misconfiguration. The refusal happens before anything listens, and it reaches the
    /// operator as a configuration outcome rather than as a crash.
    /// </remarks>
    [Fact]
    public async Task Serve_refuses_when_the_issuer_publishes_no_introspection_endpoint()
    {
        await using FakeAuthorizationServer issuer = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken,
            publishesIntrospection: false);

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "serve",
                "--file-store-root", Store(),
                "--mount", "/api=" + ScopedManifest("scoped"),
                "--issuer", issuer.Address.AbsoluteUri,
                "--token-validation", "introspection",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("auth/introspection-endpoint-missing", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("introspection-endpoint", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("Unhandled exception", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// Inspection answers the same question without serving, and succeeds as an inspection.
    /// </summary>
    /// <remarks>
    /// The check needs the issuer, so it cannot be derived from the mount; an inspection that
    /// omitted it would describe a configuration that could never run.
    /// </remarks>
    [Fact]
    public async Task Inspect_reports_a_validation_mode_the_issuer_cannot_support()
    {
        await using FakeAuthorizationServer issuer = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken,
            publishesIntrospection: false);

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--file-store-root", Store(),
                "--mount", "/api=" + ScopedManifest("scoped"),
                "--issuer", issuer.Address.AbsoluteUri,
                "--token-validation", "introspection",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("would be refused", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("auth/introspection-endpoint-missing", outcome.Output, StringComparison.Ordinal);

        // And it still described what would be served.
        Assert.Contains("fingerprint=", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// Successful file serving reports the bound introspection revalidation policy before the
    /// listener opens.
    /// </summary>
    [Fact]
    public async Task Serve_file_mode_reports_the_effective_introspection_bound()
    {
        await using FakeAuthorizationServer issuer = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken);

        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var progress = new StringWriter();

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "serve",
                "--file-store-root", Store(),
                "--mount", "/api=" + ScopedManifest("serve-policy"),
                "--issuer", issuer.Address.AbsoluteUri,
                "--token-validation", "introspection",
                "--introspection-cache-ttl-seconds", "11",
            ],
            Identity,
            stop.Token,
            progress);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains(
            "introspection revalidation bound: 11 seconds",
            progress.ToString(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Inspection describes the serving policy but does not advertise the Engine-local cache
    /// bound as if it were part of the inspected Manifest or Platform metadata.
    /// </summary>
    [Fact]
    public async Task Inspect_does_not_report_the_engine_local_introspection_bound()
    {
        await using FakeAuthorizationServer issuer = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken);

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--file-store-root", Store(),
                "--mount", "/api=" + ScopedManifest("inspect-policy"),
                "--issuer", issuer.Address.AbsoluteUri,
                "--token-validation", "introspection",
                "--introspection-cache-ttl-seconds", "11",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.DoesNotContain("introspection revalidation bound", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("fingerprint=", outcome.Output, StringComparison.Ordinal);
    }

    private const string OpenManifestText = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": {
              "name": "Open API",
              "authenticationRequired": false
            } },
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

    private string ScopedManifest(string name)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), ScopedManifestText);
        return directory;
    }

    private const string ScopedManifestText = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": {
              "name": "Scoped API",
              "surfaces": [
                { "slug": "full", "isDefault": true, "requiredScopes": ["probe.read"],
                  "operations": [ { "operation": "list-pets", "exposure": "direct" } ] }
              ]
            } },
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

    private const string MinimalManifest = """
        {
          "manifestFormatVersion": "0.3",
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
