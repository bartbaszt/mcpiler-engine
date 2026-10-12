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
    public async Task Compatibility_prints_the_machine_readable_descriptor()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["compatibility"],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Equal(
            MCPiler.Engine.Runtime.CompatibilityDescriptor.EngineSupport().ToCanonicalJson(),
            outcome.Output);
    }

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
    public async Task Inspect_accepts_the_exact_explicit_surface_route_external_resource_binding()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--mount", "/api=" + ScopedManifest("external-resource-valid"),
                "--file-store-root", Store(),
                "--external-resource", "/api/full=https://tunnel.example.test/v1/mcp/one",
                "--issuer", "https://issuer.example",
                "--token-validation", "introspection",
                "--introspection-endpoint", "https://issuer.example/introspect",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("/api surface full", outcome.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_default_surface_alias_is_not_a_second_external_resource_selector()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--mount", "/api=" + ScopedManifest("external-resource-default-alias"),
                "--file-store-root", Store(),
                "--external-resource", "/api=https://tunnel.example.test/v1/mcp/one",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("unknown or disabled surface route '/api'", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("tool list-pets", outcome.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Serve_refuses_an_unknown_external_resource_surface_before_listener_startup()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "serve",
                "--mount", "/api=" + ScopedManifest("external-resource-unknown"),
                "--file-store-root", Store(),
                "--external-resource", "/api/missing=https://tunnel.example.test/v1/mcp/one",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("unknown or disabled surface route '/api/missing'", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("tool list-pets", outcome.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_refuses_a_disabled_external_resource_surface()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--mount", "/api=" + DisabledSiblingManifest("external-resource-disabled"),
                "--file-store-root", Store(),
                "--external-resource", "/api/hidden=https://tunnel.example.test/v1/mcp/one",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("unknown or disabled surface route '/api/hidden'", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("tool list-pets", outcome.Output, StringComparison.Ordinal);
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

    [Theory]
    [InlineData("/api/")]
    [InlineData("/")]
    [InlineData("api")]
    [InlineData("/api/{tenant}")]
    [InlineData("/foo?x")]
    [InlineData("/api/.")]
    [InlineData("/api/../health/live")]
    [InlineData("/foo/../.engine/response-cache")]
    public async Task Inspect_refuses_noncanonical_mount_prefixes(string prefix)
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["inspect", "--mount", prefix + "=" + Manifest("bad-prefix-" + Guid.NewGuid().ToString("N")), "--file-store-root", Store()],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("canonical literal HTTP path", outcome.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("files/upload")]
    [InlineData("FILES/upload")]
    [InlineData("Files/upload")]
    [InlineData("fIlEs/upload")]
    [InlineData("files/capability")]
    [InlineData("FILES/capability")]
    [InlineData("Files/capability")]
    public async Task Inspect_and_serve_refuse_a_surface_that_collides_with_transfer_namespace(string slug)
    {
        string manifest = SurfaceSlugManifest(
            "transfer-collision-" + Guid.NewGuid().ToString("N"),
            slug);
        string store = Store();
        string[] settings =
        [
            "--mount", "/api=" + manifest,
            "--file-store-root", store,
        ];

        CommandOutcome inspect = await HostCommands.RunAsync(
            ["inspect", .. settings],
            Identity,
            TestContext.Current.CancellationToken);
        CommandOutcome serve = await HostCommands.RunAsync(
            ["serve", .. settings],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, inspect.ExitCode);
        Assert.Equal(ExitCodes.Configuration, serve.ExitCode);
        Assert.Contains("host/surface-address-transfer-collision", inspect.Output, StringComparison.Ordinal);
        Assert.Contains("host/surface-address-transfer-collision", serve.Output, StringComparison.Ordinal);
        Assert.Contains("fingerprint=", inspect.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/health", "live")]
    [InlineData("/health", "managed")]
    [InlineData("/HEALTH", "live")]
    [InlineData("/.ENGINE", "response-cache")]
    [InlineData("/.WELL-KNOWN/oauth-protected-resource", "api")]
    public async Task Inspect_refuses_a_surface_that_collides_with_reserved_host_namespaces(string prefix, string slug)
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--mount", prefix + "=" + SurfaceSlugManifest("reserved-collision", slug),
                "--file-store-root", Store(),
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("host/surface-address-reserved", outcome.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("../health/live")]
    [InlineData("../.engine/response-cache")]
    public async Task Inspect_refuses_surface_addresses_with_dot_segments(string slug)
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--mount", "/api=" + SurfaceSlugManifest("dot-segment", slug),
                "--file-store-root", Store(),
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("canonical literal HTTP path", outcome.Output, StringComparison.Ordinal);
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

    // R15.12: the operator reset verb moves an integrity-failed confirmation journal aside (never deleting it).
    [Fact]
    public async Task Confirmed_revisions_reset_moves_an_integrity_failed_journal_aside()
    {
        string stateRoot = Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        File.WriteAllBytes(keyFile, new byte[32]);
        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        File.WriteAllBytes(journal, []);

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "confirmed-revisions", "reset",
                "--file-store-root", Store(),
                "--runtime-state-root", stateRoot,
                "--runtime-state-key-file", keyFile,
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("moved aside", outcome.Output, StringComparison.Ordinal);
        Assert.False(File.Exists(journal));
        Assert.NotEmpty(Directory.GetFiles(stateRoot, "confirmed-revisions.txt.failed-*"));
    }

    // R15.12: the reset is refused while the journal is readable and valid.
    [Fact]
    public async Task Confirmed_revisions_reset_refuses_a_valid_journal()
    {
        string stateRoot = Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        File.WriteAllBytes(keyFile, new byte[32]);
        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        // A valid header-only v2 journal: checksum of the empty body (SHA-256 of "").
        File.WriteAllText(
            journal,
            "#MCPilerConfirmedRevisions\t2\tE3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\n");

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "confirmed-revisions", "reset",
                "--file-store-root", Store(),
                "--runtime-state-root", stateRoot,
                "--runtime-state-key-file", keyFile,
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
        Assert.True(File.Exists(journal), "A valid journal must be left in place.");
    }

    // R16.4: a journal that merely cannot be read right now is not proven integrity-failed, so the reset
    // refuses (non-success) and leaves the file in place instead of moving a valid journal aside.
    [Fact]
    public async Task Confirmed_revisions_reset_refuses_a_transiently_unreadable_journal()
    {
        string stateRoot = Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        File.WriteAllBytes(keyFile, new byte[32]);
        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        File.WriteAllText(journal, "valid-but-held\n");

        // Hold the file exclusively so the operator process cannot read it, reproducing a transient
        // sharing/permission fault rather than an integrity failure.
        using (new FileStream(journal, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            CommandOutcome outcome = await HostCommands.RunAsync(
                [
                    "confirmed-revisions", "reset",
                    "--file-store-root", Store(),
                    "--runtime-state-root", stateRoot,
                    "--runtime-state-key-file", keyFile,
                ],
                Identity,
                TestContext.Current.CancellationToken);

            Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
            Assert.Contains("could not be read", outcome.Output, StringComparison.Ordinal);
        }

        Assert.True(File.Exists(journal), "A transiently unreadable journal must be left in place.");
        Assert.Empty(Directory.GetFiles(stateRoot, "confirmed-revisions.txt.failed-*"));
    }

    // R16.6b: the documented reset command must bind. It takes the same --file-store-root as the other
    // verbs; without it HostConfiguration refuses and the documented command would exit with the
    // configuration code. This runs the documented argument list verbatim.
    [Fact]
    public async Task Confirmed_revisions_reset_accepts_the_documented_argument_list()
    {
        string stateRoot = Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        File.WriteAllBytes(keyFile, new byte[32]);
        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        File.WriteAllText(
            journal,
            "#MCPilerConfirmedRevisions\t2\tE3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\n");

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "confirmed-revisions", "reset",
                "--file-store-root", Store(),
                "--runtime-state-root", stateRoot,
                "--runtime-state-key-file", keyFile,
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.NotEqual(ExitCodes.Configuration, outcome.ExitCode);
        Assert.True(File.Exists(journal));
    }

    // R17.3: without the runtime-state options there is nothing the reset could act on. It must refuse with
    // the configuration code and name both options, never report "nothing to reset" for an unconfigured
    // store, and leave any journal untouched.
    [Fact]
    public async Task Confirmed_revisions_reset_without_runtime_state_refuses_and_names_the_options()
    {
        string stateRoot = Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        File.WriteAllBytes(keyFile, new byte[32]);
        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        File.WriteAllBytes(journal, []);
        byte[] before = await File.ReadAllBytesAsync(journal, TestContext.Current.CancellationToken);

        CommandOutcome outcome = await HostCommands.RunAsync(
            ["confirmed-revisions", "reset", "--file-store-root", Store()],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("--runtime-state-root", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("--runtime-state-key-file", outcome.Output, StringComparison.Ordinal);
        Assert.Equal(before, await File.ReadAllBytesAsync(journal, TestContext.Current.CancellationToken));
    }

    // R17.3: with configured runtime state and no journal on disk the existing success message stays.
    [Fact]
    public async Task Confirmed_revisions_reset_with_no_journal_still_reports_nothing_to_reset()
    {
        string stateRoot = Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        File.WriteAllBytes(keyFile, new byte[32]);

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "confirmed-revisions", "reset",
                "--file-store-root", Store(),
                "--runtime-state-root", stateRoot,
                "--runtime-state-key-file", keyFile,
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("nothing to reset", outcome.Output, StringComparison.Ordinal);
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
    /// Inspection answers both questions: what would be exposed, and whether the exact HTTP
    /// configuration can start.
    /// </summary>
    /// <remarks>
    /// A CI preflight that exits zero for a configuration <c>serve</c> will reject is worse than
    /// a missing preflight: automation promotes the deployment precisely because the check said
    /// it was usable. The report still includes the derived surface for diagnosis, but the
    /// process outcome is the same configuration refusal as serving.
    /// </remarks>
    [Fact]
    public async Task Inspect_refuses_a_protected_http_mount_without_an_issuer()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["inspect", "--file-store-root", Store(), "--mount", "/api=" + ScopedManifest("scoped")],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("requires authorization", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("would be refused", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("auth/issuer-missing", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("issuer", outcome.Output, StringComparison.Ordinal);

        // The refusal does not hide the valid Manifest/surface description an operator needs.
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

    [Fact]
    public async Task Inspect_and_serve_both_refuse_unusable_introspection_client_secret_files()
    {
        string missing = Path.Combine(_root, "missing-introspection-secret");
        string empty = Path.Combine(_root, "empty-introspection-secret");
        string notAFile = Path.Combine(_root, "introspection-secret-directory");

        File.WriteAllText(empty, string.Empty);
        Directory.CreateDirectory(notAFile);

        foreach ((string label, string secret) in new[]
        {
            ("missing", missing),
            ("empty", empty),
            ("not-a-file", notAFile),
        })
        {
            string[] settings =
            [
                "--file-store-root", Store(),
                "--mount", "/api=" + ScopedManifest("secret-" + label),
                "--issuer", "https://issuer.example",
                "--token-validation", "introspection",
                "--introspection-endpoint", "https://issuer.example/introspect",
                "--introspection-client-id", "engine",
                "--introspection-client-secret-file", secret,
            ];

            CommandOutcome inspect = await HostCommands.RunAsync(
                ["inspect", .. settings],
                Identity,
                TestContext.Current.CancellationToken);

            CommandOutcome serve = await HostCommands.RunAsync(
                ["serve", .. settings],
                Identity,
                TestContext.Current.CancellationToken);

            Assert.Equal(ExitCodes.Configuration, inspect.ExitCode);
            Assert.Equal(ExitCodes.Configuration, serve.ExitCode);
            Assert.Contains("auth/introspection-client-secret-unusable", inspect.Output, StringComparison.Ordinal);
            Assert.Contains("introspection client", inspect.Output, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(secret, inspect.Output, StringComparison.Ordinal);
            Assert.Contains("auth/introspection-client-secret-unusable", serve.Output, StringComparison.Ordinal);
            Assert.Contains(secret, serve.Output, StringComparison.Ordinal);
        }
    }

    /// <summary>An open mount inspects without any refusal, with no issuer configured.</summary>
    [Fact]
    public async Task Inspect_requires_an_allowed_host_for_a_protected_wildcard_listener()
    {
        string[] settings =
        [
            "--file-store-root", Store(),
            "--mount", "/api=" + ScopedManifest("wildcard-protected"),
            "--issuer", "https://issuer.example",
            "--token-validation", "introspection",
            "--introspection-endpoint", "https://issuer.example/introspect",
            "--listen", "http://0.0.0.0:8080",
        ];

        CommandOutcome refused = await HostCommands.RunAsync(
            ["inspect", .. settings],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, refused.ExitCode);
        Assert.Contains("auth/allowed-host-missing", refused.Output, StringComparison.Ordinal);

        CommandOutcome admitted = await HostCommands.RunAsync(
            ["inspect", .. settings, "--allowed-host", "mcp.example.com"],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, admitted.ExitCode);
        Assert.DoesNotContain("auth/allowed-host-missing", admitted.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Open_mount_does_not_require_an_allowed_host_only_because_issuer_settings_exist()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--file-store-root", Store(),
                "--mount", "/api=" + OpenManifest("wildcard-open"),
                "--issuer", "https://issuer.example",
                "--token-validation", "introspection",
                "--introspection-endpoint", "https://issuer.example/introspect",
                "--listen", "http://0.0.0.0:8080",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.DoesNotContain("auth/allowed-host-missing", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// Binding one protected surface's resource does not make its protected sibling servable, and
    /// the refusal names the surface that is actually unbound.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The bound surface carries a fixed audience, so it needs no listener boundary. The unbound
    /// sibling derives its resource identity from the request authority, which is the whole reason
    /// the setting exists. A refusal that did not name that sibling would leave an operator with
    /// one missing setting and no way to tell which surface still wanted it.
    /// </para>
    /// <para>
    /// The last assertion is the distinct case: a mount whose every protected surface is bound
    /// needs no allowed host at all, even on a wildcard listener. Without it, a test could pass
    /// because the setting happened to be supplied and never prove that binding every surface
    /// removes the requirement.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_protected_sibling_without_an_external_resource_still_requires_an_allowed_host()
    {
        string[] shared =
        [
            "--file-store-root", Store(),
            "--mount", "/api=" + TwoSurfaceProtectedManifest("allowed-host-siblings"),
            "--issuer", "https://issuer.example",
            "--token-validation", "introspection",
            "--introspection-endpoint", "https://issuer.example/introspect",
            "--listen", "http://0.0.0.0:8080",
        ];

        CommandOutcome oneBound = await HostCommands.RunAsync(
            [
                "inspect",
                .. shared,
                "--external-resource", "/api/first=https://tunnel.example.test/v1/mcp/one",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, oneBound.ExitCode);
        Assert.Contains("auth/allowed-host-missing", oneBound.Output, StringComparison.Ordinal);

        // The whole sentence is asserted, not just the route: "inspect" already prints every
        // mounted surface, so an assertion on "/api/second" alone would be satisfied by that
        // listing whether or not the diagnostic named it. The contiguous sentence can only come
        // from the refusal itself, and naming only the unbound sibling is the property under test.
        Assert.Contains(
            "These protected surfaces have no external resource, so their resource identity is "
            + "derived from the request authority: /api/second.",
            oneBound.Output,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "request authority: /api/first",
            oneBound.Output,
            StringComparison.Ordinal);

        CommandOutcome withAllowedHost = await HostCommands.RunAsync(
            [
                "inspect",
                .. shared,
                "--external-resource", "/api/first=https://tunnel.example.test/v1/mcp/one",
                "--allowed-host", "mcp.example.com",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, withAllowedHost.ExitCode);
        Assert.DoesNotContain("auth/allowed-host-missing", withAllowedHost.Output, StringComparison.Ordinal);

        CommandOutcome allBound = await HostCommands.RunAsync(
            [
                "inspect",
                .. shared,
                "--external-resource", "/api/first=https://tunnel.example.test/v1/mcp/one",
                "--external-resource", "/api/second=https://tunnel.example.test/v1/mcp/two",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, allBound.ExitCode);
        Assert.DoesNotContain("auth/allowed-host-missing", allBound.Output, StringComparison.Ordinal);
    }

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

    [Fact]
    public async Task Inspect_stdio_uses_the_local_process_boundary_and_does_not_require_an_http_issuer()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "inspect",
                "--file-store-root", Store(),
                "--mount", "/api=" + ScopedManifest("stdio-protected"),
                "--transport", "stdio",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.DoesNotContain("auth/issuer-missing", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("would be refused", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("fingerprint=", outcome.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_and_serve_stdio_both_refuse_more_than_one_surface()
    {
        string manifest = MultiSurfaceManifest("stdio-many-surfaces");

        string[] settings =
        [
            "--file-store-root", Store(),
            "--mount", "/api=" + manifest,
            "--transport", "stdio",
        ];

        CommandOutcome inspect = await HostCommands.RunAsync(
            ["inspect", .. settings],
            Identity,
            TestContext.Current.CancellationToken);

        CommandOutcome serve = await HostCommands.RunAsync(
            ["serve", .. settings],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, inspect.ExitCode);
        Assert.Equal(ExitCodes.Configuration, serve.ExitCode);
        Assert.Contains("exactly one surface", inspect.Output, StringComparison.Ordinal);
        Assert.Contains("exactly one surface", serve.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_and_serve_stdio_both_refuse_more_than_one_mount()
    {
        string first = OpenManifest("stdio-first");
        string second = OpenManifest("stdio-second");

        string[] settings =
        [
            "--file-store-root", Store(),
            "--mount", "/first=" + first,
            "--mount", "/second=" + second,
            "--transport", "stdio",
        ];

        CommandOutcome inspect = await HostCommands.RunAsync(
            ["inspect", .. settings],
            Identity,
            TestContext.Current.CancellationToken);

        CommandOutcome serve = await HostCommands.RunAsync(
            ["serve", .. settings],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, inspect.ExitCode);
        Assert.Equal(ExitCodes.Configuration, serve.ExitCode);
        Assert.Contains("exactly one mounted Manifest", inspect.Output, StringComparison.Ordinal);
        Assert.Contains("exactly one mounted Manifest", serve.Output, StringComparison.Ordinal);
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
    /// Inspection returns the same configuration refusal when the chosen validation mode cannot
    /// be satisfied by the issuer.
    /// </summary>
    [Fact]
    public async Task Inspect_refuses_a_validation_mode_the_issuer_cannot_support()
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

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("would be refused", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("auth/introspection-endpoint-missing", outcome.Output, StringComparison.Ordinal);

        // The valid Manifest/surface description remains available for diagnosis.
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

    private string MultiSurfaceManifest(string name)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), MultiSurfaceManifestText);
        return directory;
    }

    private const string MultiSurfaceManifestText = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": {
              "name": "Multi Surface API",
              "authenticationRequired": false,
              "surfaces": [
                {
                  "slug": "read",
                  "isDefault": true,
                  "operations": [ { "operation": "list-pets", "exposure": "direct" } ]
                },
                {
                  "slug": "full",
                  "operations": [ { "operation": "list-pets", "exposure": "direct" } ]
                }
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

    private string SurfaceSlugManifest(string name, string slug)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(
            Path.Combine(directory, "manifest.json"),
            OpenManifestText.Replace(
                "\"name\": \"Open API\",",
                $"\"name\": \"Open API\", \"surfaces\": [{{ \"slug\": \"{slug}\", \"isDefault\": true, \"operations\": [{{ \"operation\": \"list-pets\", \"exposure\": \"direct\" }}] }}],",
                StringComparison.Ordinal));
        return directory;
    }

    private string ScopedManifest(string name)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), ScopedManifestText);
        return directory;
    }

    /// <summary>
    /// A protected mount with two surfaces, because the sibling case is the one the allowed-host
    /// requirement turns on: binding one surface's resource must not make the other one servable.
    /// </summary>
    private string TwoSurfaceProtectedManifest(string name)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), TwoSurfaceProtectedManifestText);
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

    private const string TwoSurfaceProtectedManifestText = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": {
              "name": "Two surface API",
              "surfaces": [
                { "slug": "first", "isDefault": true, "requiredScopes": ["probe.read"],
                  "operations": [ { "operation": "list-pets", "exposure": "direct" } ] },
                { "slug": "second", "requiredScopes": ["probe.read"],
                  "operations": [ { "operation": "list-orders", "exposure": "direct" } ] }
              ]
            } },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": {
                "operations": [
                  { "key": "GET /pets", "method": "GET", "path": "/pets" },
                  { "key": "GET /orders", "method": "GET", "path": "/orders" }
                ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "list-pets",
                    "name": "List pets",
                    "binding": { "type": "http", "operation": "GET /pets" }
                  },
                  {
                    "slug": "list-orders",
                    "name": "List orders",
                    "binding": { "type": "http", "operation": "GET /orders" }
                  }
                ]
              }
            }
          }
        }
        """;

    private string DisabledSiblingManifest(string name)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), DisabledSiblingManifestText);
        return directory;
    }

    private const string DisabledSiblingManifestText = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": {
              "name": "Scoped API",
              "authenticationRequired": false,
              "surfaces": [
                { "slug": "full", "isDefault": true,
                  "operations": [ { "operation": "list-pets", "exposure": "direct" } ] },
                { "slug": "hidden", "enabled": false,
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
            "server": { "inline": {
              "name": "Example API",
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
}
