using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Cli;

/// <summary>
/// The stage-1 operator management surface end to end: status of every state, a deliberate clear
/// with its separate local and provider outcomes, bounded diagnostics and the acknowledged
/// destructive reset.
/// </summary>
/// <remarks>
/// Everything here drives the real CLI verbs against a real deployment directory: a real Manifest,
/// a real encrypted store and, where a provider is involved, a real loopback HTTP provider. The
/// canaries deliberately written into fixtures must never appear in any output.
/// </remarks>
[Collection(AuthorizationCommandCollection.Name)]
public sealed class OAuthOperatorCommandsTests : IDisposable
{
    private const string Identity = "mcpiler-engine test (manifest format 0.2)";

    /// <summary>A manifest scope fingerprint must be 64 lower-case hex characters.</summary>
    private const string ScopeFingerprint =
        "0000000000000000000000000000000000000000000000000000000000000007";

    /// <summary>A literal credential the CLI may resolve but must never print.</summary>
    private const string InlineCanary = "CANARY-declared-inline-77c2";

    /// <summary>A fallback refresh credential used only by the serving-path assertions.</summary>
    private const string DeclaredFallback = "CANARY-declared-fallback";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-oauth-ops-" + Guid.NewGuid().ToString("N"));
    private readonly AuthorizationOutcomeLog _log = new();

    private int _sequence;

    public OAuthOperatorCommandsTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    /// <summary>Status of a profile whose declared source does not resolve is a missing source, not configured.</summary>
    [Fact]
    public async Task Status_reports_a_declared_source_that_does_not_resolve_as_a_missing_source()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialUnsetEnv, ProfileJson("oauth", null)));

        CommandOutcome outcome = await RunAsync(deployment, "auth", "status", "/api", "oauth");

        Assert.True(outcome.ExitCode == ExitCodes.Success, outcome.Output);
        Assert.Contains("unconfigured oauth/missing-source", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("MCPILER_OPS_UNSET_REFRESH", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("fromEnv:MCPILER_OPS_UNSET_REFRESH", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(InlineCanary, outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>A resolvable declared source is reported configured, and its value is never printed.</summary>
    [Fact]
    public async Task Status_reports_a_resolvable_declared_source_as_configured_without_its_value()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        CommandOutcome outcome = await RunAsync(
            deployment, "auth", "status", "/api", "oauth");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("configured oauth/configured", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("slot=refreshToken", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("inline:(redacted)", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("present", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(InlineCanary, outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>A committed local decision is reported with its effective epoch, and a cleared one masks the declared source.</summary>
    [Theory]
    [InlineData(false, "authorized oauth/authorized")]
    [InlineData(true, "cleared oauth/cleared")]
    public async Task Status_reports_a_committed_decision(bool cleared, string expected)
    {
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, TestContext.Current.CancellationToken, authorizationCode: provider);

        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null, server.Address)));

        var store = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await store.CompareAndCommitAsync(
            Decision("oauth", server.Address, null,
                cleared ? MutableSlotDecisionKind.Cleared : MutableSlotDecisionKind.Authorized,
                epoch: 2, revision: 0, cleared ? null : provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            TestContext.Current.CancellationToken);

        CommandOutcome outcome = await RunAsync(deployment, "auth", "status", "/api", "oauth");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains(expected, outcome.Output, StringComparison.Ordinal);
        Assert.Contains("authority epoch 2, revision 0", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(provider.RefreshToken, outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>An unreadable record is a fault that names the recovery, and is never treated as absent.</summary>
    [Fact]
    public async Task Status_reports_an_unreadable_record_and_points_at_the_acknowledged_reset()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        // A v1 record written with one key, then read with another: readable bytes, unauthenticatable.
        await WriteUnreadableRecordAsync(deployment);

        CommandOutcome outcome = await RunAsync(deployment, "auth", "status", "/api", "oauth");

        Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
        Assert.Contains("faulted oauth/authority-unreadable", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("--acknowledge-irrecoverable", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-unreadable-3c9d", outcome.Output, StringComparison.Ordinal);
        Assert.Single(Directory.GetFiles(deployment.StateRoot, "*.rstate"));
    }

    /// <summary>A second owner means no coherent read is claimed, rather than a possibly stale one.</summary>
    [Fact]
    public async Task Status_reports_a_conflict_while_another_owner_holds_the_root()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        Assert.True(EngineRuntime.TryAcquireRuntimeStateOwner(deployment.StateRoot, out IDisposable? owner, out string? refusal), refusal);
        using (owner)
        {
            CommandOutcome outcome = await RunAsync(deployment, "auth", "status", "/api", "oauth");

            Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
            Assert.Contains("unavailable oauth/status-conflict", outcome.Output, StringComparison.Ordinal);
        }
    }

    /// <summary>A profile whose durable state cannot be provided is refused by name.</summary>
    [Fact]
    public async Task Status_without_runtime_state_is_refused_by_name()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "auth", "status", "/api", "oauth",
                "--mount", "/api=" + deployment.ManifestDirectory,
                "--file-store-root", deployment.StoreRoot,
                "--allow-inline-secrets", "true",
            ],
            Identity,
            TestContext.Current.CancellationToken,
            progress: null,
            outcomes: _log);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("RuntimeStateRoot", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>The inventory form reports every profile of every mount.</summary>
    [Fact]
    public async Task Status_without_a_target_reports_every_profile()
    {
        Deployment deployment = CreateDeployment(
            Manifest(
                CredentialInline,
                ProfileJson("oauth", null) + ", " + ProfileJson("oauth-b", null),
                "\"oauth\", \"oauth-b\""));

        CommandOutcome outcome = await RunAsync(deployment, "auth", "status");

        Assert.True(outcome.ExitCode == ExitCodes.Success, outcome.Output);
        Assert.Contains("/api oauth ", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("/api oauth-b ", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>Managed status reports managed metadata only and directs lifecycle to Platform.</summary>
    [Fact]
    public async Task Status_in_managed_mode_reports_only_managed_metadata()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "auth", "status",
                "--mode", "managed",
                "--file-store-root", deployment.StoreRoot,
                "--management-endpoint", "http://127.0.0.1:9/api",
                "--deployment-id", "deployment-under-test",
                "--deployment-secret-file", Path.Combine(_root, "deployment.secret"),
            ],
            Identity,
            TestContext.Current.CancellationToken,
            progress: null,
            outcomes: _log);

        Assert.True(outcome.ExitCode == ExitCodes.Success, outcome.Output);
        Assert.Contains("managed", outcome.Output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Platform Connect", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(InlineCanary, outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>A clear commits an advancing cleared floor that a restart and a served call both honour.</summary>
    [Fact]
    public async Task Clear_commits_a_floor_a_restart_cannot_bypass()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null, server.Address)));

        var seeded = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await seeded.CompareAndCommitAsync(
            Decision("oauth", server.Address, null, MutableSlotDecisionKind.Authorized, 2, 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        CommandOutcome outcome = await RunAsync(deployment, "auth", "clear", "/api", "oauth");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("cleared /api oauth oauth/cleared", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("local clear: cleared", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("provider revocation: not-attempted", outcome.Output, StringComparison.Ordinal);
        Assert.Equal(0, provider.RevocationRequests);
        Assert.DoesNotContain(provider.RefreshToken, outcome.Output, StringComparison.Ordinal);

        // The floor is durable and advances beyond both the declared epoch and the local decision.
        MutableSlotDecision? decision = await new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision!.Kind);
        Assert.Equal(3, decision.AuthorityEpoch);
        Assert.Null(decision.RefreshToken);
    }

    /// <summary>Clearing an already-cleared slot is a documented no-op that never unmasks a source.</summary>
    [Fact]
    public async Task Clear_is_a_no_op_when_the_slot_is_already_cleared()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        var store = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await store.CompareAndCommitAsync(
            Decision("oauth", null, null, MutableSlotDecisionKind.Cleared, 2, 0, null),
            expectedVersion: null,
            declaredEpoch: 1,
            TestContext.Current.CancellationToken);

        string recordPath = Assert.Single(Directory.GetFiles(deployment.StateRoot, "*.rstate"));
        byte[] before = await File.ReadAllBytesAsync(recordPath, TestContext.Current.CancellationToken);

        CommandOutcome outcome = await RunAsync(deployment, "auth", "clear", "/api", "oauth");

        Assert.True(outcome.ExitCode == ExitCodes.Success, outcome.Output);
        Assert.Contains("oauth/already-cleared", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("Nothing was changed", outcome.Output, StringComparison.Ordinal);
        Assert.Equal(before, await File.ReadAllBytesAsync(recordPath, TestContext.Current.CancellationToken));
        Assert.Single(Directory.GetFiles(deployment.StateRoot, "*.rstate"));
    }

    /// <summary>With neither a local decision nor a declared refresh credential there is nothing to clear.</summary>
    [Fact]
    public async Task Clear_is_a_no_op_when_nothing_exists_to_clear()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialClientSecretOnly, ProfileJson("oauth", null)));

        CommandOutcome outcome = await RunAsync(deployment, "auth", "clear", "/api", "oauth");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("oauth/nothing-to-clear", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("oauth/cleared", outcome.Output, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(deployment.StateRoot, "*.rstate"));
    }

    /// <summary>
    /// A declared endpoint the shipped containment policy refuses cannot undo the committed local
    /// clear, and its failure never escapes.
    /// </summary>
    [Fact]
    public async Task Clear_keeps_the_local_clear_when_the_provider_endpoint_is_out_of_policy()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario { Revocation = RevocationBehaviour.Reject };
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", RevocationEndpoint(server.Address), server.Address)));

        var seeded = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await seeded.CompareAndCommitAsync(
            Decision("oauth", server.Address, RevocationEndpoint(server.Address), MutableSlotDecisionKind.Authorized, 2, 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        CommandOutcome outcome = await RunAsync(deployment, "auth", "clear", "/api", "oauth");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("local clear: cleared", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("provider revocation: failed", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-revocation-secret-4a1f", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(provider.RefreshToken, outcome.Output, StringComparison.Ordinal);

        // A loopback revocation endpoint is not reachable under the shipped production policy, so a
        // CLI clear never contacts it; the seam test with a permissive policy covers the attempt.
        Assert.Equal(0, provider.RevocationRequests);

        MutableSlotDecision? decision = await new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision!.Kind);
        Assert.Equal(3, decision.AuthorityEpoch);
    }

    /// <summary>Without a declared endpoint nothing is contacted, and the local clear still stands.</summary>
    [Fact]
    public async Task Clear_reports_not_attempted_when_no_revocation_endpoint_is_declared()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        Deployment deployment = CreateDeployment(
            Manifest(CredentialClientSecretOnly, ProfileJson("oauth", null)));

        var seeded = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await seeded.CompareAndCommitAsync(
            Decision("oauth", null, null, MutableSlotDecisionKind.Authorized, 2, 0, DeclaredFallback),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        CommandOutcome outcome = await RunAsync(deployment, "auth", "clear", "/api", "oauth");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("provider revocation: not-attempted", outcome.Output, StringComparison.Ordinal);
        Assert.Equal(0, provider.RevocationRequests);
    }

    /// <summary>A running owner refuses the clear before any state or provider change.</summary>
    [Fact]
    public async Task Clear_refuses_before_any_change_while_another_owner_holds_the_root()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        Assert.True(EngineRuntime.TryAcquireRuntimeStateOwner(deployment.StateRoot, out IDisposable? owner, out string? refusal), refusal);
        using (owner)
        {
            CommandOutcome outcome = await RunAsync(deployment, "auth", "clear", "/api", "oauth");

            Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
            Assert.Empty(Directory.GetFiles(deployment.StateRoot, "*.rstate"));
        }
    }

    /// <summary>Clearing one profile leaves a sibling profile's authorization untouched (OPS-2b).</summary>
    [Fact]
    public async Task Clear_isolates_a_sibling_profile()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        Deployment deployment = CreateDeployment(
            Manifest(
                CredentialInline,
                ProfileJson("oauth", null, server.Address) + ", " + ProfileJson("oauth-b", null, server.Address),
                "\"oauth\", \"oauth-b\""));

        var store = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await store.CompareAndCommitAsync(
            Decision("oauth", server.Address, null, MutableSlotDecisionKind.Authorized, 2, 0, provider.RefreshToken),
            expectedVersion: null, declaredEpoch: 1, cancellationToken);
        await store.CompareAndCommitAsync(
            Decision("oauth-b", server.Address, null, MutableSlotDecisionKind.Authorized, 2, 0, "CANARY-sibling-refresh-1b7e"),
            expectedVersion: null, declaredEpoch: 1, cancellationToken);

        CommandOutcome outcome = await RunAsync(deployment, "auth", "clear", "/api", "oauth");

        Assert.True(outcome.ExitCode == ExitCodes.Success, outcome.Output);

        MutableSlotDecision? sibling = await new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth-b", "refreshToken", cancellationToken);
        Assert.NotNull(sibling);
        Assert.Equal(MutableSlotDecisionKind.Authorized, sibling!.Kind);
        Assert.Equal(2, sibling.AuthorityEpoch);
        Assert.Equal(2, Directory.GetFiles(deployment.StateRoot, "*.rstate").Length);
    }

    /// <summary>A local clear is refused in managed mode before any change.</summary>
    [Theory]
    [InlineData("clear")]
    [InlineData("authority-reset")]
    public async Task Managed_mode_refuses_local_mutating_auth_verbs(string verb)
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        CommandOutcome outcome = await HostCommands.RunAsync(
            ["auth", verb, "/api", "oauth", "--mode", "managed"],
            Identity,
            TestContext.Current.CancellationToken,
            progress: null,
            outcomes: _log);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("managed mode", outcome.Output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Reauthorize", outcome.Output, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(deployment.StateRoot, "*.rstate"));
    }

    /// <summary>The reset names what it would affect and refuses without the acknowledgement.</summary>
    [Fact]
    public async Task Authority_reset_demands_an_acknowledgement_and_names_the_affected_slots()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));
        string recordPath = await WriteUnreadableRecordAsync(deployment);

        byte[] before = await File.ReadAllBytesAsync(recordPath, TestContext.Current.CancellationToken);
        CommandOutcome outcome = await RunAsync(deployment, "auth", "authority-reset", "/api", "oauth");

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("oauth/reset-acknowledgement-required", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("affected slot: refreshToken", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("--acknowledge-irrecoverable", outcome.Output, StringComparison.Ordinal);
        Assert.Equal(before, await File.ReadAllBytesAsync(recordPath, TestContext.Current.CancellationToken));
    }

    /// <summary>A readable record is ordinary business, so the destructive path refuses it.</summary>
    [Fact]
    public async Task Authority_reset_refuses_when_the_record_can_still_be_read()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        var store = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await store.CompareAndCommitAsync(
            Decision("oauth", null, null, MutableSlotDecisionKind.Authorized, 2, 0, DeclaredFallback),
            expectedVersion: null, declaredEpoch: 1, TestContext.Current.CancellationToken);

        CommandOutcome outcome = await RunAsync(
            deployment, "auth", "authority-reset", "/api", "oauth", "--acknowledge-irrecoverable");

        Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
        Assert.Contains("oauth/reset-not-required", outcome.Output, StringComparison.Ordinal);

        MutableSlotDecision? decision = await new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal(2, decision.AuthorityEpoch);
    }

    /// <summary>An acknowledged reset replaces unreadable authority with a fail-closed baseline in one commit.</summary>
    [Fact]
    public async Task Authority_reset_establishes_a_fail_closed_baseline()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null, server.Address)));
        string recordPath = await WriteUnreadableRecordAsync(deployment);

        CommandOutcome outcome = await RunAsync(
            deployment, "auth", "authority-reset", "/api", "oauth", "--acknowledge-irrecoverable");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("reset /api oauth oauth/reset-complete", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("result: refreshToken: baseline-established", outcome.Output, StringComparison.Ordinal);

        // The slot is never observably absent: the fresh baseline is a cleared decision at the
        // next declared epoch, and a fresh read authenticates it.
        MutableSlotDecision? decision = await new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision!.Kind);
        Assert.Equal(2, decision.AuthorityEpoch);
        Assert.Single(Directory.GetFiles(deployment.StateRoot, "*.rstate"));

        // The retired bytes are gone and the declared source stays masked: no provider is reached.
        byte[] after = await File.ReadAllBytesAsync(recordPath, cancellationToken);
        Assert.DoesNotContain("CANARY-unreadable-3c9d", Encoding.UTF8.GetString(after), StringComparison.Ordinal);
        Assert.Equal(0, provider.TokenRequests);
    }

    /// <summary>Diagnostics state their in-memory scope instead of inventing a durable history.</summary>
    [Fact]
    public async Task Events_state_that_no_history_survives_a_restart()
    {
        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", null)));

        CommandOutcome outcome = await RunAsync(deployment, "auth", "events");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("No recent authorization outcomes are available.", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("not a durable audit history", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>A recorded outcome is reported as categories and identities, never as secrets.</summary>
    [Fact]
    public async Task Events_report_a_recorded_outcome_without_secrets()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario { Revocation = RevocationBehaviour.Reject };
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", RevocationEndpoint(server.Address), server.Address)));

        var seeded = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await seeded.CompareAndCommitAsync(
            Decision("oauth", server.Address, RevocationEndpoint(server.Address), MutableSlotDecisionKind.Authorized, 2, 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        CommandOutcome cleared = await RunAsync(deployment, "auth", "clear", "/api", "oauth");
        CommandOutcome events = await RunAsync(deployment, "auth", "events");

        Assert.Equal(ExitCodes.Success, cleared.ExitCode);
        Assert.Equal(ExitCodes.Success, events.ExitCode);
        Assert.Contains("clear /api oauth local oauth/cleared", events.Output, StringComparison.Ordinal);
        Assert.Contains("clear /api oauth provider oauth/revocation-failed", events.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-revocation-secret-4a1f", events.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(provider.RefreshToken, events.Output, StringComparison.Ordinal);
    }

    /// <summary>The outcome buffer is bounded by count and by age.</summary>
    [Fact]
    public void Outcome_buffer_is_bounded_and_expires()
    {
        DateTimeOffset realNow = TimeProvider.System.GetUtcNow();
        var bounded = new AuthorizationOutcomeLog(maximumEntries: 3);

        for (int index = 0; index < 5; index++)
        {
            bounded.Record(new AuthorizationOutcome(realNow, "clear", "/api", "oauth", "local", "oauth/cleared", "outcome " + index.ToString(CultureInfo.InvariantCulture)));
        }

        Assert.Equal(3, bounded.Count);
        Assert.Equal(3, bounded.Recent(realNow).Count);
        Assert.Equal("outcome 4", bounded.Recent(realNow)[0].Message);

        bounded.Clear();
        Assert.Equal(0, bounded.Count);
        Assert.Empty(bounded.Recent(realNow));

        // An entry older than the window is dropped rather than reported as recent. Reading far
        // enough ahead ages the entry out without touching a clock inside the buffer.
        var expiring = new AuthorizationOutcomeLog(retention: TimeSpan.FromMinutes(1));
        expiring.Record(new AuthorizationOutcome(realNow, "clear", "/api", "oauth", "local", "oauth/cleared", "aged"));

        Assert.Single(expiring.Recent(realNow));
        Assert.Empty(expiring.Recent(realNow + TimeSpan.FromMinutes(5)));
    }

    /// <summary>Every operator surface renders without leaking a declared, retired or provider secret.</summary>
    [Fact]
    public async Task No_operator_surface_renders_a_secret_canary()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario { Revocation = RevocationBehaviour.Reject };
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        Deployment deployment = CreateDeployment(
            Manifest(CredentialInline, ProfileJson("oauth", RevocationEndpoint(server.Address), server.Address)));

        var seeded = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await seeded.CompareAndCommitAsync(
            Decision("oauth", server.Address, RevocationEndpoint(server.Address), MutableSlotDecisionKind.Authorized, 2, 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        StringBuilder all = new();
        all.Append((await RunAsync(deployment, "auth", "status", "/api", "oauth")).Output);
        all.Append((await RunAsync(deployment, "auth", "clear", "/api", "oauth")).Output);
        all.Append((await RunAsync(deployment, "auth", "events")).Output);
        all.Append((await RunAsync(deployment, "auth", "authority-reset", "/api", "oauth", "--acknowledge-irrecoverable")).Output);

        string rendered = all.ToString();
        Assert.DoesNotContain(InlineCanary, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(DeclaredFallback, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(provider.RefreshToken, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(provider.AccessToken, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-revocation-secret-4a1f", rendered, StringComparison.Ordinal);
    }

    /// <summary>
    /// A committed decision is durable across a real process boundary: a <em>second</em> operating
    /// system process reads the encrypted authority this process committed and reports the same
    /// effective epoch, without ever seeing the credential.
    /// </summary>
    [Fact]
    public async Task A_second_process_reports_the_committed_authority_without_its_secret()
    {
        const string refresh = "CANARY-process-boundary-9f31";
        Deployment deployment = CreateDeployment(Manifest(CredentialInline, ProfileJson("oauth", null)));

        var store = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await store.CompareAndCommitAsync(
            Decision("oauth", serverAddress: null, revocationEndpoint: null,
                MutableSlotDecisionKind.Authorized, epoch: 2, revision: 0, refresh),
            expectedVersion: null,
            declaredEpoch: 1,
            TestContext.Current.CancellationToken);

        EngineCliOutcome outcome = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken,
            ProcessArguments(deployment, "status", "/api", "oauth"));

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("authorized oauth/authorized", outcome.Stdout, StringComparison.Ordinal);
        Assert.Contains("authority epoch 2, revision 0", outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(refresh, outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(refresh, outcome.Stderr, StringComparison.Ordinal);
    }

    /// <summary>
    /// A clear performed by a real CLI process persists: the next process reads the advanced
    /// cleared floor and the declared source stays masked.
    /// </summary>
    [Fact]
    public async Task A_real_cli_clear_advances_the_floor_across_a_process_boundary()
    {
        const string refresh = "CANARY-process-clear-4b8e";
        Deployment deployment = CreateDeployment(Manifest(CredentialInline, ProfileJson("oauth", null)));

        var store = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        await store.CompareAndCommitAsync(
            Decision("oauth", serverAddress: null, revocationEndpoint: null,
                MutableSlotDecisionKind.Authorized, epoch: 2, revision: 0, refresh),
            expectedVersion: null,
            declaredEpoch: 1,
            TestContext.Current.CancellationToken);

        EngineCliOutcome outcome = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken,
            ProcessArguments(deployment, "clear", "/api", "oauth"));

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("oauth/cleared", outcome.Stdout, StringComparison.Ordinal);
        Assert.Contains("provider revocation: not-attempted", outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(refresh, outcome.Stdout, StringComparison.Ordinal);

        // The next process's view: the floor advanced and no source can resurrect behind it.
        var reopened = new FileMutableSlotStore(deployment.StateRoot, "/api", FixtureKey());
        MutableSlotDecision? decision = await reopened.LoadDecisionAsync(
            "oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision!.Kind);
        Assert.Equal(3, decision.AuthorityEpoch);
        Assert.Equal(0, decision.RuntimeRevision);
        Assert.Null(decision.RefreshToken);
    }

    /// <summary>Writes an authenticated v1 record with a key this deployment does not use.</summary>
    private async Task<string> WriteUnreadableRecordAsync(Deployment deployment)    {
        var writer = new FileMutableSlotStore(deployment.StateRoot, "/api", Enumerable.Repeat((byte)0x5A, 32).ToArray());
        await writer.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", ScopeFingerprint, 1, 0, "CANARY-unreadable-3c9d"),
            TestContext.Current.CancellationToken);
        return Assert.Single(Directory.GetFiles(deployment.StateRoot, "*.rstate"));
    }

    private async Task<CommandOutcome> RunAsync(Deployment deployment, params string[] args)        => await HostCommands.RunAsync(
            [.. args, .. deployment.Arguments()],
            Identity,
            TestContext.Current.CancellationToken,
            progress: null,
            outcomes: _log);

    /// <summary>
    /// Arguments for a <em>real</em> CLI subprocess: the verb, its targets and the deployment's
    /// configuration switches, in one place so a process-level test cannot drift from an
    /// in-process one.
    /// </summary>
    private static string[] ProcessArguments(Deployment deployment, string verb, params string[] targets)
        => [.. new[] { "auth", verb }, .. targets, .. deployment.Arguments()];

    private Deployment CreateDeployment(string manifestText, byte[]? key = null)
    {
        string manifestDirectory = NewDirectory("manifest");
        File.WriteAllText(Path.Combine(manifestDirectory, "manifest.json"), manifestText);
        string stateRoot = NewDirectory("state");
        string storeRoot = NewDirectory("files");
        string keyDirectory = NewDirectory("key");
        string keyFile = Path.Combine(keyDirectory, "state.key");
        File.WriteAllBytes(keyFile, key ?? FixtureKey());
        return new Deployment(manifestDirectory, stateRoot, storeRoot, keyFile);
    }

    private string NewDirectory(string name)
    {
        string path = Path.Combine(_root, name + "-" + (++_sequence).ToString(CultureInfo.InvariantCulture));
        Directory.CreateDirectory(path);
        return path;
    }

    private static byte[] FixtureKey()
        => Enumerable.Range(0, 32).Select(index => (byte)index).ToArray();

    private static string RevocationEndpoint(Uri serverAddress) => serverAddress + "revoke";

    /// <summary>The in-code twin of one manifest profile, so a seeded decision binds exactly like the Manifest's.</summary>
    private static AuthenticationProfile ProfileModel(string id, Uri? serverAddress, string? revocationEndpoint)
    {
        string authority = serverAddress?.GetLeftPart(UriPartial.Authority) ?? "https://auth.example.com:443";

        return new AuthenticationProfile(
            id,
            AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
            CanonicalJson.Parse(Encoding.UTF8.GetBytes($$"""
                {"strategyId":"oauth2-authorization-code-pkce-refresh",
                 "clientId":"test-client", "tokenAuthMethod":"none",
                 "authorizationEndpoint":"{{authority}}/authorize",
                 "tokenEndpoint":"{{authority}}/token"{{(revocationEndpoint is null ? string.Empty : ",\n \"revocationEndpoint\":\"" + revocationEndpoint + "\"")}}}
                """))!.AsObject(),
            [authority],
            [authority],
            ["oauth-refresh"],
            ScopeFingerprint,
            [new AuthenticationSlot("refreshToken", 1, 0)]);
    }

    private static MutableSlotDecision Decision(
        string profileId,
        Uri? serverAddress,
        string? revocationEndpoint,
        MutableSlotDecisionKind kind,
        long epoch,
        long revision,
        string? refresh)
    {
        AuthenticationProfile profile = ProfileModel(profileId, serverAddress, revocationEndpoint);

        return new MutableSlotDecision(
            profileId,
            "refreshToken",
            ScopeFingerprint,
            AuthorityBinding.Declaration(profile),
            AuthorityBinding.Configuration(OAuthStrategyConfiguration.FromConfiguration(
                profile.Configuration, authorizationCodeRequired: true)),
            epoch,
            revision,
            kind,
            refresh);
    }

    private static string ProfileJson(string id, string? revocationEndpoint, Uri? serverAddress = null)
    {
        string authority = serverAddress?.GetLeftPart(UriPartial.Authority) ?? "https://auth.example.com:443";
        string revocation = revocationEndpoint is null
            ? string.Empty
            : ",\n            \"revocationEndpoint\": \"" + revocationEndpoint + "\"";

        return $$"""
            {
              "id": "{{id}}",
              "kind": "oauth2-authorization-code-pkce-refresh",
              "configuration": {
                "strategyId": "oauth2-authorization-code-pkce-refresh",
                "inputs": { "clientId": "test-client" },
                "clientId": "test-client",
                "tokenAuthMethod": "none",
                "authorizationEndpoint": "{{authority}}/authorize",
                "tokenEndpoint": "{{authority}}/token"{{revocation}}
              },
              "authenticationOrigins": ["{{authority}}"],
              "destinationOrigins": ["{{authority}}"],
              "credentialRef": ["oauth-refresh"],
              "scopeFingerprint": "{{ScopeFingerprint}}",
              "slots": [ { "slot": "refreshToken", "authorityEpoch": 1, "runtimeRevision": 0 } ]
            }
            """;
    }

    /// <summary>A refresh credential that resolves only when inline material is allowed.</summary>
    private static string CredentialInline => $$"""
        {
          "id": "oauth-refresh",
          "scheme": "oauth2-authorization-code",
          "slot": "refreshToken",
          "value": { "inline": "{{InlineCanary}}" }
        }
        """;

    /// <summary>A refresh credential whose environment variable is not set.</summary>
    private const string CredentialUnsetEnv = """
        {
          "id": "oauth-refresh",
          "scheme": "oauth2-authorization-code",
          "slot": "refreshToken",
          "value": { "fromEnv": "MCPILER_OPS_UNSET_REFRESH" }
        }
        """;

    /// <summary>A credential whose slot is not the refresh slot, so the profile declares no refresh authority.</summary>
    private const string CredentialClientSecretOnly = """
        {
          "id": "oauth-refresh",
          "scheme": "oauth2-authorization-code",
          "slot": "clientSecret",
          "value": { "fromEnv": "MCPILER_OPS_UNSET_SECRET" }
        }
        """;

    private static string Manifest(string credentials, string profiles, string profileReferences = "\"oauth\"") => $$"""
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": { "name": "Ops API", "authenticationRequired": false } },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": { "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ] }
            },
            "agentSurface": { "inline": { "operations": [{{Surfaces(profileReferences)}}] } },
            "credentials": { "inline": { "formatVersion": 4, "credentials": [{{credentials}}] } },
            "authentication": { "inline": { "formatVersion": 2, "profiles": [{{profiles}}] } }
          }
        }
        """;

    /// <summary>
    /// One surface per referenced profile: an unreferenced profile is refused rather than silently
    /// unused, so a multi-profile fixture must reference each profile exactly once.
    /// </summary>
    private static string Surfaces(string profileReferences)
        => string.Join(
            ", ",
            profileReferences
                .Split(',', StringSplitOptions.TrimEntries)
                .Select((reference, index) => string.Create(
                    CultureInfo.InvariantCulture,
                    $"{{ \"slug\": \"list-pets-{index}\", \"name\": \"List pets {index}\", \"binding\": {{ \"type\": \"http\", \"operation\": \"GET /pets\", \"authenticationRef\": {reference} }} }}")));

    /// <summary>One deployment's directories, so a test can address the store and the root directly.</summary>
    private sealed record Deployment(string ManifestDirectory, string StateRoot, string StoreRoot, string KeyFile)
    {
        internal string[] Arguments() =>
        [
            "--mount", "/api=" + ManifestDirectory,
            "--file-store-root", StoreRoot,
            "--allow-inline-secrets", "true",
            "--runtime-state-root", StateRoot,
            "--runtime-state-key-file", KeyFile,
        ];
    }
}
