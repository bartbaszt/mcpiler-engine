using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Host.Hosting;
using Xunit;

namespace MCPiler.Engine.IntegrationTests.Cli;

/// <summary>
/// Process-level OS lease verification: actual Engine hosts, not a same-process gate.
/// </summary>
public sealed class RuntimeStateOwnerProcessTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "engine-owner-process-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Killed_stdio_owner_can_restart_against_lexically_aliased_store_root()
    {
        string manifest = WriteMinimalManifest();
        string root = Path.Combine(_directory, "runtime-state");
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(Path.Combine(root, "alias-segment"));
        string alias = Path.Combine(root, "alias-segment", "..", ".");
        Assert.Equal(Path.GetFullPath(root), Path.GetFullPath(alias));

        string[] arguments(string storeRoot) =>
            ["serve", "--transport", "stdio", "--file-store-root", storeRoot, "--mount", "/test=" + manifest];

        await using (var first = EngineCliProcess.Start(arguments(root)))
        {
            await first.WaitForStderrLineAsync("stdio", TestContext.Current.CancellationToken);
            Assert.False(first.HasExited);
            await first.KillAndReapAsync(TestContext.Current.CancellationToken);
            Assert.True(first.HasExited);
            EngineCliOutcome transcript = await first.CompleteAsync(TestContext.Current.CancellationToken);
            Assert.Contains("stdio", transcript.Stderr, StringComparison.Ordinal);
        }

        await using (var restarted = EngineCliProcess.Start(arguments(alias)))
        {
            await restarted.WaitForStderrLineAsync("stdio", TestContext.Current.CancellationToken);
            Assert.False(restarted.HasExited);
            await restarted.KillAndReapAsync(TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task Killed_stdio_owner_can_restart_against_symlinked_store_root()
    {
        string manifest = WriteMinimalManifest();
        string root = Path.Combine(_directory, "physical-runtime-state");
        Directory.CreateDirectory(root);
        string alias = Path.Combine(_directory, "physical-store-alias");
        Directory.CreateSymbolicLink(alias, root);
        Assert.Equal(Path.GetFullPath(root),
            Path.GetFullPath(new DirectoryInfo(alias).ResolveLinkTarget(returnFinalTarget: true)!.FullName));

        string[] arguments(string storeRoot) =>
            ["serve", "--transport", "stdio", "--file-store-root", storeRoot, "--mount", "/test=" + manifest];

        await using (var owner = EngineCliProcess.Start(arguments(root)))
        {
            await ExpectReadyAsync(owner);
            Assert.False(owner.HasExited);
            await owner.KillAndReapAsync(TestContext.Current.CancellationToken);
        }

        await using (var successor = EngineCliProcess.Start(arguments(alias)))
        {
            await successor.WaitForStderrLineAsync("stdio", TestContext.Current.CancellationToken);
            Assert.False(successor.HasExited);
            await successor.KillAndReapAsync(TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task Active_owner_refuses_another_process_for_same_root_then_kill_releases_lease()
    {
        string manifest = WriteMinimalManifest();
        string root = Path.Combine(_directory, "exclusive-runtime-state");
        string keyFile = WriteKeyFile();
        Directory.CreateDirectory(Path.Combine(root, "alias-segment"));
        string alias = Path.Combine(root, "alias-segment", "..", ".");

        string[] arguments(string stateRoot) =>
            ["serve", "--transport", "stdio", "--file-store-root", FileStore(),
             "--runtime-state-root", stateRoot, "--runtime-state-key-file", keyFile,
             "--mount", "/test=" + manifest];

        await using (var owner = EngineCliProcess.Start(arguments(root)))
        {
            await owner.WaitForStderrLineAsync("stdio", TestContext.Current.CancellationToken);
            Assert.False(owner.HasExited);

            EngineCliOutcome competitor = await EngineCliProcess.RunAsync(
                TestContext.Current.CancellationToken, arguments(alias));
            Assert.Equal(ExitCodes.Configuration, competitor.ExitCode);
            Assert.Contains("ownership is unavailable or held", competitor.Stdout, StringComparison.Ordinal);
            Assert.DoesNotContain("stdio transport selected", competitor.Stderr, StringComparison.Ordinal);
            Assert.False(owner.HasExited);

            // Same root must not leave a second lock inode or orphan a rename temp.
            Assert.Single(Directory.GetFiles(root, ".runtime-state-owner.lock"));
            await owner.KillAndReapAsync(TestContext.Current.CancellationToken);
        }

        await using (var replacement = EngineCliProcess.Start(arguments(alias)))
        {
            await ExpectReadyAsync(replacement);
            Assert.False(replacement.HasExited);
            await replacement.KillAndReapAsync(TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task Symlink_alias_and_second_mount_cannot_bypass_active_root_owner()
    {
        string manifest = WriteMinimalManifest();
        string root = Path.Combine(_directory, "physical-root");
        Directory.CreateDirectory(root);
        string alias = Path.Combine(_directory, "symlink-root");
        Directory.CreateSymbolicLink(alias, root);
        string keyFile = WriteKeyFile();

        // stdio serves exactly one mounted Manifest, so the competing process selects a different
        // mount under the same physical root: ownership is per root, never per mount.
        string[] arguments(string stateRoot, string mountPrefix) =>
            ["serve", "--transport", "stdio", "--file-store-root", FileStore(),
             "--runtime-state-root", stateRoot, "--runtime-state-key-file", keyFile,
             "--mount", mountPrefix + "=" + manifest];

        await using var owner = EngineCliProcess.Start(arguments(root, "/first"));
        await ExpectReadyAsync(owner);
        Assert.False(owner.HasExited);

        EngineCliOutcome conflict = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken, arguments(alias, "/second"));
        Assert.Equal(ExitCodes.Configuration, conflict.ExitCode);
        Assert.Contains("ownership is unavailable or held", conflict.Stdout, StringComparison.Ordinal);
        Assert.False(owner.HasExited);
        await owner.KillAndReapAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task An_active_serve_owner_refuses_a_real_cli_mutation_before_any_change()
    {
        string manifest = WriteMinimalManifest();
        string authorizationManifest = WriteAuthorizationManifest();
        string root = Path.Combine(_directory, "shared-runtime-state");
        string keyFile = WriteKeyFile();
        Directory.CreateDirectory(root);

        string[] serveArguments =
            ["serve", "--transport", "stdio", "--file-store-root", FileStore(),
             "--runtime-state-root", root, "--runtime-state-key-file", keyFile,
             "--mount", "/test=" + manifest];

        string[] clearArguments =
            ["auth", "clear", "/api", "oauth", "--mount", "/api=" + authorizationManifest,
             "--file-store-root", FileStore(),
             "--runtime-state-root", root, "--runtime-state-key-file", keyFile];

        await using var owner = EngineCliProcess.Start(serveArguments);
        await ExpectReadyAsync(owner);
        Assert.False(owner.HasExited);

        EngineCliOutcome refused = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken, clearArguments);

        Assert.Equal(ExitCodes.Configuration, refused.ExitCode);
        Assert.Contains("ownership is unavailable or held", refused.Stdout, StringComparison.Ordinal);
        Assert.Contains("Stop the serving Engine", refused.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("cleared", refused.Stdout, StringComparison.Ordinal);

        // A refused mutation must not have written an authority record: the root holds only the
        // never-deleted owner lock.
        Assert.Single(Directory.GetFiles(root, ".runtime-state-owner.lock"));
        Assert.Single(Directory.GetFiles(root));
        Assert.False(owner.HasExited);

        await owner.KillAndReapAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Independent_roots_can_serve_concurrently()
    {
        string manifest = WriteMinimalManifest();
        string keyFile = WriteKeyFile();
        string[] arguments(string root) =>
            ["serve", "--transport", "stdio", "--file-store-root", FileStore(),
             "--runtime-state-root", root, "--runtime-state-key-file", keyFile,
             "--mount", "/test=" + manifest];

        await using var first = EngineCliProcess.Start(arguments(Path.Combine(_directory, "root1")));
        await ExpectReadyAsync(first);
        await using var second = EngineCliProcess.Start(arguments(Path.Combine(_directory, "root2")));
        await ExpectReadyAsync(second);
        Assert.False(first.HasExited);
        Assert.False(second.HasExited);
        await first.KillAndReapAsync(TestContext.Current.CancellationToken);
        await second.KillAndReapAsync(TestContext.Current.CancellationToken);
    }

    private string WriteKeyFile()
    {
        string path = Path.Combine(_directory, "key.bin");
        Directory.CreateDirectory(_directory);
        File.WriteAllBytes(path, Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());
        return path;
    }

    /// <summary>
    /// The file store root must exist before serve binds it; a missing directory is a startup
    /// refusal. Every lease case therefore provisions it explicitly.
    /// </summary>
    private string FileStore()
    {
        string path = Path.Combine(_directory, "files");
        Directory.CreateDirectory(path);
        return path;
    }

    private static async Task ExpectReadyAsync(EngineCliProcess child)
    {
        try
        {
            await child.WaitForStderrLineAsync("stdio", TestContext.Current.CancellationToken);
        }
        catch (InvalidOperationException)
        {
            EngineCliOutcome outcome = await child.CompleteAsync(TestContext.Current.CancellationToken);
            // Do not reproduce child output: later fixtures may contain secret canaries.
            throw new InvalidOperationException(
                $"Fixture child exited with code {outcome.ExitCode} before the expected stdio readiness marker. "
                + $"Captured stdout length: {outcome.Stdout.Length}; stderr length: {outcome.Stderr.Length}.");
        }
    }

    private string WriteMinimalManifest()
    {
        string directory = Path.Combine(_directory, "manifest");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), """
            {
              "manifestFormatVersion":"0.3",
              "sections":{
                "server":{"inline":{"name":"Process fixture", "authenticationRequired":false}},
                "policy":{"inline":{"baseUrl":"https://api.example.test"}},
                "operations":{"inline":{"operations":[{"key":"GET /probe", "method":"GET", "path":"/probe"}]}},
                "agentSurface":{"inline":{"operations":[{"slug":"probe", "name":"Probe", "binding":{"type":"http", "operation":"GET /probe"}}]}}
              }
            }
            """);
        return directory;
    }

    /// <summary>
    /// A Manifest with a runtime-owned OAuth refresh slot, so a mutation verb that reached the
    /// store would have something to clear. The credential is declared through the environment,
    /// so the fixture never needs inline-secret permission and never contains a value.
    /// </summary>
    private string WriteAuthorizationManifest()
    {
        string directory = Path.Combine(_directory, "authorization-manifest");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "OAuth API", "authenticationRequired": false } },
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
                        "binding": { "type": "http", "operation": "GET /pets", "authenticationRef": "oauth" }
                      }
                    ]
                  }
                },
                "credentials": {
                  "inline": {
                    "formatVersion": 4,
                    "credentials": [
                      {
                        "id": "oauth-refresh",
                        "scheme": "oauth2-authorization-code",
                        "slot": "refreshToken",
                        "value": { "fromEnv": "MCPILER_TEST_UNUSED_REFRESH" }
                      }
                    ]
                  }
                },
                "authentication": {
                  "inline": {
                    "formatVersion": 2,
                    "profiles": [
                      {
                        "id": "oauth",
                        "kind": "oauth2-authorization-code-pkce-refresh",
                        "configuration": {
                          "strategyId": "oauth2-authorization-code-pkce-refresh",
                          "inputs": { "clientId": "example-client" },
                          "clientId": "example-client",
                          "tokenEndpoint": "https://auth.example.com/oauth2/token",
                          "authorizationEndpoint": "https://auth.example.com/oauth2/authorize",
                          "tokenAuthMethod": "none",
                          "scopes": ["pets.read"],
                          "resource": "https://api.example.com"
                        },
                        "authenticationOrigins": ["https://auth.example.com:443"],
                        "destinationOrigins": ["https://api.example.com:443"],
                        "credentialRef": ["oauth-refresh"],
                        "scopeFingerprint": "0000000000000000000000000000000000000000000000000000000000000001",
                        "slots": [
                          { "slot": "refreshToken", "authorityEpoch": 1, "runtimeRevision": 0 }
                        ]
                      }
                    ]
                  }
                }
              }
            }
            """);
        return directory;
    }
}
