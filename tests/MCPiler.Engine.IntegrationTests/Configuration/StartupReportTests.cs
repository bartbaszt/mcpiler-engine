using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using MCPiler.Engine.Host.Configuration;
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

    [Theory]
    [InlineData(30, "introspection revalidation bound: 30 seconds")]
    [InlineData(7, "introspection revalidation bound: 7 seconds")]
    public void A_started_introspection_report_states_the_effective_positive_bound(
        int ttlSeconds,
        string expected)
    {
        RuntimeStartResult started = StartMinimal();
        HostAuthorizationOptions authorization = new(
            "https://issuer.example.test",
            HostTokenValidation.Introspection)
        {
            IntrospectionCacheTtlSeconds = ttlSeconds,
        };

        string report = StartupReport.Render(started, authorization);

        Assert.Contains(expected, report, StringComparison.Ordinal);
    }

    [Fact]
    public void A_started_introspection_report_states_when_caching_is_disabled()
    {
        RuntimeStartResult started = StartMinimal();
        HostAuthorizationOptions authorization = new(
            "https://issuer.example.test",
            HostTokenValidation.Introspection)
        {
            IntrospectionCacheTtlSeconds = 0,
        };

        string report = StartupReport.Render(started, authorization);

        Assert.Contains(
            "introspection revalidation bound: caching disabled (fresh issuer validation per request)",
            report,
            StringComparison.Ordinal);
    }

    [Fact]
    public void A_jwks_or_unconfigured_report_has_no_introspection_policy_line()
    {
        RuntimeStartResult started = StartMinimal();
        HostAuthorizationOptions jwks = new(
            "https://issuer.example.test",
            HostTokenValidation.Jwks);

        Assert.DoesNotContain(
            "introspection revalidation bound",
            StartupReport.Render(started, jwks),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "introspection revalidation bound",
            StartupReport.Render(started),
            StringComparison.Ordinal);
    }

    [Fact]
    public void File_and_managed_started_reports_share_the_same_authorization_policy_line()
    {
        RuntimeStartResult started = StartMinimal();
        HostAuthorizationOptions authorization = new(
            "https://issuer.example.test",
            HostTokenValidation.Introspection)
        {
            IntrospectionCacheTtlSeconds = 11,
        };

        string expected = StartupReport.RenderAuthorizationPolicy(authorization);

        Assert.Contains(expected, StartupReport.Render(started, authorization), StringComparison.Ordinal);
        Assert.Contains(
            expected,
            StartupReport.RenderManaged("http://127.0.0.1:9000", "generation-1", false, authorization),
            StringComparison.Ordinal);
    }

    private RuntimeStartResult StartMinimal()
    {
        string manifest = Path.Combine(_root, "policy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(manifest);
        File.WriteAllText(Path.Combine(manifest, "manifest.json"), Minimal);

        string store = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(store);

        RuntimeStartResult started = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", manifest)], store));

        Assert.True(started.Started, StartupReport.Render(started));
        return started;
    }

    private const string Minimal = """
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

    /// <summary>
    /// A rotatable credential without the store is a refusal, not a silent degradation.
    /// </summary>
    /// <remarks>
    /// Memory-only serving would look healthy until the first restart after a rotation, at
    /// which point the provider has already invalidated the predecessor. The refusal must name
    /// the settings an operator can act on.
    /// </remarks>
    [Fact]
    public void A_rotatable_credential_without_the_runtime_store_refuses_to_start()
    {
        string manifest = Path.Combine(_root, "refresh");
        Directory.CreateDirectory(manifest);
        File.WriteAllText(Path.Combine(manifest, "manifest.json"), Rotatable);

        string store = Path.Combine(_root, "files");
        Directory.CreateDirectory(store);

        RuntimeStartResult refused = EngineRuntime.Start(new RuntimeOptions([new MountRequest("/api", manifest)], store));

        Assert.False(refused.Started);
        StartupRefusal refusal = Assert.Single(refused.Refusals, entry => entry.Code == "host/runtime-state-required");
        Assert.Equal("/api", refusal.Mount);

        string report = StartupReport.Render(refused);
        Assert.Contains("RuntimeStateRoot", report, StringComparison.Ordinal);
        Assert.Contains("RuntimeStateKeyFile", report, StringComparison.Ordinal);
        Assert.Contains("will not start", report, StringComparison.Ordinal);
    }

    [Fact]
    public void A_rotatable_credential_with_the_runtime_store_starts()
    {
        string manifest = Path.Combine(_root, "refresh-configured");
        Directory.CreateDirectory(manifest);
        File.WriteAllText(Path.Combine(manifest, "manifest.json"), Rotatable);

        string store = Path.Combine(_root, "files-configured");
        Directory.CreateDirectory(store);
        string stateRoot = Path.Combine(_root, "state");
        string keyFile = Path.Combine(_root, "state-key");
        File.WriteAllBytes(keyFile, [.. Enumerable.Range(1, 32).Select(value => (byte)value)]);

        RuntimeStartResult started = EngineRuntime.Start(new RuntimeOptions([new MountRequest("/api", manifest)], store)
        {
            RuntimeStateRoot = stateRoot,
            RuntimeStateKeyFile = keyFile,
        });

        Assert.True(started.Started, StartupReport.Render(started));
        Assert.True(started.DurableRuntimeState);
    }

    [Fact]
    public void A_static_only_manifest_starts_without_the_runtime_store()
    {
        string manifest = Path.Combine(_root, "static-only");
        Directory.CreateDirectory(manifest);
        File.WriteAllText(Path.Combine(manifest, "manifest.json"), Minimal);

        string store = Path.Combine(_root, "files-static");
        Directory.CreateDirectory(store);

        RuntimeStartResult started = EngineRuntime.Start(new RuntimeOptions([new MountRequest("/api", manifest)], store));

        Assert.True(started.Started, StartupReport.Render(started));
        Assert.False(started.DurableRuntimeState);
    }

    private const string Rotatable = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": { "name": "Rotating API" } },
            "policy": {
              "inline": {
                "baseUrl": "https://api.example.com",
                "allowedOrigins": ["https://api.example.com", "https://auth.example.com"]
              }
            },
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
                    "binding": { "type": "http", "operation": "GET /pets", "authenticationRef": "oauth2-authorization-code-pkce-refresh" }
                  }
                ]
              }
            },
            "credentials": {
              "inline": {
                "formatVersion": 3,
                "credentials": [
                  {
                    "id": "oauth2-authorization-refresh-token",
                    "scheme": "oauth2-authorization-code",
                    "slot": "refreshToken",
                    "value": { "fromEnv": "EXAMPLE_REFRESH_TOKEN" }
                  }
                ]
              }
            },
            "authentication": {
              "inline": {
                "formatVersion": 1,
                "profiles": [
                  {
                    "id": "oauth2-authorization-code-pkce-refresh",
                    "kind": "oauth2-authorization-code-pkce-refresh",
                    "configuration": {
                      "strategyId": "oauth2-authorization-code-pkce-refresh",
                      "inputs": { "clientId": "example-client" },
                      "clientId": "example-client",
                      "tokenEndpoint": "https://auth.example.com/oauth2/token",
                      "authorizationEndpoint": "https://auth.example.com/oauth2/authorize",
                      "scopes": ["pets.read"]
                    },
                    "authenticationOrigins": ["https://auth.example.com:443"],
                    "destinationOrigins": ["https://api.example.com:443"],
                    "credentialRef": ["oauth2-authorization-refresh-token"],
                    "slots": [
                      { "slot": "refreshToken", "authorityEpoch": 1, "runtimeRevision": 0 }
                    ]
                  }
                ]
              }
            }
          }
        }
        """;
}
