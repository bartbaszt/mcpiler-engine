using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Host.Managed;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Sealing;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Runtime.Managed;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Managed;

/// <summary>
/// The managed synchronization lifecycle across a real HTTP boundary: a Platform stand-in that
/// speaks the documented protocol and the product's own client, worker, loader and generation
/// manager.
/// </summary>
/// <remarks>
/// <para>
/// The stand-in is a real listener rather than an injected client, because the properties under
/// test are properties of the exchange: the deployment secret is read from a file, the long poll
/// is bounded, a refusal is a status code, and a delivered generation is unpacked from the bytes a
/// producer actually sent. A fake transport would assert the harness's idea of the protocol.
/// </para>
/// <para>
/// The stand-in never learns a secret from the product and never inspects one: it answers with a
/// generation whose provider value is a canary, and the assertions read the wire requests the
/// product sends back.
/// </para>
/// </remarks>
public sealed class ManagedSynchronizationTests : IAsyncDisposable
{
    private const string SecretCanary = "CANARY-deployment-secret-91ba";
    private const string ProviderKey = "MCPILER_OAUTH2_CLIENT_CREDENTIALS_CLIENTSECRET";
    private const string ProviderValueCanary = "CANARY-provider-value-4d27";

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "mcpiler-managed-sync-" + Guid.NewGuid().ToString("N"));

    private readonly List<ManagedProcess> _processes = [];

    public ManagedSynchronizationTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task An_initial_synchronization_activates_the_delivered_generation_and_serves_it()
    {
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(
            _ => Response.Generation(generation));

        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        // The delivered generation is the one serving: its tool set answers over HTTP.
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/mcp/connector/full"),
            TestContext.Current.CancellationToken);

        Assert.Equal(
            ["list-pets", "add-pet"],
            Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task A_platform_outage_during_initial_synchronization_refuses_to_open_a_listener()
    {
        // A stand-in that accepts the connection and never answers: the bound must end startup
        // rather than let a process claim readiness it cannot serve.
        await using var platform = await PlatformAsync(
            _ => Response.Silent(),
            delay: TimeSpan.FromSeconds(30));

        ManagedInitialSync initial = await SynchronizeInitialAsync(platform);

        Assert.False(initial.Started);
        Assert.NotNull(initial.Refusal);
        Assert.Contains("managed/", initial.Refusal!.Code, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_platform_reporting_nothing_desired_refuses_initial_synchronization()
    {
        await using var platform = await PlatformAsync(_ => Response.NoContent());

        ManagedInitialSync initial = await SynchronizeInitialAsync(platform);

        Assert.False(initial.Started);
        Assert.Equal("managed/initial-generation-absent", initial.Refusal!.Code);
    }

    [Fact]
    public async Task A_no_content_poll_learns_the_platform_epoch_and_the_next_poll_echoes_it()
    {
        await using var platform = await PlatformAsync(_ => Response.NoContent());
        using var client = new ManagedSyncClient(platform.Options());

        var first = await client.PollAsync(
            PollRequest(sequence: 1),
            sessionEpoch: null,
            TestContext.Current.CancellationToken);

        Assert.Equal(ManagedPollOutcome.Unchanged, first.Outcome);
        Assert.Equal(1, first.SessionEpoch);

        var second = await client.PollAsync(
            PollRequest(sequence: 2),
            first.SessionEpoch,
            TestContext.Current.CancellationToken);

        Assert.Equal(ManagedPollOutcome.Unchanged, second.Outcome);
        Assert.Equal(1, second.SessionEpoch);
        Assert.Equal([null, "1"], platform.PollSessionEpochHeaders.Take(2).ToArray());
    }

    [Fact]
    public async Task A_later_generation_is_activated_while_the_previous_one_keeps_serving_until_replaced()
    {
        var first = Generation("g1", ServedManifests.ThreeSurfaces, prefix: "/mcp/connector");
        var second = Generation("g2", ServedManifests.OneSurface, prefix: "/mcp/connector");

        var current = first;
        await using var platform = await PlatformAsync(_ => Response.Generation(current));

        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        // A surface only the first generation serves is reachable before the swap. Both
        // generations serve 'full', so the observable difference is the extra surfaces g1 has.
        using (McpHttpSession readSurface = await McpHttpSession.OpenAsync(
            engine.At("/mcp/connector/read"),
            TestContext.Current.CancellationToken))
        {
            Assert.Contains(
                "list-pets",
                Names(await readSurface.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
        }

        // The Platform now desires the replacement, and the worker picks it up on its next poll.
        current = second;

        await WaitForAsync(() => engine.Worker.ActiveGenerationId == "g2");

        // The replacement serves 'full' but not the surface only the first generation had.
        using (McpHttpSession replacement = await McpHttpSession.OpenAsync(
            engine.At("/mcp/connector/full"),
            TestContext.Current.CancellationToken))
        {
            Assert.Equal(
                ["list-pets", "add-pet"],
                Names(await replacement.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
        }

        using HttpClient http = new();
        using HttpResponseMessage removed = await http.PostAsync(
            engine.At("/mcp/connector/read"),
            new StringContent(
                """{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""",
                Encoding.UTF8,
                "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, removed.StatusCode);
    }

    [Fact]
    public async Task Open_to_protected_without_an_issuer_is_refused_and_keeps_the_open_generation()
    {
        var current = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(current));
        await using ManagedProcess engine = await StartAsync(
            platform,
            allowedHosts: ["mcp.example.test"]);

        current = Generation("g2", ServedManifests.ProtectedOneSurface, prefix: "/mcp/connector");

        await WaitForAsync(
            () =>
            {
                lock (engine.Diagnostics)
                {
                    return engine.Diagnostics.Any(message =>
                        message.Contains("auth/issuer-missing", StringComparison.Ordinal));
                }
            });

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/mcp/connector/full"),
            TestContext.Current.CancellationToken);
        Assert.Equal(
            ["list-pets", "add-pet"],
            Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task Open_to_protected_without_an_allowed_host_is_refused_and_keeps_the_open_generation()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken);

        var current = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(current));
        await using ManagedProcess engine = await StartAsync(
            platform,
            authorization: AuthorizationFor(authorization.Address),
            allowedHosts: []);

        current = Generation("g2", ServedManifests.ProtectedOneSurface, prefix: "/mcp/connector");

        await WaitForAsync(
            () =>
            {
                lock (engine.Diagnostics)
                {
                    return engine.Diagnostics.Any(message =>
                        message.Contains("auth/allowed-host-missing", StringComparison.Ordinal));
                }
            });

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
    }

    [Fact]
    public async Task Open_to_protected_with_issuer_and_allowed_host_activates_and_requires_bearer_authentication()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken);

        var current = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(current));
        await using ManagedProcess engine = await StartAsync(
            platform,
            authorization: AuthorizationFor(authorization.Address));

        current = Generation("g2", ServedManifests.ProtectedOneSurface, prefix: "/mcp/connector");
        await WaitForAsync(() => engine.Worker.ActiveGenerationId == "g2");

        Uri endpoint = engine.At("/mcp/connector/full");
        using (HttpClient anonymous = new())
        using (HttpResponseMessage refused = await anonymous.PostAsync(
            endpoint,
            new StringContent(
                """{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""",
                Encoding.UTF8,
                "application/json"),
            TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        }

        string token = authorization.Mint(endpoint.AbsoluteUri.TrimEnd('/'), string.Empty);
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            endpoint,
            TestContext.Current.CancellationToken,
            bearerToken: token);
        Assert.Equal(
            ["list-pets", "add-pet"],
            Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task Protected_to_open_activates_and_the_new_generation_serves_without_a_bearer()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken);

        var current = Generation("g1", ServedManifests.ProtectedOneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(current));
        await using ManagedProcess engine = await StartAsync(
            platform,
            authorization: AuthorizationFor(authorization.Address));

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        current = Generation("g2", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await WaitForAsync(() => engine.Worker.ActiveGenerationId == "g2");

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/mcp/connector/full"),
            TestContext.Current.CancellationToken);
        Assert.Equal(
            ["list-pets", "add-pet"],
            Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task A_candidate_that_cannot_be_loaded_leaves_the_active_generation_serving()
    {
        var original = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        // A mount whose bundle is not an archive. The loader refuses it whole, so no generation
        // replaces the one already serving.
        var broken = new Dictionary<string, object?>
        {
            ["protocolVersion"] = 2,
            ["generationId"] = "g2",
            ["mounts"] = new[]
            {
                new
                {
                    prefix = "/mcp/connector",
                    bundle = Convert.ToBase64String(Encoding.UTF8.GetBytes("not an archive")),
                    externalResources = new Dictionary<string, string>(StringComparer.Ordinal),
                },
            },
            ["secrets"] = new Dictionary<string, string>(StringComparer.Ordinal),
            ["metadata"] = new { desiredRevisionId = "g2", engineVersion = "fixture" },
            ["kind"] = "generation",
            ["compatibility"] = new
            {
                status = "compatible",
                reasonCode = "compatibility/compatible",
                dimension = "contract",
                descriptorSchemaVersion = 1,
                required = (string?)null,
                supported = (string?)null,
                message = "The Platform requirements and Engine support are compatible.",
            },
            ["diagnostics"] = Array.Empty<object>(),
        };

        var delivering = true;
        var originalBytes = JsonSerializer.SerializeToUtf8Bytes(original);
        var brokenBytes = JsonSerializer.SerializeToUtf8Bytes(broken);

        await using var platform = await PlatformAsync(
            _ => Response.Bytes(delivering ? originalBytes : brokenBytes, isGeneration: true));

        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        // The next poll delivers a candidate the loader refuses. It is refused whole and the
        // generation already serving is untouched.
        delivering = false;

        await Task.Delay(TimeSpan.FromMilliseconds(600), TestContext.Current.CancellationToken);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/mcp/connector/full"),
            TestContext.Current.CancellationToken);

        Assert.Equal(
            ["list-pets", "add-pet"],
            Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task A_malformed_generation_response_is_refused_without_replacing_the_active_generation()
    {
        var original = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        var malformed = new Dictionary<string, object?>
        {
            ["protocolVersion"] = 2,
            ["generationId"] = "g2",
            ["mounts"] = null,
            ["secrets"] = new Dictionary<string, string>(StringComparer.Ordinal),
            ["metadata"] = new { desiredRevisionId = "g2", engineVersion = "fixture" },
            ["kind"] = "generation",
            ["compatibility"] = new
            {
                status = "compatible",
                reasonCode = "compatibility/compatible",
                dimension = "contract",
                descriptorSchemaVersion = 1,
                required = (string?)null,
                supported = (string?)null,
                message = "The Platform requirements and Engine support are compatible.",
            },
            ["diagnostics"] = Array.Empty<object>(),
        };

        var delivering = true;
        var originalBytes = JsonSerializer.SerializeToUtf8Bytes(original);
        var malformedBytes = JsonSerializer.SerializeToUtf8Bytes(malformed);
        await using var platform = await PlatformAsync(
            _ => Response.Bytes(delivering ? originalBytes : malformedBytes, isGeneration: true));
        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
        delivering = false;
        await Task.Delay(TimeSpan.FromMilliseconds(600), TestContext.Current.CancellationToken);
        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
    }

    [Fact]
    public async Task A_response_missing_a_required_member_is_refused_without_replacing_the_active_generation()
    {
        var original = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        var missing = Generation("g2", ServedManifests.OneSurface, prefix: "/mcp/connector");
        missing.Remove("mounts");

        var delivering = true;
        var requests = new System.Collections.Concurrent.ConcurrentQueue<JsonObject>();
        var originalBytes = JsonSerializer.SerializeToUtf8Bytes(original);
        var missingBytes = JsonSerializer.SerializeToUtf8Bytes(missing);
        await using var platform = await PlatformAsync(request =>
        {
            requests.Enqueue(request);
            return Response.Bytes(delivering ? originalBytes : missingBytes, isGeneration: true);
        });
        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
        delivering = false;
        await WaitForAsync(() => requests.Any(request =>
            string.Equals(request["lastCandidateOutcome"]?.GetValue<string>(), "candidate-failed", StringComparison.Ordinal)
            && request["lastCandidateDiagnostics"] is JsonArray diagnostics
            && diagnostics.Count > 0
            && diagnostics[0]?["code"]?.GetValue<string>() == "managed/response-json-invalid"));
        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
    }

    [Fact]
    public async Task A_protocol_v1_generation_is_refused_as_incompatible_and_leaves_g0_active()
    {
        var original = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        var legacy = JsonSerializer.SerializeToNode(
            Generation("g2", ServedManifests.OneSurface, prefix: "/mcp/connector"))!.AsObject();
        legacy["protocolVersion"] = 1;
        foreach (var mountNode in legacy["mounts"]!.AsArray())
        {
            mountNode!.AsObject().Remove("externalResources");
        }

        var deliveringLegacy = false;
        var requests = new ConcurrentQueue<JsonObject>();
        byte[] originalBytes = JsonSerializer.SerializeToUtf8Bytes(original);
        byte[] legacyBytes = Encoding.UTF8.GetBytes(legacy.ToJsonString());
        await using var platform = await PlatformAsync(request =>
        {
            requests.Enqueue(request);
            return Response.Bytes(deliveringLegacy ? legacyBytes : originalBytes, isGeneration: true);
        });
        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
        deliveringLegacy = true;

        await WaitForAsync(() => requests.Any(request =>
            string.Equals(request["lastCandidateOutcome"]?.GetValue<string>(), "candidate-failed", StringComparison.Ordinal)
            && request["lastCandidateDiagnostics"] is JsonArray diagnostics
            && diagnostics.Count > 0
            && diagnostics[0]?["code"]?.GetValue<string>() == "managed/protocol-version-unsupported"));

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
    }

    [Fact]
    public async Task An_unknown_surface_resource_mapping_is_refused_before_activation_and_leaves_g0_active()
    {
        var original = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        var invalid = Generation(
            "g2",
            ServedManifests.OneSurface,
            prefix: "/mcp/connector",
            externalResources: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ghost"] = "https://tunnel.example/v1/mcp/ghost",
            });

        var deliveringInvalid = false;
        var requests = new ConcurrentQueue<JsonObject>();
        await using var platform = await PlatformAsync(request =>
        {
            requests.Enqueue(request);
            return Response.Generation(deliveringInvalid ? invalid : original);
        });
        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
        deliveringInvalid = true;

        await WaitForAsync(() => requests.Any(request =>
            string.Equals(request["lastCandidateOutcome"]?.GetValue<string>(), "candidate-failed", StringComparison.Ordinal)
            && request["lastCandidateDiagnostics"] is JsonArray diagnostics
            && diagnostics.Count > 0
            && diagnostics[0]?["code"]?.GetValue<string>() == "managed/external-resource-surface-unknown"));

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
    }

    [Theory]
    [InlineData("http://tunnel.example/v1/mcp/not-https")]
    [InlineData("/v1/mcp/not-https")]
    [InlineData("https://tunnel.example/v1/mcp/one?channel=main")]
    [InlineData("https://tunnel.example/v1/mcp/one#fragment")]
    [InlineData("https://user:secret@tunnel.example/v1/mcp/one")]
    [InlineData("https://user@tunnel.example/v1/mcp/one")]
    [InlineData("https://user:@tunnel.example/v1/mcp/one")]
    [InlineData("https://:@tunnel.example/v1/mcp/one")]
    [InlineData("https://@tunnel.example/v1/mcp/one")]
    public async Task An_invalid_surface_resource_mapping_is_refused_before_activation_and_leaves_g0_active(string invalidResource)
    {
        var original = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        var invalid = Generation(
            "g2",
            ServedManifests.OneSurface,
            prefix: "/mcp/connector",
            externalResources: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["full"] = invalidResource,
            });

        var deliveringInvalid = false;
        var requests = new ConcurrentQueue<JsonObject>();
        await using var platform = await PlatformAsync(request =>
        {
            requests.Enqueue(request);
            return Response.Generation(deliveringInvalid ? invalid : original);
        });
        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
        deliveringInvalid = true;

        await WaitForAsync(() => requests.Any(request =>
            string.Equals(request["lastCandidateOutcome"]?.GetValue<string>(), "candidate-failed", StringComparison.Ordinal)
            && request["lastCandidateDiagnostics"] is JsonArray diagnostics
            && diagnostics.Count > 0
            && diagnostics[0]?["code"]?.GetValue<string>() == "managed/external-resource-invalid"));

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
    }

    [Fact]
    public async Task A_duplicate_delivery_of_the_active_generation_is_acknowledged_without_a_second_swap()
    {
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        var deliveries = 0;

        await using var platform = await PlatformAsync(_ =>
        {
            Interlocked.Increment(ref deliveries);
            return Response.Generation(generation);
        });

        await using ManagedProcess engine = await StartAsync(platform);

        // The stand-in keeps delivering the same generation; the worker must not rebuild it.
        long afterFirst = engine.Manager.CurrentNumber!.Value;

        await Task.Delay(TimeSpan.FromMilliseconds(600), TestContext.Current.CancellationToken);

        Assert.True(deliveries > 2, $"The stand-in delivered the generation only {deliveries} time(s).");
        Assert.Equal(afterFirst, engine.Manager.CurrentNumber);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/mcp/connector/full"),
            TestContext.Current.CancellationToken);

        Assert.Equal(
            ["list-pets", "add-pet"],
            Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task A_refused_candidate_is_reported_as_received_and_failed_on_the_next_poll()
    {
        var original = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        // A mount whose bundle is not an archive, so the loader refuses the candidate whole.
        var broken = new Dictionary<string, object?>
        {
            ["protocolVersion"] = 2,
            ["generationId"] = "g2",
            ["mounts"] = new[]
            {
                new
                {
                    prefix = "/mcp/connector",
                    bundle = Convert.ToBase64String(Encoding.UTF8.GetBytes("not an archive")),
                    externalResources = new Dictionary<string, string>(StringComparer.Ordinal),
                },
            },
            ["secrets"] = new Dictionary<string, string>(StringComparer.Ordinal),
            ["metadata"] = new { desiredRevisionId = "g2", engineVersion = "fixture" },
            ["kind"] = "generation",
            ["compatibility"] = new
            {
                status = "compatible",
                reasonCode = "compatibility/compatible",
                dimension = "contract",
                descriptorSchemaVersion = 1,
                required = (string?)null,
                supported = (string?)null,
                message = "The Platform requirements and Engine support are compatible.",
            },
            ["diagnostics"] = Array.Empty<object>(),
        };

        var delivering = false;
        var requests = new System.Collections.Concurrent.ConcurrentQueue<JsonObject>();
        var originalBytes = JsonSerializer.SerializeToUtf8Bytes(original);
        var brokenBytes = JsonSerializer.SerializeToUtf8Bytes(broken);

        await using var platform = await PlatformAsync(request =>
        {
            requests.Enqueue(request);
            return Response.Bytes(delivering ? brokenBytes : originalBytes, isGeneration: true);
        });

        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        // The next delivery is the candidate the loader refuses. Engine keeps serving g1.
        delivering = true;

        await WaitForAsync(() => requests.Any(request =>
            string.Equals(request["lastCandidateOutcome"]?.GetValue<string>(), "candidate-failed", StringComparison.Ordinal)));

        // The poll after the refusal must report the receipt AND the failure: the Platform
        // distinguishes "offered and refused" from "never arrived", and the diagnostics are the
        // only non-secret evidence an operator has of why it was refused.
        var reporting = requests.Last(request =>
            string.Equals(request["lastCandidateOutcome"]?.GetValue<string>(), "candidate-failed", StringComparison.Ordinal));

        Assert.Equal("g2", reporting["deliveredGenerationId"]?.GetValue<string>());
        Assert.Equal("g1", reporting["activeGenerationId"]?.GetValue<string>());

        var diagnostics = Assert.IsType<JsonArray>(reporting["lastCandidateDiagnostics"]);
        var diagnostic = Assert.IsType<JsonObject>(Assert.Single(diagnostics));
        Assert.NotEmpty(diagnostic["code"]!.GetValue<string>());
        Assert.NotEmpty(diagnostic["message"]!.GetValue<string>());

        // The report carries a process identity and a monotonically increasing counter, which is
        // what lets the Platform order reports from one process and refuse a delayed one.
        Assert.False(string.IsNullOrWhiteSpace(reporting["engineInstanceId"]?.GetValue<string>()));
        Assert.True(reporting["engineReportSequence"]?.GetValue<long>() > 0);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
    }

    [Fact]
    public async Task A_refused_candidate_is_not_retried_in_a_hot_loop()
    {
        var original = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        var broken = new Dictionary<string, object?>
        {
            ["protocolVersion"] = 2,
            ["generationId"] = "g2",
            ["mounts"] = new[]
            {
                new
                {
                    prefix = "/mcp/connector",
                    bundle = Convert.ToBase64String(Encoding.UTF8.GetBytes("not an archive")),
                    externalResources = new Dictionary<string, string>(StringComparer.Ordinal),
                },
            },
            ["secrets"] = new Dictionary<string, string>(StringComparer.Ordinal),
            ["metadata"] = new { desiredRevisionId = "g2", engineVersion = "fixture" },
            ["kind"] = "generation",
            ["compatibility"] = new
            {
                status = "compatible",
                reasonCode = "compatibility/compatible",
                dimension = "contract",
                descriptorSchemaVersion = 1,
                required = (string?)null,
                supported = (string?)null,
                message = "The Platform requirements and Engine support are compatible.",
            },
            ["diagnostics"] = Array.Empty<object>(),
        };

        var delivering = false;
        var requests = new System.Collections.Concurrent.ConcurrentQueue<JsonObject>();
        var originalBytes = JsonSerializer.SerializeToUtf8Bytes(original);
        var brokenBytes = JsonSerializer.SerializeToUtf8Bytes(broken);

        await using var platform = await PlatformAsync(request =>
        {
            requests.Enqueue(request);
            return Response.Bytes(delivering ? brokenBytes : originalBytes, isGeneration: true);
        });

        await using ManagedProcess engine = await StartAsync(platform);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        delivering = true;

        await WaitForAsync(() => requests.Any(request =>
            string.Equals(request["lastCandidateOutcome"]?.GetValue<string>(), "candidate-failed", StringComparison.Ordinal)));

        // The Platform keeps offering the same desired generation until its state changes, so an
        // unthrottled retry after a refusal would turn one bad candidate into a request storm: a
        // smoke run observed roughly 150 polls per second, each one a full desired-state
        // compilation on the control plane. The bounded backoff must apply instead. This test
        // constructs the worker with a 20-50 ms backoff, whose jitter floor is 25 ms, so three
        // seconds can admit at most about 120 delayed retries; a hot loop admits thousands.
        var seen = requests.Count;

        await Task.Delay(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);

        var added = requests.Count - seen;

        Assert.True(
            added <= 200,
            $"A refused candidate was retried {added} time(s) in three seconds; retries must be bounded by the backoff.");
    }

    [Fact]
    public async Task The_pending_reconciliation_count_is_reported_until_the_platform_accepts_it()
    {
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        var requests = new System.Collections.Concurrent.ConcurrentQueue<JsonObject>();

        await using var platform = await PlatformAsync(request =>
        {
            requests.Enqueue(request);
            return Response.Generation(generation);
        });

        // The Platform refuses the report at first, so the rotation stays queued and the count must
        // keep being reported rather than silently reading as converged.
        platform.OnReconcile = _ => Response.Status(HttpStatusCode.ServiceUnavailable);

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        await using ManagedProcess process = await StartAsync(platform, loader);

        await slots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-client-credentials",
                "clientSecret",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 1,
                "CANARY-rotated-value-7f31"),
            TestContext.Current.CancellationToken);

        process.Worker.RotationCommitted(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            authorityEpoch: 1,
            previousRuntimeRevision: 0,
            runtimeRevision: 1);

        await WaitForAsync(() => requests.Any(request =>
            request["pendingReconciliationCount"]?.GetValue<int>() == 1));

        // The Platform accepts the report, so the queue empties and the count returns to zero.
        platform.OnReconcile = _ => Response.Status(HttpStatusCode.OK, "{\"outcome\":\"recorded\"}");

        await process.Worker.ReconcilePendingAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, process.Worker.PendingReconciliations);

        await WaitForAsync(() => requests.Any(request =>
            request["pendingReconciliationCount"]?.GetValue<int>() == 0));
    }

    [Fact]
    public async Task A_missing_deployment_secret_file_is_a_retryable_fault_not_a_crash()
    {
        await using var platform = await PlatformAsync(_ => Response.Generation(
            Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector")));

        ManagedInitialSync initial = await SynchronizeInitialAsync(platform, secretFileExists: false);

        Assert.False(initial.Started);
        Assert.NotNull(initial.Refusal);
    }

    [Fact]
    public async Task A_committed_rotation_is_reconciled_with_the_platform_after_the_generation_loads()
    {
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        var reconciliations = new List<JsonObject>();

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = body =>
        {
            lock (reconciliations)
            {
                reconciliations.Add(JsonNode.Parse(body)!.AsObject());
            }

            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        await using var process = await StartAsync(platform, loader);

        Assert.Equal("g1", process.Worker.ActiveGenerationId);

        // A committed rotation is a durable record; the queue regenerates its report from it.
        await slots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-client-credentials",
                "clientSecret",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 1,
                "CANARY-rotated-value-5e18"),
            TestContext.Current.CancellationToken);

        process.Worker.RotationCommitted(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            authorityEpoch: 1,
            previousRuntimeRevision: 0,
            runtimeRevision: 1);

        await WaitForAsync(
            () =>
            {
                lock (reconciliations)
                {
                    return reconciliations.Count > 0;
                }
            },
            () =>
            {
                lock (process.Diagnostics)
                {
                    return "No reconciliation arrived. Diagnostics: "
                        + string.Join(" | ", process.Diagnostics);
                }
            });

        JsonObject report;

        lock (reconciliations)
        {
            report = reconciliations[0];
        }

        Assert.Equal("/mcp/connector", report["mount"]!.GetValue<string>());
        Assert.Equal("clientSecret", report["slot"]!.GetValue<string>());
        Assert.Equal(1, report["authorityEpoch"]!.GetValue<long>());
        Assert.Equal(1, report["runtimeRevision"]!.GetValue<long>());
        Assert.Equal("CANARY-rotated-value-5e18", report["value"]!.GetValue<string>());

        await WaitForAsync(() => process.Worker.PendingReconciliations == 0);
    }

    [Fact]
    public async Task An_evicted_pending_rotation_is_recovered_without_a_new_generation_activation()
    {
        var generation = Generation(
            "g1",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            prefix: "/mcp/connector",
            secrets: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            });

        var reconciliations = new List<JsonObject>();

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        // Reconciliation is gated so the worker cannot drain the durable rotation before the overflow
        // evicts it; the test releases the gate once the overflow is in place.
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        platform.OnReconcile = body =>
        {
            lock (reconciliations)
            {
                reconciliations.Add(JsonNode.Parse(body)!.AsObject());
            }

            entered.TrySetResult();
            release.Task.GetAwaiter().GetResult();

            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        // Give the blocker a durable record so its report reaches the reconciliation endpoint (and the
        // gate). An identity with no durable record is dropped without an HTTP call.
        await slots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-client-credentials",
                "blocker",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 1,
                "CANARY-blocker-value-0001"),
            TestContext.Current.CancellationToken);

        // Capacity two: one further distinct identity evicts the oldest queued rotation.
        await using var process = await StartAsync(platform, loader, reconciliationQueueCapacity: 2);

        Assert.Equal("g1", process.Worker.ActiveGenerationId);

        // The durable record is ahead of the delivered generation's declared slot, so a recovery replay
        // re-derives it. The declared identity is the manifest's refreshToken slot; the delivered
        // generation never changes, so only the recovery path - never a new activation - can carry it.
        await slots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-authorization-code-pkce-refresh",
                "refreshToken",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 1,
                "CANARY-recovered-rotation-9c31"),
            TestContext.Current.CancellationToken);

        // A blocker identity keeps the reconciliation loop busy, holding its snapshot, so the durable
        // rotation cannot be drained before the overflow evicts it. It has a record so its report reaches
        // the endpoint, but it is not a declared slot, so a recovery replay never re-derives it.
        process.Worker.RotationCommitted("/mcp/connector", "oauth2-client-credentials", "blocker", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        // Overflow: refreshToken is the oldest queued rotation once unused-a is admitted, so it is
        // evicted and a recovery is requested.
        process.Worker.RotationCommitted("/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        process.Worker.RotationCommitted("/mcp/connector", "oauth2-client-credentials", "unused-a", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        process.Worker.RotationCommitted("/mcp/connector", "oauth2-client-credentials", "unused-b", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);

        release.SetResult();

        await WaitForAsync(
            () =>
            {
                lock (reconciliations)
                {
                    return reconciliations.Any(report =>
                        report.TryGetPropertyValue("slot", out var slot)
                        && slot!.GetValue<string>() == "refreshToken"
                        && report.TryGetPropertyValue("value", out var value)
                        && value!.GetValue<string>() == "CANARY-recovered-rotation-9c31");
                }
            },
            () =>
            {
                lock (process.Diagnostics)
                {
                    return "No recovered reconciliation arrived. Diagnostics: "
                        + string.Join(" | ", process.Diagnostics);
                }
            });

        // No new generation was delivered or activated; the recovery replay used the active one.
        Assert.Equal("g1", process.Worker.ActiveGenerationId);
        await WaitForAsync(() => process.Worker.PendingReconciliations == 0);
    }

    [Fact]
    public async Task Multiple_rotations_before_the_first_reconciliation_converge_in_one_report()
    {
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        var reconciliations = new List<JsonObject>();

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = body =>
        {
            lock (reconciliations)
            {
                reconciliations.Add(JsonNode.Parse(body)!.AsObject());
            }

            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        await using var process = await StartAsync(platform, loader);

        Assert.Equal("g1", process.Worker.ActiveGenerationId);

        // Two sequential rotations commit before any report is sent: the durable record advances
        // 0 -> 1 -> 2 while Platform is still at 0. The report must carry previous=0, revision=2 so
        // Platform accepts them as one transition instead of refusing a revision mismatch (R4.1).
        await slots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-client-credentials",
                "clientSecret",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 2,
                "CANARY-rotated-value-twice"),
            TestContext.Current.CancellationToken);

        process.Worker.RotationCommitted(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            authorityEpoch: 1,
            previousRuntimeRevision: 0,
            runtimeRevision: 1);
        process.Worker.RotationCommitted(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            authorityEpoch: 1,
            previousRuntimeRevision: 1,
            runtimeRevision: 2);

        await WaitForAsync(() =>
        {
            lock (reconciliations)
            {
                return reconciliations.Count > 0;
            }
        });

        JsonObject report;

        lock (reconciliations)
        {
            report = reconciliations[0];
        }

        Assert.Equal(0, report["previousRuntimeRevision"]!.GetValue<long>());
        Assert.Equal(2, report["runtimeRevision"]!.GetValue<long>());
        Assert.Equal("CANARY-rotated-value-twice", report["value"]!.GetValue<string>());

        await WaitForAsync(() => process.Worker.PendingReconciliations == 0);
    }

    [Fact]
    public async Task A_rotation_with_no_durable_record_is_dropped_rather_than_invented()
    {
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        var attempts = 0;

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = _ =>
        {
            Interlocked.Increment(ref attempts);
            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        // No runtime state configured: nothing durably backs a rotation here.
        await using ManagedProcess process = await StartAsync(platform);

        process.Worker.RotationCommitted(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            authorityEpoch: 1,
            previousRuntimeRevision: 0,
            runtimeRevision: 1);

        await WaitForAsync(() => process.Worker.PendingReconciliations == 0);

        Assert.Equal(0, Volatile.Read(ref attempts));
    }

    [Fact]
    public async Task A_rotation_is_queued_and_retried_when_the_platform_cannot_accept_it()
    {
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        var attempts = 0;

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = _ =>
        {
            Interlocked.Increment(ref attempts);
            return Response.Status(HttpStatusCode.ServiceUnavailable);
        };

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        await using ManagedProcess process = await StartAsync(platform, loader);

        await slots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-client-credentials",
                "clientSecret",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 1,
                "CANARY-rotated-value-5e18"),
            TestContext.Current.CancellationToken);

        process.Worker.RotationCommitted(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            authorityEpoch: 1,
            previousRuntimeRevision: 0,
            runtimeRevision: 1);

        await WaitForAsync(() => Volatile.Read(ref attempts) > 0);

        // An undeliverable report stays queued: losing it would lose the only record that the
        // credential rotated.
        await WaitForAsync(() => process.Worker.PendingReconciliations > 0);
    }

    [Fact]
    public async Task A_lost_response_after_a_committed_report_converges_on_an_idempotent_retry()
    {
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        var attempts = 0;

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = _ =>
        {
            // The Platform commits revision 1 on the first delivery, but the response is lost. The
            // redelivered report is recognised idempotently and confirmed, so the engine records the
            // confirmed revision instead of treating the lost response as a terminal divergence (R11.6).
            if (Interlocked.Increment(ref attempts) == 1)
            {
                return Response.Status(HttpStatusCode.ServiceUnavailable);
            }

            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        await using ManagedProcess process = await StartAsync(platform, loader);

        await slots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-client-credentials",
                "clientSecret",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 1,
                "CANARY-rotated-value-5e18"),
            TestContext.Current.CancellationToken);

        process.Worker.RotationCommitted(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            authorityEpoch: 1,
            previousRuntimeRevision: 0,
            runtimeRevision: 1);

        // The first delivery is lost; the retry lands and is confirmed.
        await WaitForAsync(() => Volatile.Read(ref attempts) >= 2);
        await WaitForAsync(() => process.Worker.PendingReconciliations == 0);

        ConfirmationLookup confirmed = loader.ReadConfirmedRevision(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret");

        Assert.Equal(ConfirmationState.Confirmed, confirmed.State);
        Assert.Equal(1, confirmed.Epoch);
        Assert.Equal(1, confirmed.Revision);
    }

    [Fact]
    public async Task A_restarted_process_selects_the_durable_rotation_over_the_delivered_generation()
    {
        // Platform still describes T0 at epoch E: its stored desired state predates the rotation
        // this deployment committed locally.
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));

        string stateRoot = Path.Combine(_root, "state-restart-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-restart-" + Guid.NewGuid().ToString("N"));

        (ManagedGenerationLoader first, FileMutableSlotStore slots) =
            await OpenLoaderWithStateAsync(stateRoot, keyFile);

        await using (await StartAsync(platform, first))
        {
            await slots.ReplaceAsync(
                new MutableSlotRecord(
                    "oauth2-client-credentials",
                    "clientSecret",
                    ScopeFingerprint: null,
                    AuthorityEpoch: 1,
                    RuntimeRevision: 1,
                    "CANARY-durable-rotation-6b40"),
                TestContext.Current.CancellationToken);
        }

        // The restart: a new process, the same state directory and key. What it holds is T1 at
        // epoch E, and that is what it must resolve — never the T0 the Platform still reports.
        first.Dispose();

        (ManagedGenerationLoader restarted, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);

        ManagedSlotSnapshot? durable = await restarted.ReadSlotAsync(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            TestContext.Current.CancellationToken);

        Assert.NotNull(durable);
        Assert.Equal("CANARY-durable-rotation-6b40", durable!.Value);
        Assert.Equal(1, durable.AuthorityEpoch);
        Assert.Equal(1, durable.RuntimeRevision);

        restarted.Dispose();
    }

    [Fact]
    public async Task A_restart_re_derives_the_rotation_it_committed_before_stopping()
    {
        // MTH-ENG-9: a rotation committed locally survives a restart as durable authority and a
        // bounded reconciliation is re-derived from the durable record, without any live
        // RotationCommitted call in the new process.
        string stateRoot = Path.Combine(_root, "state-replay-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-replay-" + Guid.NewGuid().ToString("N"));

        var reconciliations = new List<JsonObject>();

        await using var platform = await PlatformAsync(_ => Response.Generation(
            Generation(
                "g1",
                ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
                prefix: "/mcp/connector",
                secrets: new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                    ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
                })));
        platform.OnReconcile = body =>
        {
            lock (reconciliations)
            {
                reconciliations.Add(JsonNode.Parse(body)!.AsObject());
            }

            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        // First process commits R1 for the declared slot, then stops before reconciling.
        (ManagedGenerationLoader first, FileMutableSlotStore firstSlots) =
            await OpenLoaderWithStateAsync(stateRoot, keyFile);
        await firstSlots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-authorization-code-pkce-refresh",
                "refreshToken",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 1,
                "CANARY-durable-rotation-eng9"),
            TestContext.Current.CancellationToken);
        first.Dispose();

        // Restart: a new process over the same durable state, with no in-memory queue.
        (ManagedGenerationLoader restarted, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        await using var process = await StartAsync(platform, restarted);

        await WaitForAsync(
            () =>
            {
                lock (reconciliations)
                {
                    return reconciliations.Count > 0;
                }
            },
            () =>
            {
                lock (process.Diagnostics)
                {
                    return "No re-derived reconciliation arrived. Diagnostics: "
                        + string.Join(" | ", process.Diagnostics);
                }
            });

        JsonObject report;
        lock (reconciliations)
        {
            report = reconciliations[0];
        }

        Assert.Equal("refreshToken", report["slot"]!.GetValue<string>());
        Assert.Equal(1, report["authorityEpoch"]!.GetValue<long>());
        Assert.Equal(1, report["runtimeRevision"]!.GetValue<long>());
        Assert.Equal("CANARY-durable-rotation-eng9", report["value"]!.GetValue<string>());
    }

    [Fact]
    public async Task A_restart_re_derives_a_multi_rotation_chain_from_the_declared_base()
    {
        // R9.1: the durable record is ahead of the declared generation by more than one revision, so the
        // recovery base must be the declared Platform revision, not record - 1. Platform refuses a base
        // that does not equal its stored revision, and the refused report would be dropped.
        string stateRoot = Path.Combine(_root, "state-multirot-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-multirot-" + Guid.NewGuid().ToString("N"));

        var reconciliations = new List<JsonObject>();

        await using var platform = await PlatformAsync(_ => Response.Generation(
            Generation(
                "g1",
                ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
                prefix: "/mcp/connector",
                secrets: new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                    ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
                })));
        platform.OnReconcile = body =>
        {
            lock (reconciliations)
            {
                reconciliations.Add(JsonNode.Parse(body)!.AsObject());
            }

            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        (ManagedGenerationLoader first, FileMutableSlotStore firstSlots) =
            await OpenLoaderWithStateAsync(stateRoot, keyFile);
        await firstSlots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-authorization-code-pkce-refresh",
                "refreshToken",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 2,
                "CANARY-multirotation-7a11"),
            TestContext.Current.CancellationToken);
        first.Dispose();

        (ManagedGenerationLoader restarted, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        await using var process = await StartAsync(platform, restarted);

        await WaitForAsync(
            () =>
            {
                lock (reconciliations)
                {
                    return reconciliations.Count > 0;
                }
            },
            () =>
            {
                lock (process.Diagnostics)
                {
                    return "No re-derived reconciliation arrived. Diagnostics: "
                        + string.Join(" | ", process.Diagnostics);
                }
            });

        JsonObject report;
        lock (reconciliations)
        {
            report = reconciliations[0];
        }

        Assert.Equal("refreshToken", report["slot"]!.GetValue<string>());
        Assert.Equal(1, report["authorityEpoch"]!.GetValue<long>());
        // Base is the declared generation revision (0), not record - 1 (1): Platform still holds 0.
        Assert.Equal(0, report["previousRuntimeRevision"]!.GetValue<long>());
        Assert.Equal(2, report["runtimeRevision"]!.GetValue<long>());
    }

    [Fact]
    public async Task Reconciliation_messages_carry_the_session_epoch_the_platform_assigned()
    {
        // The Task 8 Platform fence validates the durable session epoch before any secret mutation,
        // so the reconciliation must present the same epoch the poll established.
        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = _ => Response.Bytes(
            JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
            isGeneration: false);

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();
        await using var process = await StartAsync(platform, loader);

        await slots.ReplaceAsync(
            new MutableSlotRecord(
                "oauth2-client-credentials",
                "clientSecret",
                ScopeFingerprint: null,
                AuthorityEpoch: 1,
                RuntimeRevision: 1,
                "CANARY-epoch-header-9a21"),
            TestContext.Current.CancellationToken);

        process.Worker.RotationCommitted(
            "/mcp/connector",
            "oauth2-client-credentials",
            "clientSecret",
            authorityEpoch: 1,
            previousRuntimeRevision: 0,
            runtimeRevision: 1);

        await WaitForAsync(() => !platform.ReconcileSessionEpochHeaders.IsEmpty);

        Assert.Equal("1", platform.ReconcileSessionEpochHeaders.ToArray()[0]);
    }

    [Fact]
    public async Task A_bounded_durable_replay_reports_a_resume_cursor_until_every_candidate_is_inspected()
    {
        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        ManagedGenerationDelivery delivery = DirectDelivery(
            "g1",
            TwoSlotRotatableRefreshSurface(new Uri("https://api.example.com/")),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            });

        ManagedGenerationLoad loaded = loader.Load(delivery);
        Assert.True(loaded.Succeeded, string.Join("; ", loaded.Refusals.Select(refusal => refusal.Message)));
        IReadOnlyList<MountedManifest> mounts = loaded.Generation!.Mounts;

        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 1, "v-refresh"),
            TestContext.Current.CancellationToken);
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "clientSecret", null, 1, 1, "v-secret"),
            TestContext.Current.CancellationToken);

        var reported = new List<string>();
        RotationNotification callback = (mount, profile, slot, epoch, previous, revision, _) =>
        {
            reported.Add(slot);
            return ValueTask.CompletedTask;
        };

        // One candidate per bounded batch: the first batch leaves a resume cursor, so a worker reading only
        // this result must not treat the replay as complete (R10.1).
        DurableReplayBatch first = await loader.ReplayDurableRotationsBatchAsync(
            mounts, callback, startIndex: 0, maxSlots: 1, TestContext.Current.CancellationToken);

        Assert.Single(reported);
        Assert.NotNull(first.NextCursor);
        Assert.False(first.Incomplete);

        DurableReplayBatch second = await loader.ReplayDurableRotationsBatchAsync(
            mounts, callback, startIndex: first.NextCursor!.Value, maxSlots: 1, TestContext.Current.CancellationToken);

        Assert.Equal(2, reported.Count);
        Assert.Null(second.NextCursor);
        Assert.False(second.Incomplete);
    }

    [Fact]
    public async Task An_unreadable_durable_record_marks_the_replay_batch_incomplete()
    {
        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        ManagedGenerationDelivery delivery = DirectDelivery(
            "g1",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            });

        ManagedGenerationLoad loaded = loader.Load(delivery);
        Assert.True(loaded.Succeeded, string.Join("; ", loaded.Refusals.Select(refusal => refusal.Message)));
        IReadOnlyList<MountedManifest> mounts = loaded.Generation!.Mounts;

        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 1, "v-refresh"),
            TestContext.Current.CancellationToken);

        // Corrupt the committed record so the replay cannot read it. A pass that skipped it must report the
        // batch incomplete rather than letting the worker acknowledge recovery (R10.2).
        string record = Directory.GetFiles(slots.Root, "*" + FileMutableSlotStore.RecordExtension).Single();
        byte[] bytes = await File.ReadAllBytesAsync(record, TestContext.Current.CancellationToken);
        bytes[0] ^= 0xFF;
        await File.WriteAllBytesAsync(record, bytes, TestContext.Current.CancellationToken);

        var reported = new List<string>();
        RotationNotification callback = (mount, profile, slot, epoch, previous, revision, _) =>
        {
            reported.Add(slot);
            return ValueTask.CompletedTask;
        };

        DurableReplayBatch batch = await loader.ReplayDurableRotationsBatchAsync(
            mounts, callback, startIndex: 0, maxSlots: 8, TestContext.Current.CancellationToken);

        Assert.Empty(reported);
        Assert.Null(batch.NextCursor);
        Assert.True(batch.Incomplete);
    }

    [Fact]
    public async Task A_recovery_report_bases_on_the_platform_confirmed_revision()
    {
        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        ManagedGenerationLoad loaded = loader.Load(DirectDelivery(
            "g1",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            }));
        Assert.True(loaded.Succeeded, string.Join("; ", loaded.Refusals.Select(refusal => refusal.Message)));
        IReadOnlyList<MountedManifest> mounts = loaded.Generation!.Mounts;

        // The durable record advanced 0 -> 1 -> 2, but the served generation still declares 0. The Platform
        // accepted the 0 -> 1 rotation, so it holds revision 1 for this slot and expects a base of 1: a
        // declared-revision base of 0 would be refused as a mismatch and the newer credential stranded
        // (R10.6).
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 2, "v2"),
            TestContext.Current.CancellationToken);
        loader.RecordConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 1, runtimeRevision: 1);

        var reports = new List<(long Previous, long Revision)>();
        RotationNotification callback = (mount, profile, slot, epoch, previous, revision, _) =>
        {
            reports.Add((previous, revision));
            return ValueTask.CompletedTask;
        };

        await loader.ReplayDurableRotationsBatchAsync(
            mounts, callback, startIndex: 0, maxSlots: 8, TestContext.Current.CancellationToken);

        var report = Assert.Single(reports);
        Assert.Equal(1, report.Previous);
        Assert.Equal(2, report.Revision);
    }

    [Fact]
    public async Task A_replay_does_not_re_report_a_slot_the_platform_already_confirmed()
    {
        (ManagedGenerationLoader loader, FileMutableSlotStore slots) = await OpenLoaderWithStateAsync();

        ManagedGenerationLoad loaded = loader.Load(DirectDelivery(
            "g1",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            }));
        IReadOnlyList<MountedManifest> mounts = loaded.Generation!.Mounts;

        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 2, "v2"),
            TestContext.Current.CancellationToken);
        loader.RecordConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 1, runtimeRevision: 2);

        var reports = new List<string>();
        RotationNotification callback = (mount, profile, slot, epoch, previous, revision, _) =>
        {
            reports.Add(slot);
            return ValueTask.CompletedTask;
        };

        await loader.ReplayDurableRotationsBatchAsync(
            mounts, callback, startIndex: 0, maxSlots: 8, TestContext.Current.CancellationToken);

        Assert.Empty(reports);
    }

    [Fact]
    public async Task A_confirmed_revision_survives_a_restart()
    {
        string stateRoot = Path.Combine(_root, "state-confirm-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-confirm-" + Guid.NewGuid().ToString("N"));

        (ManagedGenerationLoader first, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        first.RecordConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 3, runtimeRevision: 7);
        first.Dispose();

        (ManagedGenerationLoader restarted, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        ConfirmationLookup confirmed = restarted.ReadConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken");

        Assert.Equal(ConfirmationState.Confirmed, confirmed.State);
        Assert.Equal(3, confirmed.Epoch);
        Assert.Equal(7, confirmed.Revision);
    }

    [Fact]
    public async Task A_failed_confirmation_write_is_reported_and_not_read_back()
    {
        string stateRoot = Path.Combine(_root, "state-confirmfail-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-confirmfail-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);

        // Force the journal write to fail: a directory occupying the journal path makes the atomic
        // rename fail, so the confirmation must not be treated as durable (R11.2).
        Directory.CreateDirectory(Path.Combine(stateRoot, "confirmed-revisions.txt"));

        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);

        bool recorded = loader.RecordConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 1, runtimeRevision: 5);

        Assert.False(recorded);
        Assert.Equal(ConfirmationState.NotConfirmed, loader.ReadConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken").State);

        // R11.2: once the fault is gone a later confirmation is durable, so the two sides converge
        // instead of the skipped confirmation silently reappearing as the declared-revision fallback.
        Directory.Delete(Path.Combine(stateRoot, "confirmed-revisions.txt"));
        Assert.True(loader.RecordConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 1, runtimeRevision: 5));
        loader.Dispose();

        (ManagedGenerationLoader restarted, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        ConfirmationLookup confirmed = restarted.ReadConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken");
        Assert.Equal(ConfirmationState.Confirmed, confirmed.State);
        Assert.Equal(5, confirmed.Revision);
        restarted.Dispose();
    }

    // R11.1: a read failure in an early batch must be remembered for the whole replay cycle. With a
    // bounded batch the unreadable slot sits behind the advanced resume cursor; a later clean batch
    // must not acknowledge recovery while that slot was never re-read.
    [Fact]
    public async Task A_read_error_in_an_early_recovery_batch_keeps_recovery_pending_until_the_slot_is_readable()
    {
        var generation = Generation(
            "g1",
            TwoSlotRotatableRefreshSurface(new Uri("https://api.example.com/")),
            prefix: "/mcp/connector",
            secrets: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            });

        var reconciledSlots = new System.Collections.Concurrent.ConcurrentQueue<string>();

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = body =>
        {
            JsonObject report = JsonNode.Parse(body)!.AsObject();
            reconciledSlots.Enqueue(report["slot"]!.GetValue<string>());
            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        string stateRoot = Path.Combine(_root, "state-readfail-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-readfail-" + Guid.NewGuid().ToString("N"));

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) =
            await OpenLoaderWithStateAsync(stateRoot, keyFile);

        // clientSecret has an authoritative record; refreshToken's record is unreadable. Capacity 1 makes
        // the replay bounded: the unreadable candidate is inspected first and the cursor then advances
        // past it, so the later clean batch must not acknowledge recovery (R11.1).
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "clientSecret", null, 1, 1, "v-secret"),
            TestContext.Current.CancellationToken);

        File.WriteAllBytes(
            SlotRecordPath(stateRoot, "oauth2-authorization-code-pkce-refresh", "refreshToken"),
            [0x01, 0x02, 0x03]);

        await using ManagedProcess process = await StartAsync(platform, loader, reconciliationQueueCapacity: 1);

        // Force a recovery request (an overflow eviction) with two synthetic identities that have no
        // durable record, so the reconcile pass ahead of the replay cannot itself fail.
        process.Worker.RotationCommitted("/mcp/connector", "oauth2-authorization-code-pkce-refresh", "syntheticA", 1, 0, 1);
        process.Worker.RotationCommitted("/mcp/connector", "oauth2-authorization-code-pkce-refresh", "syntheticB", 1, 0, 1);

        // The unreadable record keeps recovery pending rather than completing it (R11.1).
        await WaitForAsync(
            () =>
            {
                lock (process.Diagnostics)
                {
                    return process.Diagnostics.Any(message =>
                        message.Contains("recovery remains pending", StringComparison.Ordinal));
                }
            },
            () =>
            {
                lock (process.Diagnostics)
                {
                    return "Recovery was not held pending. Diagnostics: " + string.Join(" | ", process.Diagnostics);
                }
            });

        // A clean later batch must not acknowledge the earlier unreadable candidate. No report
        // can have reached the Platform while the durable record remains corrupt (R11.1).
        Assert.DoesNotContain("refreshToken", reconciledSlots);
        Assert.True(process.Worker.RecoveryRequested);

        // Restore the record once. The live worker owns recovery and may confirm the rotation
        // before an independent replay could inspect it, so observe its actual reconciliation.
        File.Delete(SlotRecordPath(stateRoot, "oauth2-authorization-code-pkce-refresh", "refreshToken"));
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 1, "v-refresh"),
            TestContext.Current.CancellationToken);

        await WaitForAsync(
            () => reconciledSlots.Contains("refreshToken"),
            () => "The restored slot was never reconciled. Pending=" + process.Worker.PendingReconciliations
                + " RecoveryRequested=" + process.Worker.RecoveryRequested);
        await WaitForAsync(
            () => process.Worker.PendingReconciliations == 0 && !process.Worker.RecoveryRequested,
            () => "Recovery did not finish. Pending=" + process.Worker.PendingReconciliations
                + " RecoveryRequested=" + process.Worker.RecoveryRequested);
        ConfirmationLookup confirmed = loader.ReadConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken");
        Assert.Equal(ConfirmationState.Confirmed, confirmed.State);
        Assert.Equal(1, confirmed.Revision);
    }

    // P1-B: a slot whose durable record was unreadable must not be treated as reconciled when a later
    // read returns null during operator repair; it stays pending until the record is read again.
    [Fact]
    public async Task A_recovery_read_error_is_not_resolved_by_a_transient_null_record()
    {
        string stateRoot = Path.Combine(_root, "state-nullrecovery-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-nullrecovery-" + Guid.NewGuid().ToString("N"));

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) =
            await OpenLoaderWithStateAsync(stateRoot, keyFile);

        ManagedGenerationLoad loaded = loader.Load(DirectDelivery(
            "g1",
            TwoSlotRotatableRefreshSurface(new Uri("https://api.example.com/")),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            }));
        Assert.True(loaded.Succeeded);
        IReadOnlyList<MountedManifest> mounts = loaded.Generation!.Mounts;

        var reported = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var rotations = new RotationNotification((_, _, slot, _, _, _, _) =>
        {
            reported.Enqueue(slot);
            return ValueTask.CompletedTask;
        });

        // The refreshToken record is corrupt, so the first pass reads a failure and marks the slot unresolved.
        File.WriteAllBytes(
            SlotRecordPath(stateRoot, "oauth2-authorization-code-pkce-refresh", "refreshToken"),
            [0x01, 0x02, 0x03]);

        var failed = await loader.ReplayDurableRotationsBatchAsync(
            mounts, rotations, startIndex: 0, maxSlots: 10, TestContext.Current.CancellationToken);
        Assert.True(failed.Incomplete);
        Assert.True(loader.HasUnresolvedRecoverySlotsForTest);

        // Operator repair step 1: delete the corrupt record. A read in the gap returns null; the batch must
        // stay incomplete and nothing may be reported for the slot.
        File.Delete(SlotRecordPath(stateRoot, "oauth2-authorization-code-pkce-refresh", "refreshToken"));

        var gap = await loader.ReplayDurableRotationsBatchAsync(
            mounts, rotations, startIndex: 0, maxSlots: 10, TestContext.Current.CancellationToken);
        Assert.True(gap.Incomplete);
        Assert.Empty(reported);

        // Operator repair step 2: write the correct record. The next pass reads it and reconciles the slot.
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 1, "v-refresh"),
            TestContext.Current.CancellationToken);

        var restored = await loader.ReplayDurableRotationsBatchAsync(
            mounts, rotations, startIndex: 0, maxSlots: 10, TestContext.Current.CancellationToken);
        Assert.False(restored.Incomplete);
        Assert.Contains("refreshToken", reported);
    }

    // R13.1: an unreadable confirmation journal must defer the slot, not base a report on the declared

    // revision (which the Platform would refuse as a mismatch).
    [Fact]
    public async Task A_replay_defers_a_slot_while_the_confirmation_journal_is_unreadable()
    {
        string stateRoot = Path.Combine(_root, "state-confirmread-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-confirmread-" + Guid.NewGuid().ToString("N"));

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) =
            await OpenLoaderWithStateAsync(stateRoot, keyFile);

        ManagedGenerationLoad loaded = loader.Load(DirectDelivery(
            "g1",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            }));
        Assert.True(loaded.Succeeded, string.Join("; ", loaded.Refusals.Select(refusal => refusal.Message)));
        IReadOnlyList<MountedManifest> mounts = loaded.Generation!.Mounts;

        // The durable record advanced 0 -> 1 -> 2 and the Platform confirmed revision 1. Write the
        // confirmation durably but never read it through this loader, so the store holds no cached snapshot.
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 2, "v2"),
            TestContext.Current.CancellationToken);
        File.WriteAllText(
            Path.Combine(stateRoot, "confirmed-revisions.txt"),
            ConfirmedRevisionStore.KeyFor("/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken")
            + "\t1\t1\n");

        // The journal becomes temporarily unreadable. A declared-revision base of 0 would be refused.
        Assert.NotNull(loader.ConfirmedJournal);
        Func<string, string[]> original = loader.ConfirmedJournal!.ReadAllLines;
        loader.ConfirmedJournal!.ReadAllLines = _ => throw new IOException("transient confirmation read failure");

        var reports = new List<(long Previous, long Revision)>();
        DurableReplayBatch unreadable = await loader.ReplayDurableRotationsBatchAsync(
            mounts,
            (_, _, _, _, previous, revision, _) =>
            {
                reports.Add((previous, revision));
                return ValueTask.CompletedTask;
            },
            0,
            8,
            TestContext.Current.CancellationToken);

        Assert.True(unreadable.Incomplete);
        Assert.Empty(reports);

        // Once readable, the report bases on the confirmed revision (1), never the declared 0.
        loader.ConfirmedJournal!.ReadAllLines = original;
        DurableReplayBatch recovered = await loader.ReplayDurableRotationsBatchAsync(
            mounts,
            (_, _, _, _, previous, revision, _) =>
            {
                reports.Add((previous, revision));
                return ValueTask.CompletedTask;
            },
            0,
            8,
            TestContext.Current.CancellationToken);

        Assert.False(recovered.Incomplete);
        var report = Assert.Single(reports);
        Assert.Equal(1, report.Previous);
        Assert.Equal(2, report.Revision);
    }

    // R13.2: an unreadable record at the initial activation must not silently finish recovery; the rotation
    // must be reconciled once the record is readable again, without a new generation.
    [Fact]
    public async Task An_unreadable_record_during_initial_activation_is_reconciled_after_it_recovers()
    {
        var generation = Generation(
            "g1",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            prefix: "/mcp/connector",
            secrets: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            });

        var reconciledSlots = new System.Collections.Concurrent.ConcurrentQueue<string>();

        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = body =>
        {
            JsonObject report = JsonNode.Parse(body)!.AsObject();
            reconciledSlots.Enqueue(report["slot"]!.GetValue<string>());
            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        string stateRoot = Path.Combine(_root, "state-initfail-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-initfail-" + Guid.NewGuid().ToString("N"));

        (ManagedGenerationLoader loader, FileMutableSlotStore slots) =
            await OpenLoaderWithStateAsync(stateRoot, keyFile);

        // A locally committed rotation exists, but its record is unreadable at the moment of activation.
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 1, "v-refresh"),
            TestContext.Current.CancellationToken);
        string recordPath = SlotRecordPath(stateRoot, "oauth2-authorization-code-pkce-refresh", "refreshToken");
        byte[] bytes = await File.ReadAllBytesAsync(recordPath, TestContext.Current.CancellationToken);
        bytes[0] ^= 0xFF;
        await File.WriteAllBytesAsync(recordPath, bytes, TestContext.Current.CancellationToken);

        await using ManagedProcess process = await StartAsync(platform, loader);

        // The initial replay marked itself incomplete and requested recovery rather than finishing.
        await WaitForAsync(
            () =>
            {
                lock (process.Diagnostics)
                {
                    return process.Diagnostics.Any(message =>
                        message.Contains("recovery remains pending", StringComparison.Ordinal));
                }
            },
            () =>
            {
                lock (process.Diagnostics)
                {
                    return "The initial replay did not keep recovery pending. Diagnostics: "
                        + string.Join(" | ", process.Diagnostics);
                }
            });

        // Restore the record with no new generation delivered; the cyclic recovery must pick it up. The
        // valid record is built under a fresh store and moved atomically over the corrupt file, so a fast
        // worker cycle never observes the slot as legitimately absent (which would acknowledge recovery).
        byte[] key = File.ReadAllBytes(keyFile);
        string restoreRoot = Path.Combine(_root, "restore-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(restoreRoot);
        var restoreStore = new FileMutableSlotStore(restoreRoot, "/mcp/connector", key);
        await restoreStore.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 1, "v-refresh"),
            TestContext.Current.CancellationToken);
        File.Move(
            SlotRecordPath(restoreRoot, "oauth2-authorization-code-pkce-refresh", "refreshToken"),
            recordPath,
            overwrite: true);

        await WaitForAsync(
            () => reconciledSlots.Contains("refreshToken"),
            () => "The recovered rotation was not reconciled without a new generation. Pending="
                + process.Worker.PendingReconciliations + " RecoveryRequested=" + process.Worker.RecoveryRequested
                + " Diagnostics: " + string.Join(" | ", process.Diagnostics));
    }

    [Fact]
    public async Task Loading_a_generation_does_not_prune_the_confirmation_journal()
    {
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync();

        loader.RecordConfirmedRevision(
            "/mcp/other", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 1, runtimeRevision: 5);
        Assert.Equal(ConfirmationState.Confirmed, loader.ReadConfirmedRevision(
            "/mcp/other", "oauth2-authorization-code-pkce-refresh", "refreshToken").State);

        ManagedGenerationLoad loaded = loader.Load(DirectDelivery(
            "g1",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            }));
        Assert.True(loaded.Succeeded, string.Join("; ", loaded.Refusals.Select(refusal => refusal.Message)));

        // Preparing a candidate must not mutate the running generation's durable state: the worker can
        // still refuse it in host validation, and the confirmation must survive (R12.2).
        Assert.Equal(ConfirmationState.Confirmed, loader.ReadConfirmedRevision(
            "/mcp/other", "oauth2-authorization-code-pkce-refresh", "refreshToken").State);

        // Pruning is an activation-time side effect. Applied with the active mounts it drops the stale
        // identity (R11.7/R12.2).
        loader.PruneConfirmedRevisions(loaded.Generation!.Mounts);
        Assert.Equal(ConfirmationState.NotConfirmed, loader.ReadConfirmedRevision(
            "/mcp/other", "oauth2-authorization-code-pkce-refresh", "refreshToken").State);
    }

    [Fact]
    public async Task A_refused_candidate_does_not_prune_the_confirmation_journal_but_an_activation_does()
    {
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync();

        var secrets = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
            ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
        };

        var current = Generation(
            "g1",
            TwoSlotRotatableRefreshSurface(new Uri("https://api.example.com/")),
            prefix: "/mcp/connector",
            secrets: secrets);
        await using var platform = await PlatformAsync(_ => Response.Generation(current));
        await using ManagedProcess engine = await StartAsync(
            platform,
            providedLoader: loader,
            allowedHosts: ["mcp.example.test"]);

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        // One confirmation the active generation declares and one it does not.
        Assert.True(engine.Loader.RecordConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 1, runtimeRevision: 1));
        Assert.True(engine.Loader.RecordConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "clientSecret", authorityEpoch: 1, runtimeRevision: 5));

        // A candidate the host refuses (protected, no issuer) must leave the running generation's
        // confirmation journal untouched (R12.2).
        current = Generation("g2", ServedManifests.ProtectedOneSurface, prefix: "/mcp/connector");
        await WaitForAsync(
            () =>
            {
                lock (engine.Diagnostics)
                {
                    return engine.Diagnostics.Any(message =>
                        message.Contains("auth/issuer-missing", StringComparison.Ordinal));
                }
            });

        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
        Assert.Equal(ConfirmationState.Confirmed, engine.Loader.ReadConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "clientSecret").State);

        // A candidate that activates and no longer declares the clientSecret slot prunes only that
        // identity; the slot it still declares keeps its confirmation (R12.2/R11.7).
        current = Generation(
            "g3",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            prefix: "/mcp/connector",
            secrets: secrets);
        await WaitForAsync(() => engine.Worker.ActiveGenerationId == "g3");

        Assert.Equal(ConfirmationState.Confirmed, engine.Loader.ReadConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken").State);
        Assert.Equal(ConfirmationState.NotConfirmed, engine.Loader.ReadConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "clientSecret").State);
    }

    // R16.7 / MTH-HEALTH-1: an absent or valid confirmation journal reports the managed health surface 200.
    [Fact]
    public async Task Managed_health_is_ok_with_an_absent_or_valid_confirmation_journal()
    {
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync();

        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        await using ManagedProcess engine = await StartAsync(platform, providedLoader: loader);

        using var http = new HttpClient();

        HttpResponseMessage absent = await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token);
        Assert.Equal(HttpStatusCode.OK, absent.StatusCode);
        Assert.Equal("ok\n", await absent.Content.ReadAsStringAsync(Token));

        Assert.True(engine.Loader.RecordConfirmedRevision(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken", authorityEpoch: 1, runtimeRevision: 1));
        HttpResponseMessage valid = await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        Assert.Equal("ok\n", await valid.Content.ReadAsStringAsync(Token));
    }

    // R16.5 / R16.7 / MTH-HEALTH-2: a checksum-mismatch journal and, separately, a zero-length journal put
    // the managed health surface at 503; the body names the integrity failure and the operator action, and
    // carries no journal path, identity or secret material. The worker emits the degraded diagnostic
    // exactly once per state.
    [Theory]
    [InlineData("checksum")]
    [InlineData("empty")]
    public async Task Managed_health_reports_a_degraded_confirmation_journal(string kind)
    {
        string stateRoot = Path.Combine(_root, "state-health-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-health-" + Guid.NewGuid().ToString("N"));
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);

        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        if (kind == "checksum")
        {
            // R18.3(b): a real record under a wrong checksum, so the body assertions can prove the 503
            // carries neither the checksum text, nor the slot identity, nor the revision.
            string record = ConfirmedRevisionStore.KeyFor(
                    "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken")
                + "\t1\t424242\n";
            File.WriteAllText(journal, "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n" + record);
        }
        else
        {
            File.WriteAllBytes(journal, []);
        }

        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        await using ManagedProcess engine = await StartAsync(platform, providedLoader: loader);

        await WaitForAsync(
            () => DiagnosticsContaining(engine, "failed its integrity check") == 1,
            () => "Diagnostics: " + string.Join(" | ", engine.Diagnostics));
        Assert.DoesNotContain(engine.Diagnostics, message => message.Contains(SecretCanary, StringComparison.Ordinal));
        Assert.DoesNotContain(engine.Diagnostics, message => message.Contains(stateRoot, StringComparison.Ordinal));

        using var http = new HttpClient();
        HttpResponseMessage response = await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token);
        string body = await response.Content.ReadAsStringAsync(Token);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("integrity", body, StringComparison.Ordinal);
        Assert.Contains("confirmed-revisions reset", body, StringComparison.Ordinal);
        Assert.DoesNotContain(stateRoot, body, StringComparison.Ordinal);
        Assert.DoesNotContain("g1", body, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretCanary, body, StringComparison.Ordinal);
        Assert.DoesNotContain("DEADBEEF", body, StringComparison.Ordinal);
        Assert.DoesNotContain("refreshToken", body, StringComparison.Ordinal);
        Assert.DoesNotContain("424242", body, StringComparison.Ordinal);
    }

    // R16.7 / MTH-HEALTH-3: while the journal is degraded, readiness and liveness stay 200 with their
    // unchanged bodies and a served tool call still succeeds.
    [Fact]
    public async Task A_degraded_journal_does_not_affect_ready_live_or_serving()
    {
        string stateRoot = Path.Combine(_root, "state-health3-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-health3-" + Guid.NewGuid().ToString("N"));
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        File.WriteAllBytes(Path.Combine(stateRoot, "confirmed-revisions.txt"), []);

        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        await using ManagedProcess engine = await StartAsync(platform, providedLoader: loader);

        using var http = new HttpClient();
        HttpResponseMessage managed = await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token);
        HttpResponseMessage ready = await http.GetAsync(engine.At(HealthEndpoints.ReadyPath), Token);
        HttpResponseMessage live = await http.GetAsync(engine.At(HealthEndpoints.LivePath), Token);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, managed.StatusCode);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.Equal("ready\n", await ready.Content.ReadAsStringAsync(Token));
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal("alive\n", await live.Content.ReadAsStringAsync(Token));

        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/mcp/connector/full"), Token);
        Assert.Equal(["list-pets", "add-pet"], Names(await session.RequestAsync("tools/list", 2, Token)));
    }

    // R16.7 / MTH-HEALTH-4: an injected transient read failure is not an integrity failure, so the managed
    // health surface stays 200.
    [Fact]
    public async Task A_transient_confirmation_read_failure_is_not_reported_as_degraded()
    {
        string stateRoot = Path.Combine(_root, "state-health4-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-health4-" + Guid.NewGuid().ToString("N"));
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        File.WriteAllText(Path.Combine(stateRoot, "confirmed-revisions.txt"), "x\n");
        loader.ConfirmedJournal!.ReadAllLines = _ => throw new IOException("transient read failure");

        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        await using ManagedProcess engine = await StartAsync(platform, providedLoader: loader);

        using var http = new HttpClient();
        HttpResponseMessage response = await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain(
            engine.Diagnostics,
            message => message.Contains("failed its integrity check", StringComparison.Ordinal));
    }

    // R16.7 / MTH-HEALTH-5 / R16.5 obligation 4: a reset performed through a separate store instance, as
    // the CLI does, is observed by the running host without a restart or a new activation; the corrupt
    // journal and its preserved copy are left byte-identical. R18.3(a): the checksum row uses a non-empty
    // integrity-failed journal so the no-write assertions cannot pass vacuously.
    [Theory]
    [InlineData("checksum")]
    [InlineData("empty")]
    public async Task A_reset_while_serving_clears_the_degraded_state_without_restart_or_reactivation(string kind)
    {
        string stateRoot = Path.Combine(_root, "state-health5-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-health5-" + Guid.NewGuid().ToString("N"));
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        if (kind == "checksum")
        {
            // A real body under a wrong checksum: the journal is non-empty, so the no-write assertions
            // below cannot pass vacuously.
            string body = ConfirmedRevisionStore.KeyFor(
                    "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken")
                + "\t1\t424242\n";
            File.WriteAllText(journal, "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n" + body);
        }
        else
        {
            File.WriteAllBytes(journal, []);
        }

        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        await using ManagedProcess engine = await StartAsync(platform, providedLoader: loader);

        using var http = new HttpClient();
        byte[] before = await File.ReadAllBytesAsync(journal, TestContext.Current.CancellationToken);

        // The degraded query observes the failed journal without changing a byte (MTH-HEALTH-5).
        Assert.Equal(
            HttpStatusCode.ServiceUnavailable,
            (await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token)).StatusCode);
        Assert.Equal(before, await File.ReadAllBytesAsync(journal, TestContext.Current.CancellationToken));
        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        // Reset through a second loader over the same root, exactly as the operator CLI does.
        (ManagedGenerationLoader operatorLoader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        string aside;
        using (operatorLoader)
        {
            Assert.Equal(JournalResetOutcome.Reset, operatorLoader.ResetConfirmedJournal(out string? moved));
            aside = moved!;
            Assert.NotNull(aside);
            Assert.False(File.Exists(journal));
            Assert.True(File.Exists(aside), "The corrupt journal bytes are preserved, never deleted.");
            Assert.Equal(before, await File.ReadAllBytesAsync(aside, TestContext.Current.CancellationToken));
        }

        // The running host observes the reset: no restart, no new activation.
        await WaitForAsync(
            () => http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token).GetAwaiter().GetResult().StatusCode
                == HttpStatusCode.OK,
            () => "The running host did not observe the reset of the corrupt journal.");
        Assert.Equal("g1", engine.Worker.ActiveGenerationId);
        Assert.Equal(1, DiagnosticsContaining(engine, "activated generation"));

        // This generation declares no rotatable slot, so the post-reset 200 records nothing: the journal
        // stays absent and the preserved copy still holds the original bytes (MTH-HEALTH-5).
        Assert.False(File.Exists(journal));
        string preserved = Assert.Single(Directory.GetFiles(stateRoot, "confirmed-revisions.txt.failed-*"));
        Assert.Equal(before, await File.ReadAllBytesAsync(preserved, TestContext.Current.CancellationToken));
    }

    // R16.5 obligation 2: a journal that becomes integrity-failed after activation is reported without a
    // new activation, when the cyclic replay or a reconciliation observes it.
    [Fact]
    public async Task A_journal_that_becomes_integrity_failed_after_activation_is_reported_without_reactivation()
    {
        string stateRoot = Path.Combine(_root, "state-health6-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-health6-" + Guid.NewGuid().ToString("N"));
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        File.WriteAllText(journal, "x\n");

        // A transient read failure at activation leaves no cached snapshot, so the next read re-reads the
        // file and can discover a corruption that appeared afterwards.
        Func<string, string[]> productionRead = loader.ConfirmedJournal!.ReadAllLines;
        loader.ConfirmedJournal!.ReadAllLines = _ => throw new IOException("transient read failure");

        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        await using ManagedProcess engine = await StartAsync(platform, providedLoader: loader);

        Assert.DoesNotContain(
            engine.Diagnostics,
            message => message.Contains("failed its integrity check", StringComparison.Ordinal));

        // The fault clears, and the journal on disk is now genuinely corrupt. Restore the production read
        // rather than File.ReadAllLines: the latter's FileShare.Read races this overwrite while the worker
        // holds the journal open on Windows (R18.1).
        loader.ConfirmedJournal!.ReadAllLines = productionRead;
        File.WriteAllText(journal, "corrupt\n");

        await WaitForAsync(
            () => DiagnosticsContaining(engine, "failed its integrity check") >= 1,
            () => "Diagnostics: " + string.Join(" | ", engine.Diagnostics));
        Assert.Equal("g1", engine.Worker.ActiveGenerationId);

        using var http = new HttpClient();
        Assert.Equal(
            HttpStatusCode.ServiceUnavailable,
            (await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token)).StatusCode);
    }

    // R17.2: a degraded serving host whose journal read becomes transiently failing keeps answering 503 and
    // emits no recovery diagnostic. An unknown state is never reported as recovered.
    [Fact]
    public async Task A_degraded_host_whose_journal_read_fails_transiently_stays_degraded()
    {
        string stateRoot = Path.Combine(_root, "state-r172-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-r172-" + Guid.NewGuid().ToString("N"));
        (ManagedGenerationLoader loader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        File.WriteAllText(
            Path.Combine(stateRoot, "confirmed-revisions.txt"),
            "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n");

        var generation = Generation("g1", ServedManifests.OneSurface, prefix: "/mcp/connector");
        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        await using ManagedProcess engine = await StartAsync(platform, providedLoader: loader);

        using var http = new HttpClient();
        Assert.Equal(
            HttpStatusCode.ServiceUnavailable,
            (await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token)).StatusCode);
        await WaitForAsync(
            () => DiagnosticsContaining(engine, "failed its integrity check") >= 1,
            () => "Diagnostics: " + string.Join(" | ", engine.Diagnostics));

        // The journal read now fails transiently. The known failure must persist: the next worker pass and
        // the health probe must both keep reporting degraded. Wait for two polls so at least one complete
        // pass evaluated the journal under the fault (the worker evaluates it before it polls, so a single
        // observed poll can belong to a pass that evaluated before the fault, R18.3(c)).
        int pollsBefore = platform.PollSessionEpochHeaders.Count;
        loader.ConfirmedJournal!.ReadAllLines = _ => throw new IOException("transient read failure");

        await WaitForAsync(
            () => platform.PollSessionEpochHeaders.Count >= pollsBefore + 2,
            () => "The worker did not complete two passes under the transient fault.");
        Assert.Equal(0, DiagnosticsContaining(engine, "reads as valid again"));
        Assert.Equal(
            HttpStatusCode.ServiceUnavailable,
            (await http.GetAsync(engine.At(HealthEndpoints.ManagedPath), Token)).StatusCode);
    }

    // R17.1 / R15.12 obligations 3-4: after an operator reset of an integrity-failed journal, the cyclic
    // recovery bases its report on the declared revision, Record writes a fresh v2 journal, the report is
    // acknowledged and the stall ends — without a new generation or a restart.
    [Theory]
    [InlineData("checksum")]
    [InlineData("empty")]
    public async Task A_reset_of_an_integrity_failed_journal_ends_the_stall_and_reconciles_on_the_declared_base(
        string kind)
    {
        var generation = Generation(
            "g1",
            ServedManifests.RotatableRefreshSurface(new Uri("https://api.example.com/")),
            prefix: "/mcp/connector",
            secrets: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MANAGED_CLIENT_SECRET"] = "client-secret-canary",
                ["MANAGED_REFRESH_TOKEN"] = "declared-refresh",
            });

        var reports = new System.Collections.Concurrent.ConcurrentQueue<JsonObject>();
        await using var platform = await PlatformAsync(_ => Response.Generation(generation));
        platform.OnReconcile = body =>
        {
            reports.Enqueue(JsonNode.Parse(body)!.AsObject());
            return Response.Bytes(
                JsonSerializer.SerializeToUtf8Bytes(new { outcome = "recorded" }),
                isGeneration: false);
        };

        string stateRoot = Path.Combine(_root, "state-r171-" + Guid.NewGuid().ToString("N"));
        string keyFile = Path.Combine(_root, "key-r171-" + Guid.NewGuid().ToString("N"));
        (ManagedGenerationLoader loader, FileMutableSlotStore slots) =
            await OpenLoaderWithStateAsync(stateRoot, keyFile);

        // A locally committed rotation ahead of the declared revision.
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth2-authorization-code-pkce-refresh", "refreshToken", null, 1, 1, "v-refresh"),
            TestContext.Current.CancellationToken);

        // An integrity-failed journal exists before the process starts.
        string journal = Path.Combine(stateRoot, "confirmed-revisions.txt");
        byte[] corruptBytes;
        if (kind == "checksum")
        {
            File.WriteAllText(journal, "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n");
            corruptBytes = await File.ReadAllBytesAsync(journal, TestContext.Current.CancellationToken);
        }
        else
        {
            File.WriteAllBytes(journal, []);
            corruptBytes = [];
        }

        await using ManagedProcess process = await StartAsync(platform, loader);
        Assert.Equal("g1", process.Worker.ActiveGenerationId);

        // While degraded: 503, recovery stays requested, and no report reaches the Platform.
        using var http = new HttpClient();
        Assert.Equal(
            HttpStatusCode.ServiceUnavailable,
            (await http.GetAsync(process.At(HealthEndpoints.ManagedPath), Token)).StatusCode);
        await WaitForAsync(
            () => process.Worker.RecoveryRequested,
            () => "Recovery was not kept pending for the slot behind the integrity-failed journal.");
        Assert.Empty(reports);

        // Reset through a separate loader over the same root and key, as the CLI does.
        (ManagedGenerationLoader operatorLoader, _) = await OpenLoaderWithStateAsync(stateRoot, keyFile);
        string aside;
        using (operatorLoader)
        {
            Assert.Equal(JournalResetOutcome.Reset, operatorLoader.ResetConfirmedJournal(out string? moved));
            aside = moved!;
        }

        // The cyclic recovery now reconciles: exactly one report based on the declared revision (0) with the
        // durable revision (1).
        await WaitForAsync(
            () => !reports.IsEmpty,
            () => "The recovered rotation was not reported. Pending=" + process.Worker.PendingReconciliations
                + " RecoveryRequested=" + process.Worker.RecoveryRequested
                + " Diagnostics: " + string.Join(" | ", process.Diagnostics));
        await WaitForAsync(
            () => process.Worker.PendingReconciliations == 0 && !process.Worker.RecoveryRequested,
            () => "The reconciliation did not complete. Pending=" + process.Worker.PendingReconciliations
                + " RecoveryRequested=" + process.Worker.RecoveryRequested);

        JsonObject report = Assert.Single(reports);
        Assert.Equal("refreshToken", report["slot"]!.GetValue<string>());
        Assert.Equal(0, report["previousRuntimeRevision"]!.GetValue<long>());
        Assert.Equal(1, report["runtimeRevision"]!.GetValue<long>());

        // The journal is a fresh v2 file whose checksum verifies, so a fresh store sees the confirmation.
        string journalText = await File.ReadAllTextAsync(journal, TestContext.Current.CancellationToken);
        Assert.StartsWith("#MCPilerConfirmedRevisions", journalText, StringComparison.Ordinal);
        var fresh = new ConfirmedRevisionStore(stateRoot);
        ConfirmationLookup confirmed = fresh.Lookup(
            "/mcp/connector", "oauth2-authorization-code-pkce-refresh", "refreshToken");
        Assert.Equal(ConfirmationState.Confirmed, confirmed.State);
        Assert.Equal(1, confirmed.Revision);

        // The moved-aside file still holds the original corrupt bytes.
        Assert.True(File.Exists(aside));
        Assert.Equal(corruptBytes, await File.ReadAllBytesAsync(aside, TestContext.Current.CancellationToken));

        Assert.Equal(
            HttpStatusCode.OK,
            (await http.GetAsync(process.At(HealthEndpoints.ManagedPath), Token)).StatusCode);
        Assert.Equal("g1", process.Worker.ActiveGenerationId);
    }

    private static int DiagnosticsContaining(ManagedProcess engine, string text)
    {
        lock (engine.Diagnostics)
        {
            return engine.Diagnostics.Count(message => message.Contains(text, StringComparison.Ordinal));
        }
    }

    private static ManagedGenerationDelivery DirectDelivery(
        string id,
        string manifest,
        IReadOnlyDictionary<string, string> secrets)
        => new(
            id,
            "fixture",
            [new ManagedMountDelivery(
                "/mcp/connector",
                Convert.FromBase64String(Bundle(manifest)),
                new Dictionary<string, string>(StringComparer.Ordinal))],
            secrets);

    /// <summary>
    /// The on-disk path a <see cref="FileMutableSlotStore"/> resolves for one slot identity, so a test
    /// can plant an unreadable record at exactly the location a replay will read (R11.1).
    /// </summary>
    private static string SlotRecordPath(string stateRoot, string profileId, string slot)
    {
        var identity = string.Join('\u001f', "/mcp/connector", profileId, slot);
        var name = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        return Path.Combine(stateRoot, name + FileMutableSlotStore.RecordExtension);
    }

    private static string TwoSlotRotatableRefreshSurface(Uri upstream)
        => ServedManifests.RotatableRefreshSurface(upstream).Replace(
            "{ \"slot\": \"refreshToken\", \"authorityEpoch\": 1, \"runtimeRevision\": 0 }",
            "{ \"slot\": \"refreshToken\", \"authorityEpoch\": 1, \"runtimeRevision\": 0 },\n"
            + "                      { \"slot\": \"clientSecret\", \"authorityEpoch\": 1, \"runtimeRevision\": 0 }",
            StringComparison.Ordinal);

    private async Task<ManagedInitialSync> SynchronizeInitialAsync(        PlatformStandIn platform,
        bool secretFileExists = true)
    {
        ManagedGenerationLoader loader = await OpenLoaderAsync();
        var manager = new EngineGenerationManager(HostMode.Managed);
        HostBinding binding = ManagedBinding();
        var worker = new ManagedSyncWorker(
            platform.Options(secretFileExists),
            loader,
            manager,
            binding,
            "test",
            backoff: new ManagedSyncBackoff(TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(50)));

        try
        {
            return await worker.SynchronizeInitialAsync(TestContext.Current.CancellationToken);
        }
        finally
        {
            worker.Dispose();
            manager.Dispose();
            loader.Dispose();
        }
    }

    private async Task<ManagedProcess> StartAsync(
        PlatformStandIn platform,
        ManagedGenerationLoader? providedLoader = null,
        HostAuthorizationOptions? authorization = null,
        IReadOnlyList<string>? allowedHosts = null,
        int reconciliationQueueCapacity = PendingReconciliationQueue.DefaultMaximumEntries)
    {
        ManagedGenerationLoader loader = providedLoader ?? await OpenLoaderAsync();
        var manager = new EngineGenerationManager(HostMode.Managed);
        var drain = new DrainCoordinator();
        HostBinding binding = ManagedBinding(authorization, allowedHosts);
        List<string> diagnostics = [];
        var worker = new ManagedSyncWorker(
            platform.Options(),
            loader,
            manager,
            binding,
            "test",
            diagnostics: message =>
            {
                lock (diagnostics)
                {
                    diagnostics.Add(message);
                }
            },
            backoff: new ManagedSyncBackoff(TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(50)),
            reconciliationQueueCapacity: reconciliationQueueCapacity);

        ManagedInitialSync initial = await worker.SynchronizeInitialAsync(TestContext.Current.CancellationToken);

        Assert.True(initial.Started, initial.Refusal?.Message);

        WebApplication app = EngineWebHost.BuildManaged(binding, drain, manager, loader.IsConfirmedJournalDegraded);

        await app.StartAsync(TestContext.Current.CancellationToken);

        worker.Start(TestContext.Current.CancellationToken);

        string bound = app.Urls.Count == 1
            ? app.Urls.Single()
            : throw new InvalidOperationException($"Expected one bound address, found {app.Urls.Count}.");

        var process = new ManagedProcess(
            app,
            new Uri(bound, UriKind.Absolute),
            manager,
            worker,
            loader,
            drain);

        process.Diagnostics = diagnostics;
        _processes.Add(process);
        return process;
    }

    private HostBinding ManagedBinding(
        HostAuthorizationOptions? authorization = null,
        IReadOnlyList<string>? allowedHosts = null)
    {
        string fileRoot = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fileRoot);

        int port = ReserveLoopbackPort();
        string authority = $"127.0.0.1:{port}";

        return new HostBinding(
            new RuntimeOptions([], fileRoot),
            new HostListenOptions($"http://{authority}", HostTransport.Http),
            authorization,
            HostLifecycleOptions.Default)
        {
            AllowedHosts = allowedHosts ?? (authorization is null ? [] : [authority]),
        };
    }

    private static int ReserveLoopbackPort() => LoopbackPorts.Reserve();

    private async Task<ManagedGenerationLoader> OpenLoaderAsync()
    {
        string fileRoot = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fileRoot);

        return await Task.FromResult(
            ManagedGenerationLoader.TryOpen(
                new RuntimeOptions([], fileRoot),
                out ManagedGenerationLoader? loader,
                out IReadOnlyList<StartupRefusal> refusals)
                ? loader!
                : throw new InvalidOperationException(
                    "The loader could not be opened: " + string.Join("; ", refusals.Select(item => item.Message))));
    }

    /// <summary>
    /// Opens a loader whose process-scoped runtime state is durable, so a rotation has an
    /// authoritative record to be reported from.
    /// </summary>
    /// <param name="stateRoot">
    /// An existing state directory to reopen, so a restart can be observed over the same bytes.
    /// </param>
    /// <param name="keyFile">The key the existing state was written under.</param>
    private async Task<(ManagedGenerationLoader Loader, FileMutableSlotStore Slots)> OpenLoaderWithStateAsync(
        string? stateRoot = null,
        string? keyFile = null)
    {
        string fileRoot = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));

        stateRoot ??= Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"));
        keyFile ??= Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(fileRoot);
        Directory.CreateDirectory(stateRoot);

        // Reopening an existing state directory must use the key it was written under; a fresh
        // directory gets a deterministic key of its own.
        byte[] key = File.Exists(keyFile)
            ? File.ReadAllBytes(keyFile)
            : new byte[32].Select((_, index) => (byte)(index + 1)).ToArray();

        if (!File.Exists(keyFile))
        {
            File.WriteAllBytes(keyFile, key);
        }

        var options = new RuntimeOptions([], fileRoot)
        {
            RuntimeStateRoot = stateRoot,
            RuntimeStateKeyFile = keyFile,
        };

        bool opened = ManagedGenerationLoader.TryOpen(
            options,
            out ManagedGenerationLoader? loader,
            out IReadOnlyList<StartupRefusal> refusals);

        Assert.True(
            opened,
            "The loader could not be opened: " + string.Join("; ", refusals.Select(item => item.Message)));

        return await Task.FromResult((loader!, new FileMutableSlotStore(stateRoot, "/mcp/connector", key)));
    }

    private async Task<PlatformStandIn> PlatformAsync(
        Func<JsonObject, Response> answer,
        TimeSpan? delay = null)
        => await PlatformStandIn.StartAsync(
            Path.Combine(_root, "secret-" + Guid.NewGuid().ToString("N")),
            answer,
            delay ?? TimeSpan.Zero,
            TestContext.Current.CancellationToken);

    private static HostAuthorizationOptions AuthorizationFor(Uri issuer)
        => new(issuer.AbsoluteUri, HostTokenValidation.Introspection);

    private static Dictionary<string, object?> Generation(
        string id,
        string manifest,
        string prefix,
        string? providerValue = null,
        IReadOnlyDictionary<string, string>? externalResources = null,
        IReadOnlyDictionary<string, string>? secrets = null)
    {
        var bundle = Bundle(manifest);

        var deliveredSecrets = secrets
            ?? (providerValue is null
                ? new Dictionary<string, string>(StringComparer.Ordinal)
                : new Dictionary<string, string>(StringComparer.Ordinal) { [ProviderKey] = providerValue });

        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["protocolVersion"] = 2,
            ["generationId"] = id,
            ["mounts"] = new[]
            {
                new
                {
                    prefix,
                    bundle,
                    externalResources = externalResources
                        ?? new Dictionary<string, string>(StringComparer.Ordinal),
                },
            },
            ["secrets"] = deliveredSecrets,
            ["metadata"] = new { desiredRevisionId = id, engineVersion = "fixture" },
            ["kind"] = "generation",
            ["compatibility"] = new
            {
                status = "compatible",
                reasonCode = "compatibility/compatible",
                dimension = "contract",
                descriptorSchemaVersion = 1,
                required = (string?)null,
                supported = (string?)null,
                message = "The Platform requirements and Engine support are compatible.",
            },
            ["diagnostics"] = Array.Empty<object>(),
        };
    }

    /// <summary>Packs a manifest the way a producer would, through the product's own archive writer.</summary>
    private static string Bundle(string manifest)
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "mcpiler-managed-bundle-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        try
        {
            var document = JsonNode.Parse(manifest)!.AsObject();
            document["manifestFormatVersion"] = "0.3";

            // A single-file bundle: the root document carries every section inline, which is the
            // shape a producer may emit and the one the loader reads with no path resolution.
            File.WriteAllText(Path.Combine(directory, "manifest.json"), document.ToJsonString());

            using var buffer = new MemoryStream();
            ManifestArchiveResult packed = ManifestArchive.Pack(directory, buffer);

            Assert.True(
                packed.Succeeded,
                string.Join("; ", packed.Diagnostics.Select(diagnostic => diagnostic.ToString())));

            return Convert.ToBase64String(buffer.ToArray());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static IEnumerable<string> Names(McpExchange exchange)
        => Tools(exchange).Select(tool => tool!["name"]!.GetValue<string>());

    private static JsonArray Tools(McpExchange exchange)
        => JsonNode.Parse(exchange.Payload)?["result"]?["tools"] as JsonArray
            ?? throw new InvalidOperationException("The payload carried no tool list: " + exchange.Body);

    private async Task WaitForAsync(Func<bool> condition, Func<string>? explain = null)
    {
        for (var attempt = 0; attempt < 200; attempt++)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.Current.CancellationToken);
        }

        Assert.Fail(explain?.Invoke() ?? "The condition was not met within the bounded wait.");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (ManagedProcess process in _processes)
        {
            await process.DisposeAsync();
        }

        // A worker that was inside a poll when its process stopped can still hold a state or
        // credential file open for a moment on Windows. Retry briefly; a directory that survives
        // that is reported, because leaving it would leak a temp artifact silently.
        for (var attempt = 0; attempt < 20 && Directory.Exists(_root); attempt++)
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.Current.CancellationToken);
            }
        }

        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class ManagedProcess : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly DrainCoordinator _drain;

        public ManagedProcess(
            WebApplication app,
            Uri address,
            EngineGenerationManager manager,
            ManagedSyncWorker worker,
            ManagedGenerationLoader loader,
            DrainCoordinator drain)
        {
            _app = app;
            Address = address;
            Manager = manager;
            Worker = worker;
            Loader = loader;
            _drain = drain;
        }

        public Uri Address { get; }

        public EngineGenerationManager Manager { get; }

        public ManagedSyncWorker Worker { get; }

        public ManagedGenerationLoader Loader { get; }

        /// <summary>Worker diagnostics, for attributing an unexpected failure.</summary>
        public List<string> Diagnostics { get; set; } = [];

        public Uri At(string route) => new(Address, route);

        public async ValueTask DisposeAsync()
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            Worker.Dispose();

            try
            {
                await _app.StopAsync(shutdown.Token);
            }
            finally
            {
                await _app.DisposeAsync();
            }

            Manager.Dispose();
            Loader.Dispose();
            _drain.Dispose();
        }
    }

    /// <summary>What the stand-in answers one poll with.</summary>
    private sealed record Response(int StatusCode, byte[]? Body, bool Delay)
    {
        public static Response Generation(Dictionary<string, object?> generation)
            => new(200, JsonSerializer.SerializeToUtf8Bytes(generation), Delay: false);

        public static Response Bytes(byte[] body, bool isGeneration)
            => new(isGeneration ? 200 : 200, body, Delay: false);

        public static Response NoContent() => new(204, null, Delay: false);

        public static Response Silent() => new(200, null, Delay: true);

        public static Response Status(HttpStatusCode status) => new((int)status, null, Delay: false);

        public static Response Status(HttpStatusCode status, string body)
            => new((int)status, Encoding.UTF8.GetBytes(body), Delay: false);
    }

    /// <summary>
    /// A listener that speaks the managed protocol well enough for the product's own client.
    /// </summary>
    private sealed class PlatformStandIn : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly string _secretFile;

        private PlatformStandIn(WebApplication app, Uri address, string secretFile)
        {
            _app = app;
            Address = address;
            _secretFile = secretFile;
        }

        public Uri Address { get; private set; }

        public ConcurrentQueue<string?> PollSessionEpochHeaders { get; } = new();

        /// <summary>Every session-epoch header presented on a reconciliation request, in order.</summary>
        public ConcurrentQueue<string?> ReconcileSessionEpochHeaders { get; } = new();

        /// <summary>Handles a reconciliation report; assigned by the test before the process starts.</summary>
        public Func<string, Response> OnReconcile { get; set; } = _ => Response.Status(HttpStatusCode.ServiceUnavailable);

        public static async Task<PlatformStandIn> StartAsync(
            string secretFile,
            Func<JsonObject, Response> answer,
            TimeSpan delay,
            CancellationToken cancellationToken)
        {
            File.WriteAllText(secretFile, SecretCanary + "\n");

            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                ContentRootPath = AppContext.BaseDirectory,
                EnvironmentName = "Testing",
            });
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");

            WebApplication app = builder.Build();

            // The instance the handler closures capture is the instance returned, so a test that
            // assigns OnReconcile after construction reaches the listener it assigned it on.
            PlatformStandIn standIn = new(app, new Uri("http://127.0.0.1:1"), secretFile);

            app.MapPost("/internal/engine/v1/deployments/{deploymentId}/poll", async context =>
            {
                var body = await ReadAsync(context, cancellationToken);
                JsonObject request = JsonNode.Parse(body)?.AsObject() ?? [];
                var presentedEpoch = context.Request.Headers[ManagedProtocol.SessionEpochHeader].ToString();
                standIn.PollSessionEpochHeaders.Enqueue(
                    string.IsNullOrEmpty(presentedEpoch) ? null : presentedEpoch);

                if (!Authorized(context))
                {
                    context.Response.StatusCode = 401;
                    return;
                }

                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken);
                }

                Response response = answer(request);

                context.Response.StatusCode = response.StatusCode;
                if (response.StatusCode is >= 200 and < 300)
                {
                    context.Response.Headers[ManagedProtocol.SessionEpochHeader] = "1";
                }

                if (response.Body is { } payload)
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.Body.WriteAsync(payload, cancellationToken);
                }
            });

            app.MapPost("/internal/engine/v1/deployments/{deploymentId}/runtime-secrets/reconcile", async context =>
            {
                var body = await ReadAsync(context, cancellationToken);

                if (!Authorized(context))
                {
                    context.Response.StatusCode = 401;
                    return;
                }

                var reconcileEpoch = context.Request.Headers[ManagedProtocol.SessionEpochHeader].ToString();
                standIn.ReconcileSessionEpochHeaders.Enqueue(
                    string.IsNullOrEmpty(reconcileEpoch) ? null : reconcileEpoch);

                Response response = standIn.OnReconcile(body);

                context.Response.StatusCode = response.StatusCode;

                if (response.Body is { } payload)
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.Body.WriteAsync(payload, cancellationToken);
                }
            });

            await app.StartAsync(cancellationToken);

            string bound = app.Urls.Count == 1
                ? app.Urls.Single()
                : throw new InvalidOperationException($"Expected one bound address, found {app.Urls.Count}.");

            standIn.Address = new Uri(bound, UriKind.Absolute);

            return standIn;
        }

        /// <summary>Options pointing the product's client at this stand-in.</summary>
        public ManagedSyncOptions Options(bool secretFileExists = true)
            => new()
            {
                Endpoint = Address,
                DeploymentId = "connector",
                SecretFile = secretFileExists ? _secretFile : _secretFile + ".missing",
                InitialSyncBound = TimeSpan.FromSeconds(3),
                PollBound = TimeSpan.FromSeconds(1),
            };

        public async ValueTask DisposeAsync()
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            await _app.StopAsync(shutdown.Token);
            await _app.DisposeAsync();

            // The product's worker may still be inside a poll that reads the credential file, so a
            // single delete can lose a race on Windows. Retry briefly; a file that survives that is
            // reported rather than ignored, because silently leaking a temp artifact would hide a
            // test that never stopped its worker.
            for (var attempt = 0; attempt < 20 && File.Exists(_secretFile); attempt++)
            {
                try
                {
                    File.Delete(_secretFile);
                }
                catch (IOException)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.Current.CancellationToken);
                }
            }

            File.Delete(_secretFile);
        }

        private static bool Authorized(HttpContext context)
            => context.Request.Headers.Authorization.ToString()
                == $"Bearer {SecretCanary}";

        private static async Task<string> ReadAsync(HttpContext context, CancellationToken cancellationToken)
        {
            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);

            return await reader.ReadToEndAsync(cancellationToken);
        }
    }

    private static ManagedPollRequestMessage PollRequest(long sequence) => new()
    {
        ProtocolVersion = ManagedProtocol.Version,
        EngineVersion = "test-engine",
        SupportedManifestRange = EngineRuntime.SupportedManifestFormatRange,
        PendingReconciliationCount = 0,
        EngineInstanceId = "test-engine-instance",
        EngineReportSequence = sequence,
        Compatibility = CompatibilityDescriptor.EngineSupport(),
    };
}
