using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Manifest.Model;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// One execution end to end against a real listener: the order of operations, the failure
/// classifications, and what reaches the wire.
/// </summary>
/// <remarks>
/// <para>
/// These tests exist for the claims a substituted transport cannot support. "No request was
/// sent" is one of them: a stub can be asked how many times it was called, but a server that
/// counted zero arrivals is evidence about a socket rather than about a mock's bookkeeping.
/// So are the elapsed-time budget, the streamed size ceiling, and address containment refusing
/// the very loopback address the test suite runs on.
/// </para>
/// <para>
/// Loopback is a denied range, which is the shipped policy working. Tests that need a request
/// to arrive substitute the address judgement through the outbound port rather than weakening
/// the table; the one test that asserts containment uses the shipped policy and expects to be
/// refused.
/// </para>
/// </remarks>
public sealed class ExecutionServiceTests : IDisposable
{
    private const string Canary = "CANARY-a91f7c-upstream-token";

    private readonly List<string> _roots = [];
    private readonly List<string> _variables = [];

    [Fact]
    public async Task A_successful_exchange_returns_the_status_headers_and_body()
    {
        var arrivals = new List<string>();
        await using var host = await StartAsync(async context =>
        {
            arrivals.Add(context.Request.Path + context.Request.QueryString);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            context.Response.Headers["X-Trace"] = "abc";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        var result = await Execute(ExecutionManifests.For(host.Address));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal("application/json", result.ResponseMediaType);
        Assert.Equal("{\"ok\":true}", Encoding.UTF8.GetString(result.ResponseBody!));
        Assert.Equal("abc", result.ResponseHeaders!["X-Trace"].Single());

        // Content headers are in the same map as message headers, which is the only way a
        // caller can see either without holding the transport object open.
        Assert.Contains("Content-Type", result.ResponseHeaders.Keys);
        Assert.Equal(["/thing"], arrivals);
    }

    [Fact]
    public async Task A_missing_required_argument_fails_compilation_without_reaching_the_server()
    {
        var arrivals = 0;
        await using var host = await StartAsync(context =>
        {
            Interlocked.Increment(ref arrivals);
            return context.Response.WriteAsync("unexpected", context.RequestAborted);
        });

        var manifest = ExecutionManifests.For(
            host.Address,
            operation: ExecutionManifests.Operation(
                parameters: [new ManifestParameter("id", ParameterLocation.Query, Required: true)]));

        var result = await Execute(manifest);

        Assert.Equal(ExecutionFailureKind.Compilation, result.Failure);

        // Zero, not "fewer than expected". A compilation refusal that still opened a connection
        // would have told the upstream about a request the product decided not to make.
        Assert.Equal(0, arrivals);
    }

    [Fact]
    public async Task A_binary_response_becomes_a_handle_whose_content_is_byte_identical()
    {
        var payload = RandomNumberGenerator.GetBytes(300_000);
        await using var host = await StartAsync(200, "application/octet-stream", payload);

        var store = NewStore();
        var result = await Execute(ExecutionManifests.For(host.Address), store: store);

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Null(result.ResponseBody);
        Assert.NotNull(result.ResponseFile);
        Assert.Equal(payload.Length, result.ResponseFile!.Length);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(payload)), result.ResponseFile.ContentHash);

        var lookup = await store.OpenAsync(result.ResponseFile.Id, TestContext.Current.CancellationToken);
        await using var content = lookup.Content!;

        using var buffer = new MemoryStream();
        await content.CopyToAsync(buffer, TestContext.Current.CancellationToken);

        Assert.Equal(payload, buffer.ToArray());
    }

    [Fact]
    public async Task A_declared_binary_response_with_no_stated_type_is_still_stored()
    {
        var payload = RandomNumberGenerator.GetBytes(64);
        await using var host = await StartAsync(async context =>
        {
            context.Response.StatusCode = 200;
            context.Response.ContentLength = payload.Length;
            await context.Response.Body.WriteAsync(payload, context.RequestAborted);
        });

        // Nothing observed, so the contract answers — read at the status that arrived.
        var manifest = ExecutionManifests.For(
            host.Address,
            operation: ExecutionManifests.Operation(
                responses: ExecutionManifests.Declares("200", "application/pdf")));

        var result = await Execute(manifest, store: NewStore());

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.NotNull(result.ResponseFile);
    }

    [Fact]
    public async Task A_declaration_under_an_unrelated_status_does_not_classify_the_response()
    {
        await using var host = await StartAsync(async context =>
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"error\":\"bad\"}", context.RequestAborted);
        });

        // application/pdf on 200 and nothing else. A 400 arriving must not be stored as a file
        // because of a declaration describing a response that did not happen.
        var manifest = ExecutionManifests.For(
            host.Address,
            operation: ExecutionManifests.Operation(
                responses: ExecutionManifests.Declares("200", "application/pdf")));

        var result = await Execute(manifest, store: NewStore());

        Assert.Equal(400, result.StatusCode);
        Assert.Null(result.ResponseFile);
        Assert.Equal("{\"error\":\"bad\"}", Encoding.UTF8.GetString(result.ResponseBody!));
    }

    [Fact]
    public async Task A_response_over_the_ceiling_fails_with_the_status_and_headers_preserved()
    {
        await using var host = await StartAsync(200, "text/plain", RandomNumberGenerator.GetBytes(8192));

        var result = await Execute(ExecutionManifests.For(
            host.Address,
            ExecutionLimits.Default with { UpstreamResponseSizeLimitBytes = 1024 }));

        Assert.Equal(ExecutionFailureKind.ResponseSize, result.Failure);

        // Everything observed before the ceiling was reached is still true, and it is the only
        // evidence about what the upstream was answering.
        Assert.Equal(200, result.StatusCode);
        Assert.Equal("text/plain", result.ResponseMediaType);
        Assert.NotNull(result.ResponseHeaders);
    }

    [Fact]
    public async Task A_binary_response_over_the_ceiling_fails_as_a_response_size_refusal()
    {
        await using var host = await StartAsync(200, "application/octet-stream", RandomNumberGenerator.GetBytes(8192));

        var store = NewStore();
        var result = await Execute(
            ExecutionManifests.For(host.Address, ExecutionLimits.Default with { UpstreamResponseSizeLimitBytes = 1024 }),
            store: store);

        // How large a response was allowed to be is a different question from how large a
        // payload the store will keep. Only the outer one classifies here.
        Assert.Equal(ExecutionFailureKind.ResponseSize, result.Failure);
        Assert.Null(result.ResponseFile);
        Assert.Empty(Directory.GetFiles(store.Root));
    }

    [Fact]
    public async Task A_redirect_to_a_disallowed_origin_is_refused()
    {
        await using var host = await StartAsync(context =>
        {
            context.Response.StatusCode = 302;
            context.Response.Headers.Location = "http://127.0.0.1:9/elsewhere";
            return Task.CompletedTask;
        });

        var result = await Execute(ExecutionManifests.For(host.Address));

        Assert.Equal(ExecutionFailureKind.OriginPolicy, result.Failure);
    }

    [Fact]
    public async Task A_chain_longer_than_the_hop_limit_is_refused_as_a_hop_limit_breach()
    {
        var arrivals = 0;
        await using var host = await StartAsync(context =>
        {
            Interlocked.Increment(ref arrivals);
            context.Response.StatusCode = 302;
            context.Response.Headers.Location = "/next";
            return Task.CompletedTask;
        });

        var result = await Execute(ExecutionManifests.For(
            host.Address,
            ExecutionLimits.Default with { RedirectHopLimit = 2 }));

        Assert.Equal(ExecutionFailureKind.RedirectLimit, result.Failure);
        Assert.Equal(3, arrivals);
    }

    [Fact]
    public async Task A_slow_upstream_exhausts_the_whole_exchange_budget()
    {
        await using var host = await StartAsync(async context =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), context.RequestAborted);
            await context.Response.WriteAsync("late", context.RequestAborted);
        });

        var result = await Execute(ExecutionManifests.For(
            host.Address,
            ExecutionLimits.Default with { UpstreamRequestTimeout = TimeSpan.FromMilliseconds(250) }));

        // Not a transport failure and not a redirect-limit failure. The budget expiring is its
        // own finding, and confusing it with either would send an operator to the wrong setting.
        Assert.Equal(ExecutionFailureKind.Timeout, result.Failure);
    }

    [Fact]
    public async Task A_chain_of_individually_fast_hops_still_exhausts_the_budget()
    {
        await using var host = await StartAsync(async context =>
        {
            await Task.Delay(TimeSpan.FromMilliseconds(120), context.RequestAborted);
            context.Response.StatusCode = 302;
            context.Response.Headers.Location = "/next";
        });

        // Each hop finishes well inside any per-request timeout. Only a budget that spans the
        // chain bounds this at all, which is the distinction the requirement exists for.
        var result = await Execute(ExecutionManifests.For(
            host.Address,
            ExecutionLimits.Default with
            {
                UpstreamRequestTimeout = TimeSpan.FromMilliseconds(400),
                RedirectHopLimit = 50,
            }));

        Assert.Equal(ExecutionFailureKind.Timeout, result.Failure);
    }

    [Fact]
    public async Task A_fast_chain_inside_the_budget_is_not_cut_short()
    {
        await using var host = await StartAsync(context =>
        {
            if (context.Request.Path == "/thing")
            {
                context.Response.StatusCode = 302;
                context.Response.Headers.Location = "/next";
                return Task.CompletedTask;
            }

            return context.Response.WriteAsync("arrived", context.RequestAborted);
        });

        var result = await Execute(ExecutionManifests.For(
            host.Address,
            ExecutionLimits.Default with { UpstreamRequestTimeout = TimeSpan.FromSeconds(10) }));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal("arrived", Encoding.UTF8.GetString(result.ResponseBody!));
    }

    [Fact]
    public async Task An_unresolvable_credential_fails_authentication_without_reaching_the_server()
    {
        var arrivals = 0;
        await using var host = await StartAsync(context =>
        {
            Interlocked.Increment(ref arrivals);
            return context.Response.WriteAsync("unexpected", context.RequestAborted);
        });

        var variable = "MCPILER_TEST_UNSET_" + Guid.NewGuid().ToString("N");
        var operation = ExecutionManifests.Operation();

        var manifest = ExecutionManifests.For(
            host.Address,
            operation: operation,
            binding: new HttpBinding(operation.Key, CredentialRef: ["api"]),
            credentials: new CredentialsSection(
            [
                new ManifestCredential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable)),
            ]));

        var result = await Execute(manifest);

        Assert.Equal(ExecutionFailureKind.Authentication, result.Failure);
        Assert.Contains($"fromEnv:{variable}", result.FailureReason!, StringComparison.Ordinal);
        Assert.Equal(0, arrivals);
    }

    [Fact]
    public async Task A_binding_server_url_outside_the_perimeter_is_refused_before_any_socket()
    {
        var arrivals = 0;
        await using var host = await StartAsync(context =>
        {
            Interlocked.Increment(ref arrivals);
            return context.Response.WriteAsync("unexpected", context.RequestAborted);
        });

        var operation = ExecutionManifests.Operation();
        var manifest = ExecutionManifests.For(
            host.Address,
            operation: operation,
            binding: new HttpBinding(operation.Key, ServerUrl: "https://elsewhere.example.com"));

        var result = await Execute(manifest);

        Assert.Equal(ExecutionFailureKind.OriginPolicy, result.Failure);
        Assert.Equal(0, arrivals);
    }

    [Fact]
    public async Task The_shipped_outbound_policy_refuses_the_loopback_address()
    {
        var arrivals = 0;
        await using var host = await StartAsync(context =>
        {
            Interlocked.Increment(ref arrivals);
            return context.Response.WriteAsync("unexpected", context.RequestAborted);
        });

        // The shipped judgement, deliberately. Every other test here substitutes it because an
        // in-process server can only live in a denied range; this one proves the range is
        // denied, so the substitution elsewhere is a test affordance rather than a hole.
        using var clients = new UpstreamClientFactory(new OutboundConnectionPolicy());
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver());

        var result = await service.ExecuteAsync(
            new ExecutionRequest(ExecutionManifests.For(host.Address), ExecutionManifests.Slug, []),
            TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionFailureKind.AddressPolicy, result.Failure);
        Assert.Contains("127.0.0.1", result.FailureReason!, StringComparison.Ordinal);
        Assert.Equal(0, arrivals);
    }

    [Fact]
    public async Task A_resolved_credential_reaches_the_upstream_and_appears_in_no_diagnostic()
    {
        var received = new List<string?>();
        await using var host = await StartAsync(context =>
        {
            received.Add(context.Request.Headers.Authorization);
            context.Response.StatusCode = 302;
            context.Response.Headers.Location = "/next";
            return Task.CompletedTask;
        });

        var variable = SetVariable(Canary);
        var operation = ExecutionManifests.Operation();

        var manifest = ExecutionManifests.For(
            host.Address,
            ExecutionLimits.Default with { RedirectHopLimit = 1 },
            operation: operation,
            binding: new HttpBinding(operation.Key, CredentialRef: ["api"]),
            credentials: new CredentialsSection(
            [
                new ManifestCredential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable)),
            ]));

        var result = await Execute(manifest);

        // Applied: the upstream saw it on every same-origin hop.
        Assert.NotEmpty(received);
        Assert.All(received, header => Assert.Equal($"Bearer {Canary}", header));

        // And the whole cycle ended in a failure, which is the path a leak would take.
        Assert.Equal(ExecutionFailureKind.RedirectLimit, result.Failure);
        Assert.DoesNotContain(Canary, result.FailureReason!, StringComparison.Ordinal);

        // The inspectable request is the compiled one. Credentials are applied to a separate
        // value that never becomes part of the result, so a diagnostic surface cannot echo a
        // secret even when someone adds one later.
        Assert.All(
            result.Request!.Headers.Values.SelectMany(values => values),
            value => Assert.DoesNotContain(Canary, value, StringComparison.Ordinal));

        Assert.DoesNotContain(Canary, Describe(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_credential_the_binding_does_not_reference_is_neither_read_nor_sent()
    {
        var received = new List<string?>();
        await using var host = await StartAsync(context =>
        {
            received.Add(context.Request.Headers["X-Unreferenced"]);
            return context.Response.WriteAsync("ok", context.RequestAborted);
        });

        var referenced = SetVariable("used");
        var operation = ExecutionManifests.Operation();

        var manifest = ExecutionManifests.For(
            host.Address,
            operation: operation,
            binding: new HttpBinding(operation.Key, CredentialRef: ["used"]),
            credentials: new CredentialsSection(
            [
                new ManifestCredential("used", CredentialScheme.Header, "X-Used", CredentialReference.Env(referenced)),

                // Points at a variable nothing set. If the resolver read the section rather
                // than the reference list, this manifest could not execute at all.
                new ManifestCredential(
                    "unreferenced",
                    CredentialScheme.Header,
                    "X-Unreferenced",
                    CredentialReference.Env("MCPILER_TEST_NEVER_SET_" + Guid.NewGuid().ToString("N"))),
            ]));

        var result = await Execute(manifest);

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.All(received, header => Assert.True(string.IsNullOrEmpty(header)));
    }

    [Fact]
    public async Task An_operation_the_manifest_does_not_expose_is_a_compilation_refusal()
    {
        await using var host = await StartAsync(200, "text/plain", "ok"u8.ToArray());

        using var clients = new UpstreamClientFactory(Permissive());
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver());

        var result = await service.ExecuteAsync(
            new ExecutionRequest(ExecutionManifests.For(host.Address), "no-such-operation", []),
            TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionFailureKind.Compilation, result.Failure);
    }

    public void Dispose()
    {
        foreach (var variable in _variables)
        {
            Environment.SetEnvironmentVariable(variable, null);
        }

        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Task<LoopbackHost> StartAsync(RequestDelegate handler)
        => LoopbackHost.StartAsync(handler, TestContext.Current.CancellationToken);

    private static Task<LoopbackHost> StartAsync(int statusCode, string mediaType, byte[] body)
        => LoopbackHost.StartAsync(statusCode, mediaType, body, TestContext.Current.CancellationToken);

    /// <summary>
    /// An outbound policy that judges no address, used by the tests that need the request to
    /// arrive.
    /// </summary>
    private static OutboundConnectionPolicy Permissive() => new(_ => false);

    private static async Task<EngineExecutionResult> Execute(
        Manifest.Model.ManifestDocument manifest,
        FileHandleStore? store = null,
        JsonObject? arguments = null)
    {
        using var clients = new UpstreamClientFactory(Permissive());
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver(), store);

        return await service.ExecuteAsync(
            new ExecutionRequest(manifest, ExecutionManifests.Slug, arguments ?? []),
            TestContext.Current.CancellationToken);
    }

    private static string Describe(EngineExecutionResult result)
        => string.Join(
            '\n',
            result.ToString(),
            result.FailureReason ?? string.Empty,
            string.Join('\n', result.ResponseHeaders?.SelectMany(entry => entry.Value) ?? []));

    private FileHandleStore NewStore()
    {
        var root = Path.Combine(Path.GetTempPath(), "mcpiler-exec-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);

        return new FileHandleStore(FileHandleStoreOptions.For(root));
    }

    private string SetVariable(string value)
    {
        var name = "MCPILER_TEST_SECRET_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(name, value);
        _variables.Add(name);
        return name;
    }
}
