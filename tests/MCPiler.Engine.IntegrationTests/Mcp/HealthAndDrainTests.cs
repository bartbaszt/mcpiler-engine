using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>Operator health and bounded shutdown behavior on the real HTTP host.</summary>
public sealed class HealthAndDrainTests : IDisposable
{
    private readonly List<string> _roots = [];

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public void A_refused_runtime_cannot_build_a_serving_or_health_listener()
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-health-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);

        string manifest = ServedManifests.Write(
            root,
            "valid",
            ServedManifests.Upstream(new Uri("http://127.0.0.1:1")));
        string store = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;

        var validOptions = new RuntimeOptions([new MountRequest("/api", manifest)], store);
        var refusedOptions = new RuntimeOptions(
            [new MountRequest("/api", Path.Combine(root, "missing"))],
            store);
        RuntimeStartResult valid = EngineRuntime.Start(validOptions);
        RuntimeStartResult refused = EngineRuntime.Start(refusedOptions);

        Assert.True(valid.Started);
        Assert.False(refused.Started);

        using EngineExecution execution = EngineExecution.Create(valid, ServedEngine.Permissive());
        var binding = new HostBinding(
            refusedOptions,
            new HostListenOptions("http://127.0.0.1:0", HostTransport.Http),
            authorization: null);

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => EngineWebHost.Build(refused, binding, execution));

        Assert.Contains("no listener", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Health_is_ready_and_alive_without_probing_an_unreachable_upstream()
    {
        (ServedEngine engine, _) = await ServeAsync(new Uri("http://127.0.0.1:1"));
        await using (engine)
        using (var http = new HttpClient())
        {
            HttpResponseMessage ready = await http.GetAsync(engine.At(HealthEndpoints.ReadyPath), Token);
            HttpResponseMessage live = await http.GetAsync(engine.At(HealthEndpoints.LivePath), Token);

            Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
            Assert.Equal("ready\n", await ready.Content.ReadAsStringAsync(Token));
            Assert.Equal(HttpStatusCode.OK, live.StatusCode);
            Assert.Equal("alive\n", await live.Content.ReadAsStringAsync(Token));
        }
    }

    [Fact]
    public async Task Readiness_reports_a_file_store_that_becomes_unwritable_while_liveness_stays_alive()
    {
        (ServedEngine engine, string store) = await ServeAsync(new Uri("http://127.0.0.1:1"));
        await using (engine)
        using (var http = new HttpClient())
        {
            Directory.CreateDirectory(Path.Combine(store, FileHandleStore.WriteProbeName));

            HttpResponseMessage ready = await http.GetAsync(engine.At(HealthEndpoints.ReadyPath), Token);
            string readyBody = await ready.Content.ReadAsStringAsync(Token);
            HttpResponseMessage live = await http.GetAsync(engine.At(HealthEndpoints.LivePath), Token);

            Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
            Assert.Contains(store, readyBody, StringComparison.Ordinal);
            Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        }
    }

    [Fact]
    public async Task Drain_refuses_new_work_but_allows_an_admitted_call_to_finish_within_the_window()
    {
        var arrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                arrived.TrySetResult();
                await release.Task.WaitAsync(context.RequestAborted);
                context.Response.StatusCode = StatusCodes.Status200OK;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync("[]"u8.ToArray(), context.RequestAborted);
            },
            Token);

        (ServedEngine engine, _) = await ServeAsync(upstream.Address);
        await using (engine)
        using (McpHttpSession admitted = await McpHttpSession.OpenAsync(engine.At("api/full"), Token))
        using (McpHttpSession refused = await McpHttpSession.OpenAsync(engine.At("api/full"), Token))
        using (var http = new HttpClient())
        {
            Task<McpExchange> call = admitted.CallAsync(
                "list-pets",
                """{"status":"available"}""",
                2,
                Token);

            await arrived.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);

            Task<DrainReport> draining = engine.Drain.DrainAsync(TimeSpan.FromSeconds(5));

            McpExchange afterDrain = await refused.CallAsync(
                "list-pets",
                """{"status":"available"}""",
                2,
                Token);
            HttpResponseMessage ready = await http.GetAsync(engine.At(HealthEndpoints.ReadyPath), Token);
            HttpResponseMessage live = await http.GetAsync(engine.At(HealthEndpoints.LivePath), Token);

            Assert.Equal(HttpStatusCode.ServiceUnavailable, afterDrain.Status);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
            Assert.Equal(HttpStatusCode.OK, live.StatusCode);

            release.TrySetResult();

            McpExchange completed = await call;
            DrainReport report = await draining;

            Assert.Equal(HttpStatusCode.OK, completed.Status);
            Assert.True(report.Completed);
            Assert.Empty(report.AbandonedTools);
        }
    }

    [Fact]
    public async Task Drain_deadline_cancels_and_reports_the_tool_that_was_still_running()
    {
        var arrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var aborted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                arrived.TrySetResult();

                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, context.RequestAborted);
                }
                catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
                {
                    aborted.TrySetResult();
                }
            },
            Token);

        (ServedEngine engine, _) = await ServeAsync(upstream.Address);
        await using (engine)
        using (McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token))
        {
            Task<McpExchange> call = session.CallAsync(
                "list-pets",
                """{"status":"available"}""",
                2,
                Token);

            await arrived.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);

            DrainReport report = await engine.Drain.DrainAsync(TimeSpan.FromMilliseconds(100));

            Assert.False(report.Completed);
            Assert.Equal(["list-pets"], report.AbandonedTools);
            await aborted.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);

            Task settled = await Task.WhenAny(call, Task.Delay(TimeSpan.FromSeconds(5), Token));
            Assert.Same(call, settled);

            try
            {
                _ = await call;
            }
            catch (Exception)
            {
                // A protocol transport may surface forced cancellation as an aborted exchange.
                // The product contract asserted here is that the call is canceled and reported.
            }
        }
    }

    public void Dispose()
    {
        foreach (string root in _roots)
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private async Task<(ServedEngine Engine, string Store)> ServeAsync(Uri upstream)
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-health-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);

        string manifest = ServedManifests.Write(root, "api", ServedManifests.Upstream(upstream));
        string store = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;
        ServedEngine engine = await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", manifest)], store),
            Token);

        return (engine, store);
    }
}
