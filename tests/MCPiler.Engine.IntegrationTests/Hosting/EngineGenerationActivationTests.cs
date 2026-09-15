using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Hosting;

/// <summary>
/// What an activation may and may not change about a running listener.
/// </summary>
/// <remarks>
/// <para>
/// These tests drive the real managed listener: one template route, one generation manager in DI,
/// the same dispatch middleware the process runs. A harness that resolved generations itself would
/// assert its own ordering rather than the product's, and the ordering is the whole requirement.
/// </para>
/// <para>
/// The address gate is deliberately exercised through HTTP rather than through the manager. A
/// generation that stopped admitting callers but left its address reachable would pass a unit test
/// of the manager and still serve a surface an operator had just removed.
/// </para>
/// </remarks>
public sealed class EngineGenerationActivationTests : IAsyncDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-generation-" + Guid.NewGuid().ToString("N"));
    private readonly List<ManagedListener> _listeners = [];

    public EngineGenerationActivationTests() => Directory.CreateDirectory(_root);

    /// <summary>
    /// A lease keeps resolving through the generation that granted it.
    /// </summary>
    /// <remarks>
    /// The two generations serve different surfaces at the same address, so a lease that resolved
    /// through the manager's current pointer instead of the generation it was taken from would
    /// silently change the surface under a request that was already admitted. This is the
    /// per-admission half of the atomicity requirement, asserted directly on the lease; the HTTP
    /// tests below assert the same thing at the boundary a client sees.
    /// </remarks>
    [Fact]
    public async Task A_lease_keeps_resolving_through_the_generation_that_granted_it()
    {
        await using ManagedListener listener = await StartAsync();

        EngineGeneration first = listener.Manager.Current!;

        Assert.True(first.TryResolve("/api/read", out SurfaceResolution? readBefore));
        Assert.NotNull(readBefore);
        Assert.Equal("read", readBefore!.Surface.Slug);

        EngineGeneration candidate = listener.NewGeneration(Load("/api", ServedManifests.OneSurface));
        Task retired = listener.Manager.Activate(candidate);

        // The generation that granted the lease still resolves its own addresses, unchanged.
        Assert.True(first.TryResolve("/api/read", out SurfaceResolution? readAfter));
        Assert.NotNull(readAfter);
        Assert.Equal("read", readAfter!.Surface.Slug);

        // A new admission is judged by the replacement, which does not serve that address.
        Assert.True(listener.Manager.TryLease(out EngineGenerationLease? current));
        using (current)
        {
            Assert.False(current!.Generation.TryResolve("/api/read", out _));
            Assert.True(current.Generation.TryResolve("/api/full", out _));
        }

        await retired.WaitAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A surface an activation removed stops being reachable for a brand-new request.
    /// </summary>
    [Fact]
    public async Task A_removed_address_is_refused_after_activation()
    {
        await using ManagedListener listener = await StartAsync();

        using (McpHttpSession before = await McpHttpSession.OpenAsync(
            listener.At("/api/read"),
            TestContext.Current.CancellationToken))
        {
            Assert.Equal(["list-pets"], Names(await before.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
        }

        // OneSurface declares a single default surface, so /api/read does not exist afterwards.
        await listener.ActivateAsync(Load("/api", ServedManifests.OneSurface));

        using HttpClient http = new();
        using HttpResponseMessage removed = await http.PostAsync(
            listener.At("/api/read"),
            new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""", Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, removed.StatusCode);

        // The address the new generation does serve continues to work.
        using McpHttpSession after = await McpHttpSession.OpenAsync(
            listener.At("/api/full"),
            TestContext.Current.CancellationToken);

        Assert.Equal(["list-pets", "add-pet"], Names(await after.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
    }

    /// <summary>
    /// A removed address is refused even for a session that predates the activation.
    /// </summary>
    /// <remarks>
    /// Sessions are not pinned. A session that started against a surface an activation removed
    /// must not keep serving it, because the token that authorized the session names a resource
    /// the operator has withdrawn.
    /// </remarks>
    [Fact]
    public async Task A_removed_address_is_refused_for_an_existing_session()
    {
        await using ManagedListener listener = await StartAsync();

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            listener.At("/api/read"),
            TestContext.Current.CancellationToken);

        Assert.Equal(["list-pets"], Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));

        await listener.ActivateAsync(Load("/api", ServedManifests.OneSurface));

        McpExchange removed = await session.RequestAsync("tools/list", 3, TestContext.Current.CancellationToken);

        Assert.True(
            removed.Status == HttpStatusCode.NotFound
                || removed.Payload.Contains("\"error\"", StringComparison.Ordinal),
            "A removed address must refuse rather than answer with a tool list: " + removed.Body);
    }

    /// <summary>
    /// A refused candidate changes nothing the listener serves.
    /// </summary>
    /// <remarks>
    /// The candidate is refused the way the managed loop refuses one, by never reaching
    /// <see cref="EngineGenerationManager.Activate"/>. What is asserted is that the listener keeps
    /// serving exactly what it served before, so a caller cannot observe that an attempt happened.
    /// </remarks>
    [Fact]
    public async Task A_refused_candidate_changes_nothing()
    {
        await using ManagedListener listener = await StartAsync();

        string before = await ListAsync(listener.At("/api/full"), TestContext.Current.CancellationToken);
        long? numberBefore = listener.Manager.CurrentNumber;

        // A candidate whose Manifest cannot load is refused before a generation exists.
        RuntimeStartResult refused = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", Write("broken", "{ not json }"))], Store()));

        Assert.False(refused.Started);
        Assert.NotEmpty(refused.Refusals);

        string after = await ListAsync(listener.At("/api/full"), TestContext.Current.CancellationToken);

        Assert.Equal(before, after);
        Assert.Contains("list-pets", before, StringComparison.Ordinal);
        Assert.Equal(numberBefore, listener.Manager.CurrentNumber);
    }

    /// <summary>
    /// Activating the generation that is already installed changes nothing.
    /// </summary>
    /// <remarks>
    /// Re-installing the current generation must not retire it. Retiring the generation the
    /// process serves would stop admitting callers until the next activation, which is a state no
    /// caller can distinguish from an outage.
    /// </remarks>
    [Fact]
    public async Task Re_activating_the_current_generation_keeps_serving()
    {
        await using ManagedListener listener = await StartAsync();

        EngineGeneration current = listener.Manager.Current!;

        Task retirement = listener.Manager.Activate(current);

        Assert.True(retirement.IsCompleted);
        Assert.Same(current, listener.Manager.Current);
        Assert.False(current.IsRetired);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            listener.At("/api/full"),
            TestContext.Current.CancellationToken);

        Assert.Equal(["list-pets", "add-pet"], Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)));
    }

    /// <summary>
    /// A drained generation releases its execution graph and cannot be leased again.
    /// </summary>
    [Fact]
    public async Task A_drained_generation_is_disposed_and_stops_admitting()
    {
        await using ManagedListener listener = await StartAsync();

        EngineGeneration candidate = listener.NewGeneration(Load("/api", ServedManifests.OneSurface));

        EngineGenerationLease? held = null;
        Assert.True(listener.Manager.TryLease(out held));

        EngineGeneration superseded = listener.Manager.Current!;
        Task retired = listener.Manager.Activate(candidate);

        Assert.True(superseded.IsRetired);
        Assert.False(superseded.IsDisposed);
        Assert.False(retired.IsCompleted);

        // No new admission may be taken from a retired generation while it drains.
        Assert.False(superseded.TryLease(out _));

        held!.Dispose();

        await retired.WaitAsync(TestContext.Current.CancellationToken);

        Assert.True(superseded.IsDisposed);
        Assert.Equal(0, superseded.LeaseCount);
    }

    /// <summary>
    /// Draining a generation with no outstanding leases disposes it immediately.
    /// </summary>
    [Fact]
    public async Task An_idle_generation_is_disposed_at_activation()
    {
        await using ManagedListener listener = await StartAsync();

        EngineGeneration candidate = listener.NewGeneration(Load("/api", ServedManifests.OneSurface));
        EngineGeneration superseded = listener.Manager.Current!;

        await listener.Manager.Activate(candidate).WaitAsync(TestContext.Current.CancellationToken);

        Assert.True(superseded.IsRetired);
        Assert.True(superseded.IsDisposed);
    }

    /// <summary>
    /// An address the active generation never served is refused by the managed listener.
    /// </summary>
    /// <remarks>
    /// A single template matches every path, so without the address gate the protocol handler would
    /// answer from whatever the current generation is — turning a misspelled address into a
    /// successful session against a different surface.
    /// </remarks>
    [Theory]
    [InlineData("/nope")]
    [InlineData("/api/nosuch")]
    [InlineData("/api/full/deeper")]
    public async Task An_address_no_generation_serves_discloses_nothing(string route)
    {
        await using ManagedListener listener = await StartAsync();

        using HttpClient http = new();
        using HttpResponseMessage refused = await http.PostAsync(
            listener.At(route),
            new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""", Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, refused.StatusCode);
        Assert.Empty(await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A managed listener refuses to build without an initial generation.
    /// </summary>
    /// <remarks>
    /// The failure has to happen before a listener exists. A managed process that opened a socket
    /// first would report readiness while serving nothing, so the refusal names synchronization
    /// rather than surfacing later as a client-side 404.
    /// </remarks>
    [Fact]
    public void A_managed_listener_without_a_generation_refuses_to_build()
    {
        RuntimeStartResult started = Load("/api", ServedManifests.OneSurface);
        EngineExecution execution = EngineExecution.Create(started, ServedEngine.Permissive());
        var drain = new DrainCoordinator();
        EngineGenerationManager empty = new(HostMode.Managed);

        try
        {
            InvalidOperationException refused = Assert.Throws<InvalidOperationException>(() =>
                EngineWebHost.BuildManaged(
                    Binding(started),
                    drain,
                    empty));

            Assert.Contains("initial generation", refused.Message, StringComparison.Ordinal);
        }
        finally
        {
            execution.Dispose();
            empty.Dispose();
            drain.Dispose();
        }
    }

    /// <summary>
    /// A file-mode manager is refused by the managed builder.
    /// </summary>
    [Fact]
    public void A_managed_listener_refuses_a_file_mode_manager()
    {
        RuntimeStartResult started = Load("/api", ServedManifests.OneSurface);
        EngineExecution execution = EngineExecution.Create(started, ServedEngine.Permissive());
        var drain = new DrainCoordinator();
        EngineGenerationManager fileMode = new(HostMode.File);

        try
        {
            InvalidOperationException refused = Assert.Throws<InvalidOperationException>(() =>
                EngineWebHost.BuildManaged(
                    Binding(started),
                    drain,
                    fileMode));

            Assert.Contains("managed generation manager", refused.Message, StringComparison.Ordinal);
        }
        finally
        {
            execution.Dispose();
            fileMode.Dispose();
            drain.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (ManagedListener listener in _listeners)
        {
            await listener.DisposeAsync();
        }

        _listeners.Clear();

        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private async Task<ManagedListener> StartAsync()
    {
        ManagedListener listener = await ManagedListener.StartAsync(
            Load("/api", ServedManifests.ThreeSurfaces),
            Store(),
            TestContext.Current.CancellationToken);

        _listeners.Add(listener);
        return listener;
    }

    private HostBinding Binding(RuntimeStartResult started)
        => new(
            new RuntimeOptions([new MountRequest("/api", started.Mounts[0].Path)], Store()),
            new HostListenOptions("http://127.0.0.1:0", HostTransport.Http),
            Authorization: null,
            HostLifecycleOptions.Default);

    private RuntimeStartResult Load(string prefix, string manifest)
    {
        RuntimeStartResult started = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest(prefix, Write(prefix.Trim('/'), manifest))], Store()));

        Assert.True(
            started.Started,
            "The fixture Manifest was refused: "
                + string.Join("; ", started.Refusals.Select(refusal => refusal.Code + " " + refusal.Message)));

        return started;
    }

    private string Write(string name, string manifest) => ServedManifests.Write(_root, name, manifest);

    private string Store()
    {
        string store = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(store);
        return store;
    }

    private static async Task<string> ListAsync(Uri endpoint, CancellationToken cancellationToken)
    {
        using McpHttpSession session = await McpHttpSession.OpenAsync(endpoint, cancellationToken);
        return (await session.RequestAsync("tools/list", 2, cancellationToken)).Payload;
    }

    private static IReadOnlyList<string> Names(McpExchange exchange)
        => [.. Tools(exchange).Select(tool => tool!["name"]!.GetValue<string>())];

    private static JsonArray Tools(McpExchange exchange)
        => JsonNode.Parse(exchange.Payload)?["result"]?["tools"] as JsonArray
            ?? throw new InvalidOperationException("The payload carried no tool list: " + exchange.Body);

    /// <summary>
    /// A managed listener plus the manager an activation installs into.
    /// </summary>
    /// <remarks>
    /// Built through <see cref="EngineWebHost.BuildManaged"/>, so the routes, the dispatch
    /// middleware and the DI registrations are the product's. Only the generation contents are the
    /// test's, because that is what the test is varying.
    /// </remarks>
    private sealed class ManagedListener : IAsyncDisposable
    {
        private static readonly TimeSpan ShutdownBudget = TimeSpan.FromSeconds(5);

        private readonly WebApplication _app;
        private readonly DrainCoordinator _drain;
        private readonly List<EngineExecution> _executions = [];
        private long _nextNumber = 1;

        private ManagedListener(
            WebApplication app,
            Uri address,
            EngineGenerationManager manager,
            DrainCoordinator drain)
        {
            _app = app;
            Address = address;
            Manager = manager;
            _drain = drain;
        }

        public Uri Address { get; }

        public EngineGenerationManager Manager { get; }

        public static async Task<ManagedListener> StartAsync(
            RuntimeStartResult initial,
            string fileStoreRoot,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(initial);

            var manager = new EngineGenerationManager(HostMode.Managed);
            var drain = new DrainCoordinator();

            EngineExecution initialExecution = EngineExecution.Create(initial, ServedEngine.Permissive());
            _ = manager.Activate(Generation(0, initial, initialExecution));

            WebApplication app = EngineWebHost.BuildManaged(
                new HostBinding(
                    new RuntimeOptions([new MountRequest("/managed", initial.Mounts[0].Path)], fileStoreRoot),
                    new HostListenOptions("http://127.0.0.1:0", HostTransport.Http),
                    Authorization: null,
                    HostLifecycleOptions.Default),
                drain,
                manager);

            try
            {
                await app.StartAsync(cancellationToken);
            }
            catch
            {
                manager.Dispose();
                initialExecution.Dispose();
                await app.DisposeAsync();
                drain.Dispose();
                throw;
            }

            string bound = app.Urls.Count == 1
                ? app.Urls.Single()
                : throw new InvalidOperationException(
                    $"Expected exactly one bound address, found {app.Urls.Count}: {string.Join(", ", app.Urls)}.");

            var listener = new ManagedListener(app, new Uri(bound, UriKind.Absolute), manager, drain);
            listener._executions.Add(initialExecution);
            return listener;
        }

        /// <summary>
        /// Builds a candidate generation over a freshly loaded runtime.
        /// </summary>
        /// <remarks>
        /// The execution graph is owned by this listener, not by the generation, so a candidate
        /// that is built and never activated is still disposed exactly once at teardown. That
        /// mirrors file mode, where the command runner owns the execution and the generation only
        /// borrows it.
        /// </remarks>
        public EngineGeneration NewGeneration(RuntimeStartResult started)
        {
            EngineExecution execution = EngineExecution.Create(started, ServedEngine.Permissive());
            _executions.Add(execution);

            return Generation(_nextNumber++, started, execution);
        }

        /// <summary>Loads, builds and activates a replacement generation.</summary>
        public Task ActivateAsync(RuntimeStartResult replacement)
            => Manager.Activate(NewGeneration(replacement)).WaitAsync(TestContext.Current.CancellationToken);

        public Uri At(string route) => new(Address, route);

        public async ValueTask DisposeAsync()
        {
            using var shutdown = new CancellationTokenSource(ShutdownBudget);

            try
            {
                await _app.StopAsync(shutdown.Token);
            }
            finally
            {
                await _app.DisposeAsync();
            }

            Manager.Dispose();

            foreach (EngineExecution execution in _executions)
            {
                execution.Dispose();
            }

            _drain.Dispose();
        }

        private static EngineGeneration Generation(long number, RuntimeStartResult started, EngineExecution execution)
            => new(number, MountSet.From(started), execution, ownsExecution: false);
    }
}
