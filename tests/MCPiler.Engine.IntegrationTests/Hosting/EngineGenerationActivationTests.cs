using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
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

    private static CancellationToken Token => TestContext.Current.CancellationToken;

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

    /// <summary>A stateful session cannot carry its original surface onto a served sibling address.</summary>
    [Fact]
    public async Task A_session_id_cannot_move_tools_between_sibling_surfaces()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token);

        int upstreamArrivals = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref upstreamArrivals);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    $$"""{"path":"{{context.Request.Path.Value}}"}""",
                    context.RequestAborted);
            },
            Token);

        await using ManagedListener listener = await StartAsync(
            ServedManifests.ProtectedSiblingSurfaces(upstream.Address),
            AuthorizationFor(authorization.Address));

        Uri read = listener.At("/api/read");
        Uri write = listener.At("/api/write");
        string readToken = authorization.Mint(read.AbsoluteUri.TrimEnd('/'), string.Empty);
        string writeToken = authorization.Mint(write.AbsoluteUri.TrimEnd('/'), string.Empty);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            read,
            Token,
            bearerToken: readToken);

        Assert.Equal(["read-probe"], Names(await session.RequestAsync("tools/list", 2, Token)));

        McpExchange replayedList = await ReplaySessionAsync(
            write,
            session.SessionId!,
            writeToken,
            """{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}""",
            Token);

        Assert.DoesNotContain("read-probe", replayedList.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("write-probe", replayedList.Body, StringComparison.Ordinal);

        McpExchange replayedCall = await ReplaySessionAsync(
            write,
            session.SessionId!,
            writeToken,
            """{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read-probe","arguments":{}}}""",
            Token);

        Assert.Equal(0, Volatile.Read(ref upstreamArrivals));
        Assert.DoesNotContain("\"path\":\"/read-probe\"", replayedCall.Body, StringComparison.Ordinal);
    }

    /// <summary>A session-bound resource identity includes authority as well as the surface path.</summary>
    [Fact]
    public async Task A_session_id_cannot_move_tools_to_the_same_path_on_another_authority()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token);

        int upstreamArrivals = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref upstreamArrivals);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"authority\":\"captured\"}", context.RequestAborted);
            },
            Token);

        await using ManagedListener listener = await StartAsync(
            ServedManifests.ProtectedSiblingSurfaces(upstream.Address),
            AuthorizationFor(authorization.Address));

        Uri read = listener.At("/api/read");
        string originalResource = read.AbsoluteUri.TrimEnd('/');
        string originalToken = authorization.Mint(originalResource, string.Empty);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            read,
            Token,
            bearerToken: originalToken);

        string alternateAuthority = $"localhost:{read.Port}";
        string alternateResource = $"{read.Scheme}://{alternateAuthority}{read.AbsolutePath}";
        string alternateToken = authorization.Mint(alternateResource, string.Empty);

        McpExchange replayedCall = await ReplaySessionAsync(
            read,
            session.SessionId!,
            alternateToken,
            """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read-probe","arguments":{}}}""",
            Token,
            host: alternateAuthority);

        Assert.Equal(0, Volatile.Read(ref upstreamArrivals));
        Assert.DoesNotContain("\"authority\":\"captured\"", replayedCall.Body, StringComparison.Ordinal);
    }

    /// <summary>
    /// A protected tools/list request stays on the generation that authorization admitted even
    /// when activation happens while token introspection is waiting.
    /// </summary>
    [Fact]
    public async Task A_protected_tools_list_stays_on_the_admitted_generation_during_activation()
    {
        var gate = new FakeAuthorizationServer.IntrospectionGate();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token,
            introspectionGate: gate);

        const string g0SecretVariable = "MCPILER_TEST_GENERATION_G0";
        const string g1SecretVariable = "MCPILER_TEST_GENERATION_G1";
        Environment.SetEnvironmentVariable(g0SecretVariable, "g0-secret");
        Environment.SetEnvironmentVariable(g1SecretVariable, "g1-secret");

        try
        {
            await using ManagedListener listener = await StartAsync(
                ServedManifests.ProtectedGeneration(
                    new Uri("https://g0.example.test", UriKind.Absolute),
                    "g0",
                    g0SecretVariable,
                    "g0-probe"),
                AuthorizationFor(authorization.Address));

            string resource = listener.At("/api/full").AbsoluteUri.TrimEnd('/');
            string token = authorization.Mint(resource, string.Empty);

            using McpHttpSession session = await McpHttpSession.OpenAsync(
                listener.At("/api/full"),
                Token,
                bearerToken: token);

            gate.Arm();
            Task<McpExchange> pending = session.RequestAsync("tools/list", 2, Token);
            await gate.Reached.WaitAsync(TimeSpan.FromSeconds(10), Token);

            EngineGeneration superseded = listener.Manager.Current!;
            EngineGeneration candidate = listener.NewGeneration(
                Load(
                    "/api",
                    ServedManifests.ProtectedGeneration(
                        new Uri("https://g1.example.test", UriKind.Absolute),
                        "g1",
                        g1SecretVariable,
                        "g1-probe")));
            Task retirement = listener.Manager.Activate(candidate);

            Assert.True(superseded.IsRetired);
            Assert.False(superseded.IsDisposed);
            Assert.False(retirement.IsCompleted);

            gate.Release();
            McpExchange listed = await pending;

            Assert.Equal(HttpStatusCode.OK, listed.Status);
            Assert.Contains("\"name\":\"g0-probe\"", listed.Payload, StringComparison.Ordinal);
            Assert.DoesNotContain("\"name\":\"g1-probe\"", listed.Payload, StringComparison.Ordinal);

            await retirement.WaitAsync(Token);
            Assert.True(superseded.IsDisposed);

            // The session is deliberately reused after activation: its completed G0 request
            // lease is not a session pin, so a later request sees G1.
            McpExchange later = await session.RequestAsync("tools/list", 3, Token);
            Assert.Contains("\"name\":\"g1-probe\"", later.Payload, StringComparison.Ordinal);
            Assert.DoesNotContain("\"name\":\"g0-probe\"", later.Payload, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(g0SecretVariable, null);
            Environment.SetEnvironmentVariable(g1SecretVariable, null);
        }
    }

    /// <summary>
    /// A protected tools/call keeps its route, execution graph and managed secret on G0 while G1
    /// becomes current during introspection.
    /// </summary>
    [Fact]
    public async Task A_protected_tools_call_uses_only_the_admitted_generation_during_activation()
    {
        var gate = new FakeAuthorizationServer.IntrospectionGate();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token,
            introspectionGate: gate);

        const string g0SecretVariable = "MCPILER_TEST_CALL_G0";
        const string g1SecretVariable = "MCPILER_TEST_CALL_G1";
        Environment.SetEnvironmentVariable(g0SecretVariable, "g0-call-secret");
        Environment.SetEnvironmentVariable(g1SecretVariable, "g1-call-secret");

        int g0Arrivals = 0;
        int g1Arrivals = 0;
        await using LoopbackHost g0Upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref g0Arrivals);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    $$"""{"generation":"g0","secret":"{{context.Request.Headers["X-Generation-Secret"]}}"}""",
                    context.RequestAborted);
            },
            Token);
        await using LoopbackHost g1Upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref g1Arrivals);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    $$"""{"generation":"g1","secret":"{{context.Request.Headers["X-Generation-Secret"]}}"}""",
                    context.RequestAborted);
            },
            Token);

        try
        {
            await using ManagedListener listener = await StartAsync(
                ServedManifests.ProtectedGeneration(g0Upstream.Address, "g0", g0SecretVariable),
                AuthorizationFor(authorization.Address));

            string resource = listener.At("/api/full").AbsoluteUri.TrimEnd('/');
            string token = authorization.Mint(resource, string.Empty);
            using McpHttpSession session = await McpHttpSession.OpenAsync(
                listener.At("/api/full"),
                Token,
                bearerToken: token);

            gate.Arm();
            Task<McpExchange> pending = session.CallAsync("probe", "{}", 2, Token);
            await gate.Reached.WaitAsync(TimeSpan.FromSeconds(10), Token);

            EngineGeneration superseded = listener.Manager.Current!;
            EngineGeneration candidate = listener.NewGeneration(
                Load(
                    "/api",
                    ServedManifests.ProtectedGeneration(g1Upstream.Address, "g1", g1SecretVariable)));
            Task retirement = listener.Manager.Activate(candidate);

            Assert.False(retirement.IsCompleted);
            gate.Release();
            McpExchange called = await pending;

            Assert.Equal(HttpStatusCode.OK, called.Status);
            string text = Text(called);
            Assert.Contains("\"generation\":\"g0\"", text, StringComparison.Ordinal);
            Assert.Contains("\"secret\":\"g0-call-secret\"", text, StringComparison.Ordinal);
            Assert.Equal(1, Volatile.Read(ref g0Arrivals));
            Assert.Equal(0, Volatile.Read(ref g1Arrivals));

            await retirement.WaitAsync(Token);
            Assert.True(superseded.IsDisposed);
        }
        finally
        {
            Environment.SetEnvironmentVariable(g0SecretVariable, null);
            Environment.SetEnvironmentVariable(g1SecretVariable, null);
        }
    }

    /// <summary>Upload execution remains on the protected parent generation through activation.</summary>
    [Fact]
    public async Task A_protected_upload_stays_on_the_admitted_generation_during_activation()
    {
        var gate = new FakeAuthorizationServer.IntrospectionGate();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token,
            introspectionGate: gate);

        string g0Store = Store();
        string g1Store = Store();

        await using ManagedListener listener = await StartAsync(
            ServedManifests.ProtectedOneSurface,
            AuthorizationFor(authorization.Address),
            g0Store);

        string resource = listener.At("/api/full").AbsoluteUri.TrimEnd('/');
        string token = authorization.Mint(resource, string.Empty);
        byte[] payload = Encoding.UTF8.GetBytes("g0 upload canary");
        using HttpClient http = new();
        using HttpRequestMessage request = new(HttpMethod.Post, listener.At("/api/full/files/upload"))
        {
            Content = new ByteArrayContent(payload),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        gate.Arm();
        Task<HttpResponseMessage> pending = http.SendAsync(request, Token);
        Task reached = gate.Reached.WaitAsync(TimeSpan.FromSeconds(10), Token);
        Task first = await Task.WhenAny(reached, pending);
        if (ReferenceEquals(first, pending))
        {
            using HttpResponseMessage early = await pending;
            throw new InvalidOperationException(
                $"Upload completed before introspection gate: {(int)early.StatusCode} {await early.Content.ReadAsStringAsync(Token)}");
        }

        await reached;

        EngineGeneration superseded = listener.Manager.Current!;
        EngineGeneration candidate = listener.NewGeneration(
            Load("/api", ServedManifests.ProtectedOneSurface, g1Store));
        Task retirement = listener.Manager.Activate(candidate);

        Assert.False(retirement.IsCompleted);
        gate.Release();
        using HttpResponseMessage response = await pending;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(ContainsBytes(g0Store, payload));
        Assert.False(ContainsBytes(g1Store, payload));

        await retirement.WaitAsync(Token);
        Assert.True(superseded.IsDisposed);
    }

    /// <summary>Download redemption remains on the protected parent generation through activation.</summary>
    [Fact]
    public async Task A_protected_download_stays_on_the_admitted_generation_during_activation()
    {
        var gate = new FakeAuthorizationServer.IntrospectionGate();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token,
            introspectionGate: gate);

        string g0Store = Store();
        string g1Store = Store();
        await using ManagedListener listener = await StartAsync(
            ServedManifests.ProtectedOneSurface,
            AuthorizationFor(authorization.Address),
            g0Store);

        EngineGeneration superseded = listener.Manager.Current!;
        string resource = listener.At("/api/full").AbsoluteUri.TrimEnd('/');
        byte[] payload = [7, 8, 9, 0, 255];
        RuntimeFileUploadResult issued = await superseded.Execution.UploadFileAsync(
            new MemoryStream(payload),
            "g0.bin",
            "application/octet-stream",
            resource,
            Token);
        Assert.True(issued.Succeeded);

        string token = authorization.Mint(resource, string.Empty);
        using HttpClient http = new();
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            listener.At("/api/full/files/" + issued.Capability));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        gate.Arm();
        Task<HttpResponseMessage> pending = http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            Token);
        await gate.Reached.WaitAsync(TimeSpan.FromSeconds(10), Token);

        EngineGeneration candidate = listener.NewGeneration(
            Load("/api", ServedManifests.ProtectedOneSurface, g1Store));
        Task retirement = listener.Manager.Activate(candidate);

        Assert.False(retirement.IsCompleted);
        gate.Release();
        using HttpResponseMessage response = await pending;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(payload, await response.Content.ReadAsByteArrayAsync(Token));

        await retirement.WaitAsync(Token);
        Assert.True(superseded.IsDisposed);

        // A transfer admitted after the swap uses G1, and a retired generation cannot grant a
        // fresh lease even though its old capability was valid for the earlier request.
        using HttpRequestMessage postActivationRequest = new(
            HttpMethod.Post,
            listener.At("/api/full/files/upload"))
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes("g1 upload")),
        };
        postActivationRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using HttpResponseMessage postActivation = await http.SendAsync(postActivationRequest, Token);
        Assert.Equal(HttpStatusCode.OK, postActivation.StatusCode);
        Assert.False(superseded.TryLease(out _));
        Assert.True(ContainsBytes(g1Store, Encoding.UTF8.GetBytes("g1 upload")));
    }

    /// <summary>Managed transfer children inherit the parent resource for challenge, audience and scopes.</summary>
    [Fact]
    public async Task Managed_protected_transfer_uses_the_parent_resource_for_challenge_audience_and_scopes()
    {
        string manifest = ProtectedTransferManifest();

        await using FakeAuthorizationServer inactiveAuthorization = await FakeAuthorizationServer.StartAsync(
            active: false,
            Token);
        await using ManagedListener inactiveListener = await StartAsync(
            manifest,
            AuthorizationFor(inactiveAuthorization.Address));

        string inactiveParent = inactiveListener.At("/api/full").AbsoluteUri.TrimEnd('/');
        byte[] inactivePayload = Encoding.UTF8.GetBytes("inactive transfer");
        RuntimeFileUploadResult inactiveIssued = await inactiveListener.Manager.Current!.Execution.UploadFileAsync(
            new MemoryStream(inactivePayload),
            "inactive.bin",
            "application/octet-stream",
            inactiveParent,
            Token);
        Assert.True(inactiveIssued.Succeeded);

        using HttpClient http = new();
        using HttpRequestMessage unauthenticatedUpload = new(
            HttpMethod.Post,
            inactiveListener.At("/api/full/files/upload"))
        {
            Content = new ByteArrayContent(inactivePayload),
        };
        unauthenticatedUpload.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using HttpResponseMessage uploadChallenge = await http.SendAsync(unauthenticatedUpload, Token);
        AssertParentChallenge(uploadChallenge, "/api/full");

        using HttpRequestMessage inactiveUpload = new(
            HttpMethod.Post,
            inactiveListener.At("/api/full/files/upload"))
        {
            Content = new ByteArrayContent(inactivePayload),
        };
        inactiveUpload.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        inactiveUpload.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            inactiveAuthorization.Mint(inactiveParent, "tools.invoke"));
        using HttpResponseMessage inactiveUploadResponse = await http.SendAsync(inactiveUpload, Token);
        AssertParentChallenge(inactiveUploadResponse, "/api/full");

        using HttpResponseMessage downloadChallenge = await http.GetAsync(
            inactiveListener.At("/api/full/files/" + inactiveIssued.Capability),
            Token);
        AssertParentChallenge(downloadChallenge, "/api/full");

        using HttpRequestMessage inactiveDownload = new(
            HttpMethod.Get,
            inactiveListener.At("/api/full/files/" + inactiveIssued.Capability));
        inactiveDownload.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            inactiveAuthorization.Mint(inactiveParent, "tools.invoke"));
        using HttpResponseMessage inactiveDownloadResponse = await http.SendAsync(inactiveDownload, Token);
        AssertParentChallenge(inactiveDownloadResponse, "/api/full");

        await using FakeAuthorizationServer activeAuthorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token);
        await using ManagedListener activeListener = await StartAsync(
            manifest,
            AuthorizationFor(activeAuthorization.Address));

        string parent = activeListener.At("/api/full").AbsoluteUri.TrimEnd('/');
        string child = parent + "/files/upload";
        byte[] payload = Encoding.UTF8.GetBytes("managed parent transfer");
        RuntimeFileUploadResult issued = await activeListener.Manager.Current!.Execution.UploadFileAsync(
            new MemoryStream(payload),
            "parent.bin",
            "application/octet-stream",
            parent,
            Token);
        Assert.True(issued.Succeeded);

        using NeverSerializedContent childBody = new();
        using HttpRequestMessage wrongAudienceUpload = new(
            HttpMethod.Post,
            activeListener.At("/api/full/files/upload"))
        {
            Content = childBody,
        };
        wrongAudienceUpload.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        wrongAudienceUpload.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            activeAuthorization.Mint(child, "tools.invoke"));
        wrongAudienceUpload.Headers.ExpectContinue = true;
        using HttpResponseMessage wrongAudienceUploadResponse = await http.SendAsync(wrongAudienceUpload, Token);
        Assert.Equal(HttpStatusCode.NotFound, wrongAudienceUploadResponse.StatusCode);
        Assert.False(childBody.SerializationStarted);

        using NeverSerializedContent missingScopeBody = new();
        using HttpRequestMessage missingScopeUpload = new(
            HttpMethod.Post,
            activeListener.At("/api/full/files/upload"))
        {
            Content = missingScopeBody,
        };
        missingScopeUpload.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        missingScopeUpload.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            activeAuthorization.Mint(parent, string.Empty));
        missingScopeUpload.Headers.ExpectContinue = true;
        using HttpResponseMessage missingScopeUploadResponse = await http.SendAsync(missingScopeUpload, Token);
        Assert.Equal(HttpStatusCode.NotFound, missingScopeUploadResponse.StatusCode);
        Assert.False(missingScopeBody.SerializationStarted);

        using HttpResponseMessage wrongAudienceDownload = await http.SendAsync(
            new HttpRequestMessage(
                HttpMethod.Get,
                activeListener.At("/api/full/files/" + issued.Capability))
            {
                Headers =
                {
                    Authorization = new AuthenticationHeaderValue(
                        "Bearer",
                        activeAuthorization.Mint(parent + "/files/" + issued.Capability, "tools.invoke")),
                },
            },
            Token);
        Assert.Equal(HttpStatusCode.NotFound, wrongAudienceDownload.StatusCode);

        using HttpResponseMessage missingScopeDownload = await http.SendAsync(
            new HttpRequestMessage(
                HttpMethod.Get,
                activeListener.At("/api/full/files/" + issued.Capability))
            {
                Headers =
                {
                    Authorization = new AuthenticationHeaderValue(
                        "Bearer",
                        activeAuthorization.Mint(parent, string.Empty)),
                },
            },
            Token);
        Assert.Equal(HttpStatusCode.NotFound, missingScopeDownload.StatusCode);

        string validToken = activeAuthorization.Mint(parent, "tools.invoke");
        using HttpResponseMessage admittedUpload = await http.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, activeListener.At("/api/full/files/upload"))
            {
                Content = new ByteArrayContent(payload),
                Headers = { Authorization = new AuthenticationHeaderValue("Bearer", validToken) },
            },
            Token);
        Assert.Equal(HttpStatusCode.OK, admittedUpload.StatusCode);

        using HttpRequestMessage admittedDownloadRequest = new(
            HttpMethod.Get,
            activeListener.At("/api/full/files/" + issued.Capability));
        admittedDownloadRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", validToken);
        using HttpResponseMessage admittedDownload = await http.SendAsync(admittedDownloadRequest, Token);
        Assert.Equal(HttpStatusCode.OK, admittedDownload.StatusCode);
        Assert.Equal(payload, await admittedDownload.Content.ReadAsByteArrayAsync(Token));
    }

    /// <summary>
    /// An open surface is admitted before MCP dispatch even without authorization middleware. The
    /// request body gate holds protocol parsing while activation swaps the current generation.
    /// </summary>
    [Fact]
    public async Task An_open_surface_keeps_one_generation_across_request_body_processing()
    {
        const string g0SecretVariable = "MCPILER_TEST_OPEN_G0";
        const string g1SecretVariable = "MCPILER_TEST_OPEN_G1";
        Environment.SetEnvironmentVariable(g0SecretVariable, "open-g0");
        Environment.SetEnvironmentVariable(g1SecretVariable, "open-g1");

        try
        {
            await using ManagedListener listener = await StartAsync(
                    Open(ServedManifests.ProtectedGeneration(
                        new Uri("https://g0-open.example.test", UriKind.Absolute),
                        "g0",
                        g0SecretVariable,
                        "g0-open")));

            using McpHttpSession session = await McpHttpSession.OpenAsync(
                listener.At("/api/full"),
                Token);

            using var content = new StreamingRequestContent(
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":",
                "{}}",
                Token);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using HttpRequestMessage request = new(HttpMethod.Post, listener.At("/api/full"))
            {
                Content = content,
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            request.Headers.Add("Mcp-Session-Id", session.SessionId!);

            using HttpClient http = new();
            Task<HttpResponseMessage> pending = http.SendAsync(request, Token);
            await content.PrefixWritten.WaitAsync(Token);

            EngineGeneration superseded = listener.Manager.Current!;
            EngineGeneration candidate = listener.NewGeneration(
                Load(
                    "/api",
                    Open(ServedManifests.ProtectedGeneration(
                        new Uri("https://g1-open.example.test", UriKind.Absolute),
                        "g1",
                        g1SecretVariable,
                        "g1-open"))));
            Task retirement = listener.Manager.Activate(candidate);

            Assert.False(retirement.IsCompleted);
            content.Release();
            using HttpResponseMessage response = await pending;
            string body = await response.Content.ReadAsStringAsync(Token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("\"name\":\"g0-open\"", body, StringComparison.Ordinal);
            Assert.DoesNotContain("\"name\":\"g1-open\"", body, StringComparison.Ordinal);
            await retirement.WaitAsync(Token);
            Assert.True(superseded.IsDisposed);
        }
        finally
        {
            Environment.SetEnvironmentVariable(g0SecretVariable, null);
            Environment.SetEnvironmentVariable(g1SecretVariable, null);
        }
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
    /// A cached issuer standing result cannot bypass the replacement generation's scope policy.
    /// </summary>
    /// <remarks>
    /// The first request warms the process-local introspection cache with a token that carries
    /// <c>generation.read</c>. The replacement generation requires <c>generation.write</c> at the
    /// same address. The issuer is deliberately not contacted again: the cached standing fact is
    /// reused, but the current leased generation still makes the scope decision for the request.
    /// </remarks>
    [Fact]
    public async Task A_cached_token_standing_is_checked_against_the_replacement_generation()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken,
            introspectionExpiresInSeconds: 300);

        HostAuthorizationOptions options = new(
            authorization.Address.AbsoluteUri,
            HostTokenValidation.Introspection)
        {
            IntrospectionCacheTtlSeconds = 30,
        };

        await using ManagedListener listener = await StartAsync(options);
        string token = authorization.Mint(listener.At("/api/full").AbsoluteUri, "generation.read");

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            listener.At("/api/full"),
            TestContext.Current.CancellationToken,
            bearerToken: token);

        Assert.Equal(1, authorization.IntrospectionCalls);

        await listener.ActivateAsync(Load("/api", ProtectedManifest("generation.write")));

        McpExchange refused = await session.RequestAsync(
            "tools/list",
            3,
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, refused.Status);
        Assert.Equal(1, authorization.IntrospectionCalls);
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

    /// <summary>
    /// An operator clear follows the generation it leases, not the address it was configured with.
    /// </summary>
    /// <remarks>
    /// The operator names a mount prefix, and that prefix is resolved against the generation the
    /// request leases. After an activation that replaced the mount set, a clear naming a prefix the
    /// current generation no longer serves must be refused rather than reported as a successful
    /// clear of a mount that is no longer there.
    /// </remarks>
    [Fact]
    public async Task An_operator_clear_is_refused_for_a_mount_the_current_generation_stopped_serving()
    {
        await using ManagedListener listener = await StartAsync(
            ServedManifests.OneSurface,
            authorization: null,
            fileStoreRoot: null,
            operatorSecret: "operator-secret-for-tests");

        using HttpClient client = OperatorClient();

        // The initial generation serves /api.
        using HttpResponseMessage served = await client.PostAsync(
            listener.At(ResponseCacheOperatorEndpoints.ClearPath + "?mount=/api"),
            null,
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, served.StatusCode);

        // Activate a generation mounted at a different prefix. The operator address is unchanged;
        // only the mount set the generation resolves changed.
        await listener.ActivateAsync(Load("/other", ServedManifests.OneSurface));

        using HttpClient after = OperatorClient();
        using HttpResponseMessage stale = await after.PostAsync(
            listener.At(ResponseCacheOperatorEndpoints.ClearPath + "?mount=/api"),
            null,
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, stale.StatusCode);

        using HttpResponseMessage current = await after.PostAsync(
            listener.At(ResponseCacheOperatorEndpoints.ClearPath + "?mount=/other"),
            null,
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, current.StatusCode);

        static HttpClient OperatorClient()
        {
            HttpClient client = new();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", "operator-secret-for-tests");
            client.DefaultRequestHeaders.Add(
                MCPiler.Engine.Runtime.CompatibilitySchema.ContractGenerationHeader,
                MCPiler.Engine.Runtime.CompatibilitySchema.ResponseCacheOperatorGeneration);
            return client;
        }
    }

    private Task<ManagedListener> StartAsync()
        => StartAsync(ServedManifests.ThreeSurfaces, authorization: null, fileStoreRoot: null);

    private Task<ManagedListener> StartAsync(HostAuthorizationOptions authorization)
        => StartAsync(ProtectedManifest("generation.read"), authorization, fileStoreRoot: null);

    private async Task<ManagedListener> StartAsync(
        string manifest,
        HostAuthorizationOptions? authorization = null,
        string? fileStoreRoot = null,
        string? operatorSecret = null)
    {
        string store = fileStoreRoot ?? Store();
        ManagedListener listener = await ManagedListener.StartAsync(
            Load("/api", manifest, store),
            store,
            TestContext.Current.CancellationToken,
            authorization,
            operatorSecret);

        _listeners.Add(listener);
        return listener;
    }

    private HostBinding Binding(RuntimeStartResult started)
        => new(
            new RuntimeOptions([new MountRequest("/api", started.Mounts[0].Path)], Store()),
            new HostListenOptions("http://127.0.0.1:0", HostTransport.Http),
            Authorization: null,
            HostLifecycleOptions.Default);

    private RuntimeStartResult Load(string prefix, string manifest, string? fileStoreRoot = null)
    {
        RuntimeStartResult started = EngineRuntime.Start(
            new RuntimeOptions(
                [new MountRequest(prefix, Write(prefix.Trim('/'), manifest))],
                fileStoreRoot ?? Store()));

        Assert.True(
            started.Started,
            "The fixture Manifest was refused: "
                + string.Join("; ", started.Refusals.Select(refusal => refusal.Code + " " + refusal.Message)));

        return started;
    }

    private string Write(string name, string manifest) => ServedManifests.Write(_root, name, manifest);

    private static string ProtectedManifest(string requiredScope)
        => $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": {
                  "inline": {
                    "name": "Generation API",
                    "authenticationRequired": true,
                    "surfaces": [
                      {
                        "slug": "full",
                        "isDefault": true,
                        "requiredScopes": ["{{requiredScope}}"],
                        "operations": [ { "operation": "list-pets" } ]
                      }
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
                        "binding": { "type": "http", "operation": "GET /pets" }
                      }
                    ]
                  }
                }
              }
            }
            """;

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

    private static string Text(McpExchange exchange)
        => JsonNode.Parse(exchange.Payload)?["result"]?["content"]?[0]?["text"]?.GetValue<string>()
            ?? throw new InvalidOperationException("The payload carried no text result: " + exchange.Body);

    private static async Task<McpExchange> ReplaySessionAsync(
        Uri endpoint,
        string sessionId,
        string bearerToken,
        string body,
        CancellationToken cancellationToken,
        string? host = null)
    {
        using HttpClient http = new();
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        request.Headers.Add("Mcp-Session-Id", sessionId);
        request.Headers.Host = host;

        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken);
        string text = await response.Content.ReadAsStringAsync(cancellationToken);

        return new McpExchange(
            response.StatusCode,
            response.Content.Headers.ContentType?.MediaType ?? string.Empty,
            text,
            text);
    }

    private static HostAuthorizationOptions AuthorizationFor(Uri issuer)
        => new(issuer.AbsoluteUri, HostTokenValidation.Introspection);

    private static string ProtectedTransferManifest()
        => ServedManifests.ProtectedOneSurface.Replace(
            "\"isDefault\": true,",
            "\"isDefault\": true, \"requiredScopes\": [\"tools.invoke\"],",
            StringComparison.Ordinal);

    private static void AssertParentChallenge(HttpResponseMessage response, string parentPath)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        string challenge = response.Headers.WwwAuthenticate.Single().ToString();
        Assert.Contains("/.well-known/oauth-protected-resource" + parentPath, challenge, StringComparison.Ordinal);
        Assert.DoesNotContain("/files/", challenge, StringComparison.Ordinal);
    }

    private static string Open(string manifest)
        => manifest.Replace(
            "\"authenticationRequired\": true",
            "\"authenticationRequired\": false",
            StringComparison.Ordinal);

    private static bool ContainsBytes(string root, byte[] expected)
        => Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Any(path => File.ReadAllBytes(path).SequenceEqual(expected));

    private sealed class StreamingRequestContent : HttpContent
    {
        private readonly byte[] _prefix;
        private readonly byte[] _suffix;
        private readonly CancellationToken _testCancellation;
        private readonly TaskCompletionSource _prefixWritten = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal StreamingRequestContent(string prefix, string suffix, CancellationToken testCancellation)
        {
            _prefix = Encoding.UTF8.GetBytes(prefix);
            _suffix = Encoding.UTF8.GetBytes(suffix);
            _testCancellation = testCancellation;
        }

        internal Task PrefixWritten => _prefixWritten.Task;

        internal void Release() => _release.TrySetResult();

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => WriteAsync(stream, _testCancellation);

        protected override Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context,
            CancellationToken cancellationToken)
            => WriteAsync(stream, cancellationToken);

        private async Task WriteAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteAsync(_prefix, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            _prefixWritten.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(_suffix, cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class NeverSerializedContent : HttpContent
    {
        public bool SerializationStarted { get; private set; }

        protected override bool TryComputeLength(out long length)
        {
            length = 4096;
            return true;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            SerializationStarted = true;
            throw new InvalidOperationException("Authorization should refuse before request content is serialized.");
        }

        protected override Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SerializationStarted = true;
            throw new InvalidOperationException("Authorization should refuse before request content is serialized.");
        }
    }

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
            CancellationToken cancellationToken,
            HostAuthorizationOptions? authorization = null,
            string? operatorSecret = null)
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
                    Authorization: authorization,
                    HostLifecycleOptions.Default)
                {
                    ResponseCacheOperatorSecret = operatorSecret,
                },
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
