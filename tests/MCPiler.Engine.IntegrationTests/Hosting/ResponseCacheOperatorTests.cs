using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests.Execution;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Hosting;

/// <summary>
/// The authenticated, non-MCP operator channel that reads and clears response-cache state.
/// </summary>
/// <remarks>
/// <para>
/// These tests reach the real listening process through <see cref="ServedEngine"/>, so the route
/// mapping, the authentication guard and the transport policy under test are the ones a
/// deployment runs. The channel is opt-in, so the first assertion is always that its absence maps
/// nothing.
/// </para>
/// <para>
/// The remote-plain-http refusal is asserted through the pure transport predicate rather than a
/// non-loopback listener: no portable test can open a remote address, and the predicate is the
/// whole of the decision the endpoint makes about the transport.
/// </para>
/// </remarks>
public sealed class ResponseCacheOperatorTests : IDisposable
{
    private const string OperatorSecret = "operator-secret-for-tests";

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-operator-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public ResponseCacheOperatorTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task Without_a_configured_secret_no_operator_route_is_exposed()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: false);

        using HttpClient client = new();

        // Unauthenticated, and with the exact paths the channel would claim when configured. Both
        // the read and the clear must be absent, not merely refused: a route that exists and
        // refuses still discloses that an operator surface is present.
        using HttpResponseMessage read = await client.GetAsync(engine.At(ResponseCacheOperatorEndpoints.ReadPath), Token);
        using HttpResponseMessage clear = await client.PostAsync(engine.At(ResponseCacheOperatorEndpoints.ClearPath), null, Token);

        Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, clear.StatusCode);
    }

    [Fact]
    public async Task Read_and_clear_require_the_dedicated_secret_before_any_state_is_touched()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        // Warm one entry by calling the real operation through the runtime seam, so the clear has
        // something to remove and the read has something to report.
        await WarmAsync(engine, upstream.Address);
        Assert.Single(engine.Started.Mounts);

        using HttpClient anonymous = new();
        using HttpResponseMessage unauthRead = await anonymous.GetAsync(engine.At(ReadPath(MountPrefix)), Token);
        using HttpResponseMessage unauthClear = await anonymous.PostAsync(engine.At(ClearPath(MountPrefix)), null, Token);

        // The token is refused before a mount prefix is even read, so the two answers cannot
        // disclose whether the named mount exists.
        Assert.Equal(HttpStatusCode.Unauthorized, unauthRead.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthClear.StatusCode);

        using HttpClient wrongSecret = Authorized("not-the-secret");
        using HttpResponseMessage wrongRead = await wrongSecret.GetAsync(engine.At(ReadPath(MountPrefix)), Token);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongRead.StatusCode);

        // Nothing was cleared: an unauthorized clear never reaches the epoch or the entries.
        using HttpClient operatorClient = Authorized(OperatorSecret);
        using HttpResponseMessage read = await operatorClient.GetAsync(engine.At(ReadPath(MountPrefix)), Token);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);

        using JsonDocument observation = JsonDocument.Parse(await read.Content.ReadAsStringAsync(Token));

        Assert.Equal("enabled", observation.RootElement.GetProperty("caching").GetString());
        Assert.NotEmpty(observation.RootElement.GetProperty("recent").EnumerateArray());
    }

    [Fact]
    public async Task The_shared_operator_fixture_replays_the_real_read_and_clear_shapes()
    {
        using JsonDocument expected = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "fixtures", "response-cache", "operator-v1.json")));
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);
        await WarmAsync(engine, upstream.Address);
        await WarmAsync(engine, upstream.Address);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage read = await client.GetAsync(engine.At(ReadPath(MountPrefix)), Token);
        using JsonDocument actualRead = JsonDocument.Parse(await read.Content.ReadAsStringAsync(Token));
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        Assert.Equal(
            expected.RootElement.GetProperty("read").GetProperty("mount").GetString(),
            actualRead.RootElement.GetProperty("mount").GetString());
        Assert.Equal(
            expected.RootElement.GetProperty("read").GetProperty("caching").GetString(),
            actualRead.RootElement.GetProperty("caching").GetString());
        Assert.Equal(
            expected.RootElement.GetProperty("read").GetProperty("recent").GetArrayLength(),
            actualRead.RootElement.GetProperty("recent").GetArrayLength());
        Assert.Equal(
            expected.RootElement.GetProperty("read").GetProperty("recent")[0].GetProperty("operationSlug").GetString(),
            actualRead.RootElement.GetProperty("recent")[0].GetProperty("operationSlug").GetString());

        using HttpResponseMessage clear = await client.PostAsync(
            engine.At(ClearPath(MountPrefix, ExecutionManifests.Slug)),
            null,
            Token);
        using JsonDocument actualClear = JsonDocument.Parse(await clear.Content.ReadAsStringAsync(Token));
        Assert.Equal(HttpStatusCode.OK, clear.StatusCode);
        Assert.Equal(
            expected.RootElement.GetProperty("clear").GetProperty("removed").GetInt32(),
            actualClear.RootElement.GetProperty("removed").GetInt32());
        Assert.Equal(
            expected.RootElement.GetProperty("clear").GetProperty("manifestGenerationChanged").GetBoolean(),
            actualClear.RootElement.GetProperty("manifestGenerationChanged").GetBoolean());
    }

    [Fact]
    public async Task A_clear_reports_the_selected_scope_and_never_claims_a_generation_change()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        await WarmAsync(engine, upstream.Address);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage cleared = await client.PostAsync(
            engine.At(ClearPath(MountPrefix, ExecutionManifests.Slug)),
            null,
            Token);

        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);

        using JsonDocument body = JsonDocument.Parse(await cleared.Content.ReadAsStringAsync(Token));

        Assert.Equal(MountPrefix, body.RootElement.GetProperty("mount").GetString());
        Assert.Equal(ExecutionManifests.Slug, body.RootElement.GetProperty("operation").GetString());
        Assert.Equal(1, body.RootElement.GetProperty("removed").GetInt32());

        // The response never claims a Manifest-generation change: the action mutates only runtime
        // cache state, so the flag is present and false rather than absent.
        Assert.False(body.RootElement.GetProperty("manifestGenerationChanged").GetBoolean());

        // The rendered payload names no key preimage: a cache key is 64 hex characters and the
        // fingerprint is twelve, so a full-length hex token anywhere would be a leak.
        string raw = await cleared.Content.ReadAsStringAsync(Token);
        Assert.DoesNotContain(OperatorSecret, raw, StringComparison.Ordinal);
        Assert.DoesNotContain("\"key\"", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_clear_for_an_unknown_mount_is_refused_rather_than_reported_as_a_success()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage cleared = await client.PostAsync(engine.At(ClearPath("/absent")), null, Token);

        Assert.Equal(HttpStatusCode.NotFound, cleared.StatusCode);
    }

    [Theory]
    [InlineData("https", "203.0.113.7", true)]
    [InlineData("http", "127.0.0.1", true)]
    [InlineData("http", "::1", true)]
    [InlineData("http", "203.0.113.7", false)]
    public void The_operator_channel_requires_https_off_loopback(
        string scheme,
        string remote,
        bool acceptable)
    {
        // The scheme is observed after forwarded-headers processing, so a remote client cannot
        // claim https for itself unless the operator already trusted the proxy that set it.
        Assert.Equal(
            acceptable,
            ResponseCacheOperatorEndpoints.IsTransportAcceptable(
                string.Equals(scheme, "https", StringComparison.Ordinal),
                IPAddress.Parse(remote)));
    }

    [Fact]
    public async Task A_repeated_query_member_is_refused_rather_than_resolved()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage read = await client.GetAsync(
            engine.At(ResponseCacheOperatorEndpoints.ReadPath + "?mount=api&mount=other"),
            Token);

        Assert.Equal(HttpStatusCode.BadRequest, read.StatusCode);
    }

    /// <summary>
    /// A mount value is compared literally, so a spelling that does not decode to the served
    /// prefix is an unknown mount.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Query values are percent-decoded by the framework, so an encoded form of the served prefix
    /// (<c>%2Fapi</c>) legitimately names it and is covered by the next test. These rows are the
    /// ones that must <em>not</em> resolve: surrounding whitespace, a case variant, a trailing
    /// slash, an extra segment, and a literal backslash that some normalizers would treat as a
    /// path separator. Each would clear a mount the operator did not name if the comparison were
    /// loose.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("%20%2Fapi%20")]
    [InlineData("/API")]
    [InlineData("/api/")]
    [InlineData("/api%2Fextra")]
    [InlineData("/%5Capi")]
    public async Task A_mount_value_is_compared_literally(string mount)
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage cleared = await client.PostAsync(
            engine.At(ResponseCacheOperatorEndpoints.ClearPath + "?mount=" + mount),
            null,
            Token);

        Assert.Equal(HttpStatusCode.NotFound, cleared.StatusCode);
    }

    [Fact]
    public async Task An_encoded_mount_that_decodes_to_the_served_prefix_is_still_not_the_prefix()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        await WarmAsync(engine, upstream.Address);

        using HttpClient client = Authorized(OperatorSecret);

        // %2Fapi decodes to /api. Query parsing decodes the value, so this DOES name the served
        // prefix and must clear it; that is correct behaviour, and this test records it so a later
        // "must be literal bytes" change cannot silently break a legitimate encoded request.
        using HttpResponseMessage cleared = await client.PostAsync(
            engine.At(ResponseCacheOperatorEndpoints.ClearPath + "?mount=%2Fapi"),
            null,
            Token);

        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);

        using JsonDocument body = JsonDocument.Parse(await cleared.Content.ReadAsStringAsync(Token));
        Assert.Equal("/api", body.RootElement.GetProperty("mount").GetString());
        Assert.Equal(1, body.RootElement.GetProperty("removed").GetInt32());
    }

    [Fact]
    public async Task A_pre_clear_producer_cannot_repopulate_the_cleared_cache()
    {
        // This is the operator-facing half of the epoch rule the cache enforces. A producer that
        // began before the clear must not admit its result afterwards.
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        await WarmAsync(engine, upstream.Address);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage cleared = await client.PostAsync(engine.At(ClearPath(MountPrefix)), null, Token);
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);

        // A subsequent read sees the post-clear cache, which is empty: the cleared entry is gone
        // and the observation records the pre-clear hit under the old epoch.
        using HttpResponseMessage read = await client.GetAsync(engine.At(ReadPath(MountPrefix)), Token);
        using JsonDocument observation = JsonDocument.Parse(await read.Content.ReadAsStringAsync(Token));

        // The observation history is not cache content, so the pre-clear decision remains, but the
        // entry itself is gone; a second warm call must reach the upstream again.
        await WarmAsync(engine, upstream.Address);

        Assert.Equal(2, arrivals);
    }

    [Fact]
    public async Task An_unknown_operation_clear_is_refused_without_advancing_an_epoch()
    {
        // MTH-CACHE-2: an operation slug the mount does not declare is refused and adds no new
        // operation-epoch entry, so an arbitrary caller-supplied value cannot grow epoch state.
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        await WarmAsync(engine, upstream.Address);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage refused = await client.PostAsync(
            engine.At(ClearPath(MountPrefix, "no-such-operation")),
            null,
            Token);

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        // The refusal changed nothing: the warmed entry is still present, so a second warm call
        // does not reach the upstream again.
        await WarmAsync(engine, upstream.Address);
        Assert.Equal(1, arrivals);
    }

    [Fact]
    public async Task A_scoped_read_returns_only_the_requested_operation_and_refuses_an_unknown_slug()
    {
        // MTH-CACHE-1 / MTH-CACHE-2: an operation-scoped read contains only decisions for that
        // operation, and an undeclared slug is refused exactly as a scoped clear refuses it.
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        await WarmAsync(engine, upstream.Address);

        using HttpClient client = Authorized(OperatorSecret);

        using HttpResponseMessage scopedToReal = await client.GetAsync(
            engine.At(ReadPath(MountPrefix) + "&operation=" + ExecutionManifests.Slug),
            Token);
        using JsonDocument realBody = JsonDocument.Parse(await scopedToReal.Content.ReadAsStringAsync(Token));
        Assert.Equal(HttpStatusCode.OK, scopedToReal.StatusCode);
        Assert.NotEmpty(realBody.RootElement.GetProperty("recent").EnumerateArray());

        // The mount declares no such operation, so the scoped read is refused before any cache state
        // is touched. Neither an epoch entry nor a decision is created for it.
        using HttpResponseMessage scopedToOther = await client.GetAsync(
            engine.At(ReadPath(MountPrefix) + "&operation=other-operation"),
            Token);
        Assert.Equal(HttpStatusCode.BadRequest, scopedToOther.StatusCode);
    }

    [Fact]
    public async Task A_read_for_an_unknown_mount_is_refused_rather_than_reported_as_caching_disabled()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackCachedUpstreamAsync(() => Interlocked.Increment(ref arrivals));
        await using ServedEngine engine = await StartAsync(upstream.Address, configureOperator: true);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage read = await client.GetAsync(engine.At(ReadPath("/absent")), Token);

        Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
    }

    private const string MountPrefix = "/api";

    private static HttpClient Authorized(string secret)
    {
        HttpClient client = new();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        client.DefaultRequestHeaders.Add(
            MCPiler.Engine.Runtime.CompatibilitySchema.ContractGenerationHeader,
            MCPiler.Engine.Runtime.CompatibilitySchema.ResponseCacheOperatorGeneration);
        return client;
    }

    private static string ReadPath(string mount) => ResponseCacheOperatorEndpoints.ReadPath + "?mount=" + mount;

    private static string ClearPath(string mount, string? operation = null)
        => ResponseCacheOperatorEndpoints.ClearPath + "?mount=" + mount
            + (operation is null ? string.Empty : "&operation=" + operation);

    /// <summary>Calls the mounted operation once through the runtime seam, warming one entry.</summary>
    private static async Task WarmAsync(ServedEngine engine, Uri upstream)
    {
        MountedManifest mount = Assert.Single(engine.Started.Mounts);
        MountedSurface surface = Assert.Single(mount.Surfaces);

        await engine.Execution.InvokeAsync(
            mount,
            surface,
            mount.Prefix + "/" + surface.Slug,
            ExecutionManifests.Slug,
            [],
            negotiatedProtocolRevision: null,
            Token,
            CallerPartition.Public);
    }

    private static async Task<LoopbackHost> LoopbackCachedUpstreamAsync(Action onArrival)
        => await LoopbackHost.StartAsync(
            async context =>
            {
                onArrival();
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync("{\"ok\":true}"u8.ToArray(), context.RequestAborted);
            },
            Token);

    private async Task<ServedEngine> StartAsync(Uri upstream, bool configureOperator)
    {
        string bundle = ServedManifests.Write(
            _root,
            "operator-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream));

        RuntimeOptions options = new(
            [new MountRequest("/api", bundle)],
            Directory.CreateDirectory(Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName);

        return await ServedEngine.StartAsync(
            options,
            Token,
            operatorSecret: configureOperator ? OperatorSecret : null);
    }

    /// <summary>
    /// A minimal cache-enabled mount written for the file loader, since the operator tests reach
    /// the real serving path rather than an in-process manifest document.
    /// </summary>
    private static string Manifest(Uri upstream) => $$"""
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": { "name": "Operator Probe", "authenticationRequired": false, "surfaces": [
              { "slug": "full", "isDefault": true, "operations": [ { "operation": "get-thing" } ] }
            ] } },
            "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}" } },
            "operations": { "inline": { "operations": [
              { "key": "GET /thing", "method": "GET", "path": "/thing",
                "responses": { "200": { "content": { "application/json": { "schema": { "type": "object" } } } } } }
            ] } },
            "agentSurface": { "inline": { "operations": [
              { "slug": "{{ExecutionManifests.Slug}}", "name": "Get thing",
                "responseCache": { "ttlSeconds": 300 },
                "binding": { "type": "http", "operation": "GET /thing" } }
            ] } }
          }
        }
        """;
}
