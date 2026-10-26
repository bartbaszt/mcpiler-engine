using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Hosting;

/// <summary>
/// The authenticated, non-MCP operator channel for standalone authorization state.
/// </summary>
/// <remarks>
/// <para>
/// These tests reach the real listening process through <see cref="ServedEngine"/>, so the route
/// mapping, the credential guard, the transport rule, the admission bounds and the clear's commit
/// path are the ones a deployment runs. The channel is opt-in, so the first assertion is always that
/// its absence maps nothing.
/// </para>
/// <para>
/// The remote-plain-http refusal is asserted through the pure transport predicate rather than a
/// non-loopback listener: no portable test can open a remote address, and the predicate is the whole
/// of the decision the endpoint makes about the transport.
/// </para>
/// </remarks>
public sealed class OAuthOperatorEndpointsTests : IDisposable
{
    private const string OperatorSecret = "oauth-operator-secret-for-tests";
    private const string ResponseCacheSecret = "response-cache-operator-secret-for-tests";
    private const string ProfileId = "oauth";
    private const string MountPrefix = "/api";
    private const string Tool = "list-things";

    private const string UnusedTokenAuthority = "https://auth.example.test:443";
    private const string UnusedDestinationAuthority = "https://api.example.test:443";

    private const string ManifestScopeFingerprint =
        "0000000000000000000000000000000000000000000000000000000000000007";

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-oauth-operator-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public OAuthOperatorEndpointsTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task Without_a_configured_secret_no_authorization_route_is_exposed()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment, configureOperator: false);

        using HttpClient client = new();

        // Unauthenticated, and with the exact paths the channel would claim when configured. Every
        // route must be absent, not merely refused: a route that exists and refuses still discloses
        // that an operator surface is present.
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await client.GetAsync(engine.At(OAuthOperatorEndpoints.CapabilityPath), Token)).StatusCode);
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await client.GetAsync(engine.At(OAuthOperatorEndpoints.StatusPath), Token)).StatusCode);
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await client.GetAsync(engine.At(OAuthOperatorEndpoints.EventsPath), Token)).StatusCode);
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await client.PostAsync(engine.At(OAuthOperatorEndpoints.ClearPath), null, Token)).StatusCode);

        // The relay routes open host-owned authorization attempts, so they are the highest-value
        // thing this channel offers. Their absence is asserted the same way, with the bodies they
        // would read when configured.
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await client.PostAsync(
                engine.At(OAuthOperatorEndpoints.AuthorizePath),
                JsonContent(new { mount = MountPrefix, profile = ProfileId, redirectUri = "http://127.0.0.1:1/oauth/callback" }),
                Token)).StatusCode);
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await client.PostAsync(
                engine.At(OAuthOperatorEndpoints.AuthorizeCompletePath),
                JsonContent(new { relay = "unknown" }),
                Token)).StatusCode);
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await client.PostAsync(
                engine.At(OAuthOperatorEndpoints.AuthorizeAbortPath),
                JsonContent(new { relay = "unknown" }),
                Token)).StatusCode);
    }

    [Fact]
    public async Task The_two_operator_channels_do_not_accept_each_others_secrets()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(
            deployment,
            configureOperator: true,
            configureResponseCacheOperator: true);

        // The response-cache secret may drop warm cache entries. It must not thereby be able to drop a
        // live credential.
        using HttpClient responseCacheOperator = Authorized(ResponseCacheSecret);
        using HttpResponseMessage status = await responseCacheOperator.GetAsync(
            engine.At(OAuthOperatorEndpoints.StatusPath),
            Token);
        Assert.Equal(HttpStatusCode.Unauthorized, status.StatusCode);

        // And the reverse: the authorization secret, which may clear a credential, must not be a
        // credential for the response-cache channel.
        using HttpClient authorizationOperator = Authorized(OperatorSecret);
        using HttpResponseMessage read = await authorizationOperator.GetAsync(
            engine.At(ResponseCacheOperatorEndpoints.ReadPath + "?mount=" + MountPrefix),
            Token);
        Assert.Equal(HttpStatusCode.Unauthorized, read.StatusCode);
    }

    [Theory]
    [InlineData("not-the-secret")]
    [InlineData("")]
    public async Task Every_route_requires_the_dedicated_secret_before_any_state_is_read(string presented)
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);
        await SeedAuthorizedAsync(deployment);

        using HttpClient client = new();
        client.DefaultRequestHeaders.Add(
            CompatibilitySchema.ContractGenerationHeader,
            CompatibilitySchema.OAuthOperatorGeneration);

        if (presented.Length > 0)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", presented);
        }

        // The credential is checked before a mount prefix is read, so a refused caller cannot tell an
        // unknown prefix from a mounted one, and a clear cannot begin before the caller is proven.
        foreach (string path in new[]
        {
            OAuthOperatorEndpoints.CapabilityPath,
            OAuthOperatorEndpoints.StatusPath,
            OAuthOperatorEndpoints.EventsPath,
        })
        {
            using HttpResponseMessage response = await client.GetAsync(engine.At(path), Token);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        using HttpResponseMessage clear = await client.PostAsync(engine.At(ClearPath()), null, Token);

        Assert.Equal(HttpStatusCode.Unauthorized, clear.StatusCode);

        // An unauthenticated relay request must not even build an attempt: opening one would put a
        // live PKCE verifier in this process on behalf of a caller that proved nothing.
        using HttpResponseMessage authorize = await client.PostAsync(
            engine.At(OAuthOperatorEndpoints.AuthorizePath),
            JsonContent(new { mount = MountPrefix, profile = ProfileId, redirectUri = "http://127.0.0.1:1/oauth/callback" }),
            Token);

        Assert.Equal(HttpStatusCode.Unauthorized, authorize.StatusCode);

        using HttpResponseMessage complete = await client.PostAsync(
            engine.At(OAuthOperatorEndpoints.AuthorizeCompletePath),
            JsonContent(new { relay = "unknown" }),
            Token);

        Assert.Equal(HttpStatusCode.Unauthorized, complete.StatusCode);

        // Nothing was cleared or authorized: an unauthorized mutation never reaches the store.
        MutableSlotDecision? decision = await ReadDecisionAsync(deployment);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal(2, decision.AuthorityEpoch);
    }

    [Fact]
    public async Task A_missing_or_unsupported_contract_generation_is_refused()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);

        using HttpClient absent = Authorized(OperatorSecret, generation: null);
        using HttpResponseMessage noContract = await absent.GetAsync(engine.At(OAuthOperatorEndpoints.StatusPath), Token);
        Assert.Equal(HttpStatusCode.Conflict, noContract.StatusCode);

        using HttpClient unsupported = Authorized(OperatorSecret, "999");
        using HttpResponseMessage wrongGeneration = await unsupported.GetAsync(
            engine.At(OAuthOperatorEndpoints.StatusPath),
            Token);
        Assert.Equal(HttpStatusCode.Conflict, wrongGeneration.StatusCode);

        using HttpClient repeated = Authorized(OperatorSecret, compatibilityHeaderValues: 2);
        using HttpResponseMessage ambiguous = await repeated.GetAsync(
            engine.At(OAuthOperatorEndpoints.StatusPath),
            Token);
        Assert.Equal(HttpStatusCode.Conflict, ambiguous.StatusCode);
    }

    [Fact]
    public async Task Capability_reports_the_contract_the_mode_and_the_bounds()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage response = await client.GetAsync(engine.At(OAuthOperatorEndpoints.CapabilityPath), Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Token));
        JsonElement root = document.RootElement;

        Assert.Equal(CompatibilitySchema.OAuthOperator, root.GetProperty("contract").GetString());
        Assert.Equal(CompatibilitySchema.OAuthOperatorGeneration, root.GetProperty("generation").GetString());
        Assert.Equal("file", root.GetProperty("mode").GetString());
        Assert.Equal("enabled", root.GetProperty("state").GetString());

        string[] capabilities =
            [.. root.GetProperty("capabilities").EnumerateArray().Select(entry => entry.GetString()!)];
        Assert.Contains("clear", capabilities);
        Assert.Contains("status", capabilities);
        Assert.Contains("events", capabilities);

        // The relay routes are advertised, because they are the part of this channel an operator
        // drives an authorization with rather than only reading state from.
        foreach (string relayCapability in new[] { "authorize", "complete", "abort" })
        {
            Assert.Contains(relayCapability, capabilities);
        }

        JsonElement bounds = root.GetProperty("bounds");
        Assert.Equal(OAuthOperatorAdmission.MaximumConcurrent, bounds.GetProperty("concurrent").GetInt32());
        Assert.Equal(OAuthOperatorAdmission.MaximumPending, bounds.GetProperty("pending").GetInt32());
        Assert.Equal(OAuthOperatorAdmission.MaximumRequestsPerWindow, bounds.GetProperty("ratePerWindow").GetInt32());
        Assert.Equal(OAuthOperatorEndpoints.MaximumQueryCharacters, bounds.GetProperty("maxQueryCharacters").GetInt32());
        Assert.Equal(OAuthOperatorEndpoints.MaximumBodyCharacters, bounds.GetProperty("maxBodyCharacters").GetInt32());
        Assert.Equal(
            StandaloneAuthorizationRelaySessions.MaximumSessions,
            bounds.GetProperty("maxRelaySessions").GetInt32());
    }

    [Fact]
    public async Task Status_reports_a_committed_local_authority_without_its_value()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);

        const string canary = "CANARY-operator-status-refresh-31bd";
        await SeedAuthorizedAsync(deployment, canary);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage response = await client.GetAsync(
            engine.At(OAuthOperatorEndpoints.StatusPath + "?mount=" + MountPrefix + "&profile=" + ProfileId),
            Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync(Token);
        Assert.DoesNotContain(canary, body, StringComparison.Ordinal);

        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement profile = Assert.Single(document.RootElement.GetProperty("profiles").EnumerateArray());

        Assert.Equal(MountPrefix, profile.GetProperty("mountPrefix").GetString());
        Assert.Equal(ProfileId, profile.GetProperty("profileId").GetString());
        Assert.Equal("authorized", profile.GetProperty("state").GetString());
        Assert.Equal("oauth/authorized", profile.GetProperty("code").GetString());
        Assert.Equal(2, profile.GetProperty("authorityEpoch").GetInt64());

        // This process trusts no issuer, so there is no trust interaction to report and the
        // availability section is absent rather than an empty claim of health.
        Assert.False(document.RootElement.TryGetProperty("issuerAvailability", out _));
    }

    [Fact]
    public async Task Status_refuses_an_unknown_profile_rather_than_claiming_a_state()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage response = await client.GetAsync(
            engine.At(OAuthOperatorEndpoints.StatusPath + "?mount=" + MountPrefix + "&profile=absent"),
            Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Token));
        JsonElement profile = Assert.Single(document.RootElement.GetProperty("profiles").EnumerateArray());

        Assert.Equal("unavailable", profile.GetProperty("state").GetString());
        Assert.Equal("standalone/unknown-profile", profile.GetProperty("code").GetString());
    }

    /// <summary>
    /// The serving issuer availability observations an operator reads beside authorization state:
    /// a timed, sanitized category per trust interaction, never a token, and never a substitute for
    /// a per-request decision.
    /// </summary>
    [Fact]
    public async Task Issuer_availability_is_exposed_to_the_authenticated_operator_with_sanitized_categories_only()
    {
        const string AudienceCanary = "CANARY-availability-audience-7f21";
        Deployment deployment = CreateDeployment(
            ManifestOf(
                UnusedTokenAuthority,
                UnusedDestinationAuthority,
                UnusedDestinationAuthority,
                protectedMount: true));

        var issuer = await FakeAuthorizationServer.StartAsync(active: true, Token);

        try
        {
            await using ServedEngine engine = await ServedEngine.StartAsync(
                Options(deployment),
                Token,
                authorization: new HostAuthorizationOptions(
                    issuer.Address.AbsoluteUri,
                    HostTokenValidation.Introspection),
                oauthOperatorSecret: OperatorSecret);

            using HttpClient operatorClient = Authorized(OperatorSecret);

            // Nothing has asked the issuer yet. A configured validation mode with no observation is
            // reported as an explicitly empty history, not as a claim of health.
            using (JsonDocument empty = JsonDocument.Parse(await (await operatorClient.GetAsync(
                engine.At(OAuthOperatorEndpoints.StatusPath),
                Token)).Content.ReadAsStringAsync(Token)))
            {
                JsonElement emptyAvailability = empty.RootElement.GetProperty("issuerAvailability");
                Assert.Equal("introspection", emptyAvailability.GetProperty("mode").GetString());
                Assert.Equal("in-memory", emptyAvailability.GetProperty("storage").GetString());
                Assert.Equal(0, emptyAvailability.GetProperty("retained").GetInt32());
                Assert.Empty(emptyAvailability.GetProperty("events").EnumerateArray());
            }

            string token = issuer.Mint(AudienceCanary, "tools.invoke");

            // A real protected request drives real introspection. Its audience names no resource this
            // process serves, so the boundary refuses it; the trust interaction itself happened and
            // must be observable.
            using HttpClient caller = new();
            caller.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using HttpResponseMessage refused = await caller.GetAsync(engine.At(MountPrefix + "/" + Tool), Token);
            Assert.Equal(HttpStatusCode.NotFound, refused.StatusCode);

            string secondToken = issuer.Mint(AudienceCanary + "-second", "tools.invoke");

            // The issuer stops answering. A fresh token cannot be established, so the request earns
            // the ordinary 401 challenge and the observation records an endpoint outage rather than
            // the issuer declaring a token inactive.
            await issuer.DisposeAsync();

            using HttpClient outageCaller = new();
            outageCaller.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secondToken);
            using HttpResponseMessage outageRefusal = await outageCaller.GetAsync(
                engine.At(MountPrefix + "/" + Tool),
                Token);
            Assert.Equal(HttpStatusCode.Unauthorized, outageRefusal.StatusCode);

            using HttpResponseMessage response = await operatorClient.GetAsync(
                engine.At(OAuthOperatorEndpoints.StatusPath),
                Token);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            string body = await response.Content.ReadAsStringAsync(Token);

            // Neither presented bearer nor the audience either named may reach the diagnostic surface.
            Assert.DoesNotContain(token, body, StringComparison.Ordinal);
            Assert.DoesNotContain(secondToken, body, StringComparison.Ordinal);
            Assert.DoesNotContain(AudienceCanary, body, StringComparison.Ordinal);
            Assert.DoesNotContain("Bearer", body, StringComparison.Ordinal);

            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement availability = document.RootElement.GetProperty("issuerAvailability");

            Assert.Equal("introspection", availability.GetProperty("mode").GetString());
            Assert.Equal("in-memory", availability.GetProperty("storage").GetString());
            Assert.False(availability.GetProperty("durable").GetBoolean());
            Assert.Equal(
                IssuerAvailabilityObservations.DefaultMaximumEntries,
                availability.GetProperty("maximumEntries").GetInt32());

            JsonElement[] events = [.. availability.GetProperty("events").EnumerateArray()];
            Assert.Equal(2, events.Length);
            Assert.Equal(2, availability.GetProperty("retained").GetInt32());
            Assert.Equal("introspection-unavailable", events[0].GetProperty("category").GetString());
            Assert.Equal("issuer-answered", events[1].GetProperty("category").GetString());

            foreach (JsonElement entry in events)
            {
                Assert.Equal("introspection", entry.GetProperty("mode").GetString());
                Assert.NotEmpty(entry.GetProperty("effect").GetString()!);
                _ = entry.GetProperty("observedAtUtc").GetDateTimeOffset();
            }

            Assert.True(
                events[0].GetProperty("observedAtUtc").GetDateTimeOffset()
                    >= events[1].GetProperty("observedAtUtc").GetDateTimeOffset());

            // The MCP boundary and the operator diagnostic are separate trust domains: an anonymous
            // caller and a caller holding a valid MCP bearer are both refused the availability view.
            using HttpClient anonymous = new();
            anonymous.DefaultRequestHeaders.Add(
                CompatibilitySchema.ContractGenerationHeader,
                CompatibilitySchema.OAuthOperatorGeneration);
            Assert.Equal(
                HttpStatusCode.Unauthorized,
                (await anonymous.GetAsync(engine.At(OAuthOperatorEndpoints.StatusPath), Token)).StatusCode);

            using HttpClient mcpCaller = new();
            mcpCaller.DefaultRequestHeaders.Add(
                CompatibilitySchema.ContractGenerationHeader,
                CompatibilitySchema.OAuthOperatorGeneration);
            mcpCaller.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            Assert.Equal(
                HttpStatusCode.Unauthorized,
                (await mcpCaller.GetAsync(engine.At(OAuthOperatorEndpoints.StatusPath), Token)).StatusCode);
        }
        finally
        {
            await issuer.DisposeAsync();
        }
    }

    [Fact]
    public async Task A_clear_over_the_channel_commits_a_floor_and_a_second_clear_is_a_no_op()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);
        await SeedAuthorizedAsync(deployment);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage cleared = await client.PostAsync(engine.At(ClearPath()), null, Token);
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);

        using JsonDocument clearedBody = JsonDocument.Parse(await cleared.Content.ReadAsStringAsync(Token));
        Assert.True(clearedBody.RootElement.GetProperty("cleared").GetBoolean());
        Assert.Equal("oauth/cleared", clearedBody.RootElement.GetProperty("code").GetString());
        Assert.Equal("cleared", clearedBody.RootElement.GetProperty("localOutcome").GetString());

        // The fixture declares no revocation endpoint, so nothing was attempted and nothing left the
        // process. The local clear stands on its own.
        Assert.Equal("not-attempted", clearedBody.RootElement.GetProperty("providerOutcome").GetString());

        byte[] afterClear = ReadRecord(deployment);

        // A fresh store over the same root, which is what a restarted process reads, sees the floor.
        MutableSlotDecision? decision = await ReadDecisionAsync(deployment);
        Assert.NotNull(decision);
        Assert.False(decision!.IsLegacy);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision.Kind);
        Assert.Equal(3, decision.AuthorityEpoch);
        Assert.Equal(0, decision.RuntimeRevision);
        Assert.True(string.IsNullOrEmpty(decision.RefreshToken));

        using HttpResponseMessage again = await client.PostAsync(engine.At(ClearPath()), null, Token);
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);

        using JsonDocument againBody = JsonDocument.Parse(await again.Content.ReadAsStringAsync(Token));
        Assert.False(againBody.RootElement.GetProperty("cleared").GetBoolean());
        Assert.Equal("oauth/already-cleared", againBody.RootElement.GetProperty("code").GetString());

        // A no-op clear writes nothing at all, so it cannot advance an epoch or disturb the floor.
        Assert.Equal(afterClear, ReadRecord(deployment));
    }

    [Fact]
    public async Task Malformed_oversized_and_body_carrying_requests_are_refused()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);
        using HttpClient client = Authorized(OperatorSecret);

        // A repeated member is refused rather than resolved: two callers could disagree about which
        // target they named while the response describes only one.
        using HttpResponseMessage repeated = await client.GetAsync(
            engine.At(OAuthOperatorEndpoints.StatusPath + "?mount=" + MountPrefix + "&mount=/other"),
            Token);
        Assert.Equal(HttpStatusCode.BadRequest, repeated.StatusCode);

        using HttpResponseMessage empty = await client.GetAsync(
            engine.At(OAuthOperatorEndpoints.StatusPath + "?mount=&profile=" + ProfileId),
            Token);
        Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);

        using HttpResponseMessage missing = await client.PostAsync(
            engine.At(OAuthOperatorEndpoints.ClearPath + "?mount=" + MountPrefix),
            null,
            Token);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);

        foreach (string limit in new[] { "0", "99", "many" })
        {
            using HttpResponseMessage bounded = await client.GetAsync(
                engine.At(OAuthOperatorEndpoints.EventsPath + "?limit=" + limit),
                Token);
            Assert.Equal(HttpStatusCode.BadRequest, bounded.StatusCode);
        }

        using HttpContent body = new StringContent("{\"mount\":\"/api\"}", Encoding.UTF8, "application/json");
        using HttpResponseMessage withBody = await client.PostAsync(engine.At(ClearPath()), body, Token);
        Assert.Equal(HttpStatusCode.BadRequest, withBody.StatusCode);

        string oversized = OAuthOperatorEndpoints.StatusPath
            + "?mount=/" + new string('a', OAuthOperatorEndpoints.MaximumQueryCharacters);

        using HttpResponseMessage tooLong = await client.GetAsync(engine.At(oversized), Token);
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);

        // The relay routes read one small JSON body, so their shape is checked before the body is
        // read: absent, oversized and unreadable bodies are all refused, and an absent one is refused
        // rather than treated as an empty attempt request.
        using HttpResponseMessage noBody = await client.PostAsync(
            engine.At(OAuthOperatorEndpoints.AuthorizePath),
            null,
            Token);
        Assert.Equal(HttpStatusCode.BadRequest, noBody.StatusCode);

        using HttpContent oversizedBody = new StringContent(
            "{\"mount\":\"/api\",\"profile\":\"oauth\",\"redirectUri\":\"" + new string('a', OAuthOperatorEndpoints.MaximumBodyCharacters) + "\"}",
            Encoding.UTF8,
            "application/json");

        using HttpResponseMessage tooLarge = await client.PostAsync(
            engine.At(OAuthOperatorEndpoints.AuthorizePath),
            oversizedBody,
            Token);

        Assert.Equal(HttpStatusCode.BadRequest, tooLarge.StatusCode);

        using HttpContent unreadable = new StringContent("not json at all", Encoding.UTF8, "application/json");
        using HttpResponseMessage unreadableResponse = await client.PostAsync(
            engine.At(OAuthOperatorEndpoints.AuthorizeCompletePath),
            unreadable,
            Token);

        Assert.Equal(HttpStatusCode.BadRequest, unreadableResponse.StatusCode);

        // Nothing above reached the store.
        Assert.Null(await ReadDecisionAsync(deployment));
    }

    [Fact]
    public async Task A_burst_beyond_the_rate_window_is_refused_with_a_retry_hint()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);
        using HttpClient client = Authorized(OperatorSecret);

        List<HttpStatusCode> codes = [];

        for (int attempt = 0; attempt < (OAuthOperatorAdmission.MaximumRequestsPerWindow * 2) + 1; attempt++)
        {
            using HttpResponseMessage response = await client.GetAsync(
                engine.At(OAuthOperatorEndpoints.StatusPath),
                Token);

            codes.Add(response.StatusCode);

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                // A refused caller is told when to come back, so a scripted operator backs off rather
                // than retrying into the same window.
                Assert.NotNull(response.Headers.RetryAfter);
            }
        }

        Assert.Contains(HttpStatusCode.TooManyRequests, codes);

        // The channel recovers: the window slides, so a pause is admitted again rather than locking
        // the operator out for the lifetime of the process.
        await Task.Delay(TimeSpan.FromMilliseconds(1200), Token);

        using HttpResponseMessage recovered = await client.GetAsync(engine.At(OAuthOperatorEndpoints.StatusPath), Token);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
    }

    [Fact]
    public async Task Events_reports_the_bounded_sanitized_outcomes_of_a_clear()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());
        await using ServedEngine engine = await StartAsync(deployment);

        const string canary = "CANARY-operator-events-refresh-5c27";
        await SeedAuthorizedAsync(deployment, canary);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage cleared = await client.PostAsync(engine.At(ClearPath()), null, Token);
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);

        using HttpResponseMessage response = await client.GetAsync(
            engine.At(OAuthOperatorEndpoints.EventsPath + "?limit=" + AuthorizationOutcomeLog.DefaultMaximumEntries),
            Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string body = await response.Content.ReadAsStringAsync(Token);
        Assert.DoesNotContain(canary, body, StringComparison.Ordinal);

        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement root = document.RootElement;

        // The buffer is stated as in-memory and not durable, so a caller cannot read the response as
        // an audit history this process does not keep.
        Assert.False(root.GetProperty("durable").GetBoolean());
        Assert.Equal("in-memory", root.GetProperty("storage").GetString());
        Assert.Equal(AuthorizationOutcomeLog.DefaultMaximumEntries, root.GetProperty("maximumEntries").GetInt32());

        List<JsonElement> mine = [.. root.GetProperty("events")
            .EnumerateArray()
            .Where(entry => entry.GetProperty("mount").GetString() == MountPrefix
                && entry.GetProperty("profile").GetString() == ProfileId
                && entry.GetProperty("verb").GetString() == "clear")];

        Assert.Contains(mine, entry => entry.GetProperty("category").GetString() == "local"
            && entry.GetProperty("code").GetString() == "oauth/cleared");
        Assert.Contains(mine, entry => entry.GetProperty("category").GetString() == "provider"
            && entry.GetProperty("code").GetString() == "oauth/revocation-not-attempted");
    }

    [Fact]
    public async Task A_clear_stops_the_served_path_from_reusing_a_warm_token()
    {
        var cancellationToken = Token;

        // A real loopback provider and a real loopback upstream, so the served call is the production
        // path: acquire through the committed local authority, call the provider once, then call the
        // upstream with the acquired bearer.
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync("{\"ok\":true}"u8.ToArray(), context.RequestAborted);
            },
            cancellationToken);

        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true,
            cancellationToken,
            authorizationCode: provider);

        // The declared source must resolve, because the execution layer resolves a profile's declared
        // credentials before it consults the local authority. A file keeps that resolution local to
        // this test rather than mutating the process environment other suites share.
        string declared = Path.Combine(_root, "declared-" + Guid.NewGuid().ToString("N") + ".refresh");
        File.WriteAllText(declared, "CANARY-declared-refresh-9f21");

        Deployment deployment = CreateDeployment(ManifestOf(
            Origin(server.Address),
            Origin(upstream.Address),
            upstream.Address.GetLeftPart(UriPartial.Path),
            credential: $"{{ \"fromFile\": \"{declared.Replace('\\', '/')}\" }}"));

        await SeedAuthorizedAsync(
            deployment,
            Origin(server.Address),
            Origin(upstream.Address),
            refresh: provider.RefreshToken);

        await using ServedEngine engine = await StartAsync(deployment);

        // The first served call uses the committed local authority, asks the provider once, and caches
        // the access token against that authority.
        ToolOutcome served = await InvokeAsync(engine, cancellationToken);
        Assert.False(served.IsError, served.Text);
        Assert.Equal(1, provider.RefreshRequests);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage cleared = await client.PostAsync(engine.At(ClearPath()), null, Token);
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);

        // The second served call must refuse rather than serve the token the clear displaced, and must
        // not go back to the provider to mint one under the displaced authority.
        ToolOutcome refused = await InvokeAsync(engine, cancellationToken);
        Assert.True(refused.IsError, "The served path served a credential after its local authority was cleared.");
        Assert.Equal(1, provider.RefreshRequests);
    }

    [Fact]
    public async Task Managed_mode_maps_only_the_read_only_routes()
    {
        Deployment deployment = CreateDeployment(UnusedFixture());

        WebApplication managed = await StartManagedAsync(deployment);
        Uri address = new(managed.Urls.Single(), UriKind.Absolute);

        try
        {
            using HttpClient client = Authorized(OperatorSecret);

            using HttpResponseMessage capability = await client.GetAsync(
                new Uri(address, OAuthOperatorEndpoints.CapabilityPath),
                Token);
            Assert.Equal(HttpStatusCode.OK, capability.StatusCode);

            using JsonDocument document = JsonDocument.Parse(await capability.Content.ReadAsStringAsync(Token));
            Assert.Equal("managed", document.RootElement.GetProperty("mode").GetString());
            Assert.Equal("read-only", document.RootElement.GetProperty("state").GetString());

            string[] capabilities =
                [.. document.RootElement.GetProperty("capabilities").EnumerateArray().Select(entry => entry.GetString()!)];
            Assert.DoesNotContain("clear", capabilities);

            // Status is read-only and claims no local authority: managed authorizations are
            // Platform-owned, and reporting a file-mode state here would be a second authority for the
            // same fact.
            using HttpResponseMessage status = await client.GetAsync(
                new Uri(address, OAuthOperatorEndpoints.StatusPath),
                Token);
            Assert.Equal(HttpStatusCode.OK, status.StatusCode);

            using JsonDocument statusBody = JsonDocument.Parse(await status.Content.ReadAsStringAsync(Token));
            JsonElement profile = Assert.Single(statusBody.RootElement.GetProperty("profiles").EnumerateArray());
            Assert.Equal("managed", profile.GetProperty("state").GetString());
            Assert.Equal("oauth/managed", profile.GetProperty("code").GetString());
            Assert.Equal(0, profile.GetProperty("authorityEpoch").GetInt64());

            // The mutation route is not mapped at all, so a managed process advertises no local
            // authorization action it would only have to refuse.
            using HttpResponseMessage clear = await client.PostAsync(
                new Uri(address, OAuthOperatorEndpoints.ClearPath + "?mount=" + MountPrefix + "&profile=" + ProfileId),
                null,
                Token);
            Assert.Equal(HttpStatusCode.NotFound, clear.StatusCode);
        }
        finally
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await managed.StopAsync(shutdown.Token);
            await managed.DisposeAsync();
        }
    }

    [Fact]
    public void The_shipped_transport_rule_accepts_https_and_loopback_only()
    {
        Assert.True(OperatorChannel.IsTransportAcceptable(isHttps: true, IPAddress.Loopback));
        Assert.True(OperatorChannel.IsTransportAcceptable(isHttps: false, IPAddress.Loopback));
        Assert.False(OperatorChannel.IsTransportAcceptable(isHttps: false, IPAddress.Parse("10.0.0.5")));
        Assert.False(OperatorChannel.IsTransportAcceptable(isHttps: false, remote: null));
    }

    [Fact]
    public async Task The_admission_bound_refuses_one_beyond_it_transfers_released_slots_and_recovers()
    {
        var admission = new OAuthOperatorAdmission();
        List<IDisposable> running = [];

        for (int index = 0; index < OAuthOperatorAdmission.MaximumConcurrent; index++)
        {
            IDisposable? lease = await admission.TryEnterAsync(Token);
            Assert.NotNull(lease);
            running.Add(lease!);
        }

        Assert.Equal(OAuthOperatorAdmission.MaximumConcurrent, admission.Active);
        Assert.Equal(0, admission.Waiting);

        // The waiting set is bounded too, and a waiter is waiting rather than running. Each call
        // reaches its first suspension synchronously, so the call itself is enough to make the waiter
        // observable; nothing here awaits a task this test did not start.
        List<Task<IDisposable?>> waiting = [];

        for (int index = 0; index < OAuthOperatorAdmission.MaximumPending; index++)
        {
            waiting.Add(admission.TryEnterAsync(Token).AsTask());
        }

        await WaitUntilAsync(() => admission.Waiting == OAuthOperatorAdmission.MaximumPending);

        Assert.Equal(OAuthOperatorAdmission.MaximumConcurrent, admission.Active);
        Assert.Equal(OAuthOperatorAdmission.MaximumPending, admission.Waiting);

        // One beyond both bounds is refused rather than queued without limit, and the refusal names
        // the concurrency bound rather than the rate window.
        Assert.Null(await admission.TryEnterAsync(Token));
        Assert.Equal(OAuthOperatorAdmission.MaximumPending, admission.Waiting);
        Assert.False(admission.RateLimited);
        Assert.Equal(OAuthOperatorAdmission.MaximumPending, waiting.Count);

        // Releasing every running slot transfers each one to the oldest waiter, so the number of
        // operations in flight never exceeds the bound at any instant: the running count stays at the
        // ceiling while the queue drains by the same number.
        foreach (IDisposable lease in running)
        {
            lease.Dispose();
        }

        await WaitUntilAsync(() =>
            admission.Waiting == OAuthOperatorAdmission.MaximumPending - OAuthOperatorAdmission.MaximumConcurrent);

        Assert.Equal(OAuthOperatorAdmission.MaximumConcurrent, admission.Active);
        Assert.Equal(
            OAuthOperatorAdmission.MaximumPending - OAuthOperatorAdmission.MaximumConcurrent,
            admission.Waiting);

        // The rate window is a separate refusal: a fast loop is refused with the rate flag set, so the
        // caller can be told which bound it hit.
        var windowed = new OAuthOperatorAdmission();

        for (int index = 0; index < OAuthOperatorAdmission.MaximumRequestsPerWindow; index++)
        {
            (await windowed.TryEnterAsync(Token))?.Dispose();
        }

        Assert.Null(await windowed.TryEnterAsync(Token));
        Assert.True(windowed.RateLimited);
    }

    private static string ClearPath()
        => OAuthOperatorEndpoints.ClearPath + "?mount=" + MountPrefix + "&profile=" + ProfileId;

    private static string Origin(Uri address) => address.GetLeftPart(UriPartial.Authority);

    private static StringContent JsonContent(object payload)
        => new(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static HttpClient Authorized(
        string secret,
        string? generation = CompatibilitySchema.OAuthOperatorGeneration,
        int compatibilityHeaderValues = 1)
    {
        HttpClient client = new();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);

        if (generation is not null)
        {
            for (int index = 0; index < compatibilityHeaderValues; index++)
            {
                // Repeated members are refused rather than resolved: two values would let a caller and
                // this process disagree about which contract was negotiated.
                client.DefaultRequestHeaders.Add(CompatibilitySchema.ContractGenerationHeader, generation);
            }
        }

        return client;
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (int attempt = 0; attempt < 200 && !condition(); attempt++)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(10), Token);
        }
    }

    private sealed record Deployment(string ManifestDirectory, string StateRoot, string StoreRoot, string KeyFile);

    private static byte[] Key() => [.. Enumerable.Range(0, 32).Select(index => (byte)index)];

    private static string RecordPath(Deployment deployment)
        => Directory.GetFiles(deployment.StateRoot, "*.rstate", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.Ordinal)
            .First();

    private static byte[] ReadRecord(Deployment deployment) => File.ReadAllBytes(RecordPath(deployment));

    private static async Task<MutableSlotDecision?> ReadDecisionAsync(Deployment deployment)
        => await new FileMutableSlotStore(deployment.StateRoot, MountPrefix, Key())
            .LoadDecisionAsync(ProfileId, OAuthTokenService.RefreshTokenSlot, Token);

    /// <summary>The unused fixture: a valid deployment with no live provider behind it.</summary>
    private static string UnusedFixture()
        => ManifestOf(UnusedTokenAuthority, UnusedDestinationAuthority, UnusedDestinationAuthority);

    private Deployment CreateDeployment(string manifestText)
    {
        string identity = Guid.NewGuid().ToString("N");

        string manifestDirectory = Directory.CreateDirectory(Path.Combine(_root, "manifest-" + identity)).FullName;
        File.WriteAllText(Path.Combine(manifestDirectory, "manifest.json"), manifestText);

        string stateRoot = Directory.CreateDirectory(Path.Combine(_root, "state-" + identity)).FullName;
        string storeRoot = Directory.CreateDirectory(Path.Combine(_root, "files-" + identity)).FullName;
        string keyFile = Path.Combine(_root, "key-" + identity);
        File.WriteAllBytes(keyFile, Key());

        return new Deployment(manifestDirectory, stateRoot, storeRoot, keyFile);
    }

    private static RuntimeOptions Options(Deployment deployment)
        => new([new MountRequest(MountPrefix, deployment.ManifestDirectory)], deployment.StoreRoot)
        {
            RuntimeStateRoot = deployment.StateRoot,
            RuntimeStateKeyFile = deployment.KeyFile,
        };

    private async Task<ServedEngine> StartAsync(
        Deployment deployment,
        bool configureOperator = true,
        bool configureResponseCacheOperator = false)
        => await ServedEngine.StartAsync(
            Options(deployment),
            Token,
            operatorSecret: configureResponseCacheOperator ? ResponseCacheSecret : null,
            oauthOperatorSecret: configureOperator ? OperatorSecret : null);

    private async Task<WebApplication> StartManagedAsync(Deployment deployment)
    {
        RuntimeStartResult initial = EngineRuntime.Start(Options(deployment));

        Assert.True(
            initial.Started,
            "The runtime refused to start: "
                + string.Join("; ", initial.Refusals.Select(refusal => refusal.Code + " " + refusal.Message)));

        var manager = new EngineGenerationManager(HostMode.Managed);
        var drain = new DrainCoordinator();
        EngineExecution execution = EngineExecution.Create(initial, ServedEngine.Permissive());

        _ = manager.Activate(new EngineGeneration(
            number: 0,
            MountSet.From(initial),
            execution,
            ownsExecution: true));

        int port = LoopbackPorts.Reserve();

        WebApplication app = EngineWebHost.BuildManaged(
            new HostBinding(
                new RuntimeOptions([new MountRequest(MountPrefix, deployment.ManifestDirectory)], deployment.StoreRoot),
                new HostListenOptions($"http://127.0.0.1:{port}", HostTransport.Http),
                Authorization: null,
                HostLifecycleOptions.Default)
            {
                OAuthOperatorSecret = OperatorSecret,
            },
            drain,
            manager);

        await app.StartAsync(Token);
        return app;
    }

    /// <summary>
    /// Commits a local authorized decision for the fixture profile, as an earlier bootstrap would.
    /// </summary>
    private async Task SeedAuthorizedAsync(
        Deployment deployment,
        string refresh = "CANARY-seeded-refresh")
        => await SeedAuthorizedAsync(deployment, UnusedTokenAuthority, UnusedDestinationAuthority, refresh);

    private async Task SeedAuthorizedAsync(
        Deployment deployment,
        string tokenAuthority,
        string destinationAuthority,
        string refresh)
    {
        AuthenticationProfile profile = Profile(tokenAuthority, destinationAuthority);
        OAuthStrategyConfiguration configuration = OAuthStrategyConfiguration.FromConfiguration(
            profile.Configuration,
            authorizationCodeRequired: true);

        var decision = new MutableSlotDecision(
            profile.Id,
            OAuthTokenService.RefreshTokenSlot,
            profile.ScopeFingerprint,
            AuthorityBinding.Declaration(profile),
            AuthorityBinding.Configuration(configuration),
            2,
            0,
            MutableSlotDecisionKind.Authorized,
            refresh);

        _ = await new FileMutableSlotStore(deployment.StateRoot, MountPrefix, Key())
            .CompareAndCommitAsync(decision, expectedVersion: null, declaredEpoch: 1, Token);
    }

    private static async Task<ToolOutcome> InvokeAsync(ServedEngine engine, CancellationToken cancellationToken)
    {
        MountedManifest mount = Assert.Single(engine.Started.Mounts);
        MountedSurface surface = Assert.Single(mount.Surfaces);

        return await engine.Execution.InvokeAsync(
            mount,
            surface,
            mount.Prefix + "/" + surface.Slug,
            Tool,
            [],
            negotiatedProtocolRevision: null,
            cancellationToken,
            CallerPartition.Public);
    }

    /// <summary>The OAuth configuration both the Manifest and the in-code twin carry.</summary>
    private static string ConfigurationOf(string tokenAuthority)
        => "{\"strategyId\":\"oauth2-authorization-code-pkce-refresh\","
            + "\"inputs\":{\"clientId\":\"test-client\"},"
            + "\"clientId\":\"test-client\","
            + "\"tokenAuthMethod\":\"none\","
            + $"\"authorizationEndpoint\":\"{tokenAuthority}/authorize\","
            + $"\"tokenEndpoint\":\"{tokenAuthority}/token\"}}";

    private static AuthenticationProfile Profile(string tokenAuthority, string destinationAuthority)
        => new(
            ProfileId,
            AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
            CanonicalJson.Parse(Encoding.UTF8.GetBytes(ConfigurationOf(tokenAuthority)))!.AsObject(),
            [tokenAuthority],
            [destinationAuthority],
            ["oauth-refresh"],
            ManifestScopeFingerprint,
            [new AuthenticationSlot(OAuthTokenService.RefreshTokenSlot, 1, 0)]);

    /// <summary>
    /// A minimal Manifest whose one protected surface uses one authorization-code profile.
    /// </summary>
    /// <param name="tokenAuthority">The canonical authority holding the OAuth endpoints.</param>
    /// <param name="destinationAuthority">The canonical authority the protected operation calls.</param>
    /// <param name="destinationBase">The base URL the protected operation is compiled against.</param>
    /// <param name="credential">
    /// The declared refresh credential's value reference. The default names an environment variable no
    /// test sets, which is the unresolved declared source these fixtures are built around.
    /// </param>
    /// <param name="protectedMount">
    /// Whether the mount requires a bearer token. A protected mount also declares the scope its one
    /// surface requires, because a scope under an unprotected mount is a startup refusal.
    /// </param>
    private static string ManifestOf(
        string tokenAuthority,
        string destinationAuthority,
        string destinationBase,
        string? credential = null,
        bool protectedMount = false)
    {
        // A protected mount states the scope its one routing surface requires. The member belongs to
        // the server-section surface, and the surface it names must be the one the MCP route serves.
        string surfaces = protectedMount
            ? ", \"surfaces\": [ { \"slug\": \"" + Tool + "\", \"isDefault\": true, "
                + "\"requiredScopes\": [\"tools.invoke\"], "
                + "\"operations\": [ { \"operation\": \"" + Tool + "\" } ] } ]"
            : string.Empty;

        return $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Authorization Operator Probe", "authenticationRequired": {{(protectedMount ? "true" : "false")}}{{surfaces}} } },
                "policy": { "inline": { "baseUrl": "{{destinationBase}}" } },
                "operations": {
                  "inline": {
                    "operations": [
                      {
                        "key": "GET /things",
                        "method": "GET",
                        "path": "/things",
                        "responses": { "200": { "content": { "application/json": { "schema": { "type": "object" } } } } }
                      }
                    ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "{{Tool}}",
                        "name": "List things",
                        "binding": { "type": "http", "operation": "GET /things", "authenticationRef": "{{ProfileId}}" }
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
                        "value": {{credential ?? "{ \"fromEnv\": \"MCPILER_OPERATOR_UNSET_REFRESH\" }"}}
                      }
                    ]
                  }
                },
                "authentication": {
                  "inline": {
                    "formatVersion": 2,
                    "profiles": [
                      {
                        "id": "{{ProfileId}}",
                        "kind": "oauth2-authorization-code-pkce-refresh",
                        "configuration": {{ConfigurationOf(tokenAuthority)}},
                        "authenticationOrigins": ["{{tokenAuthority}}"],
                        "destinationOrigins": ["{{destinationAuthority}}"],
                        "credentialRef": ["oauth-refresh"],
                        "scopeFingerprint": "{{ManifestScopeFingerprint}}",
                        "slots": [ { "slot": "refreshToken", "authorityEpoch": 1, "runtimeRevision": 0 } ]
                      }
                    ]
                  }
                }
              }
            }
            """;
    }
}
