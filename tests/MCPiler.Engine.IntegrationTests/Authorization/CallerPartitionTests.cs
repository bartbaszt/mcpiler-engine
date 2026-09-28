using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authorization;

/// <summary>
/// The caller partition the authorization boundary settles before a response-cache decision.
/// </summary>
/// <remarks>
/// <para>
/// The partition is the boundary's answer to "which caller is this, as far as caching may
/// tell?". It is derived here and consumed later, so the tests drive the real middleware
/// against a real started runtime, a real leased generation and a real admission feature: a
/// hand-assembled harness would agree with itself about which token, resource and scope set
/// were consulted while the product consulted something else.
/// </para>
/// <para>
/// The derivation is opaque and process-keyed, so every assertion is about equality, inequality
/// and what must not appear in the value - never about the value itself. A test that pinned the
/// bytes would be pinning one process's key.
/// </para>
/// <para>
/// Distinctness at the MCP boundary becomes externally observable only once the response cache
/// exists, because there is nothing a client can see that depends on the partition today. These
/// tests therefore prove it at the layer that derives it, and the cache boundary adds the
/// end-to-end assertion.
/// </para>
/// </remarks>
public sealed class CallerPartitionTests : IDisposable
{
    private const string Scheme = "http";
    private const string Host = "127.0.0.1:15000";
    private const string FullAddress = "/api/full";
    private const string OtherAddress = "/api/other";

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-caller-partition-" + Guid.NewGuid().ToString("N"));

    public CallerPartitionTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    // ---- what the derivation is keyed on -------------------------------------------------

    [Fact]
    public void One_identity_and_one_process_key_derive_one_stable_value()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);

        string value = CallerPartitionDerivation.Derive("token-a", "http://host/api/full", ["tools.invoke"], key);

        Assert.Equal(value, CallerPartitionDerivation.Derive("token-a", "http://host/api/full", ["tools.invoke"], key));

        // Every admitted fact is an input: a different presented bearer, resource or scope set
        // must reach a different partition, or two callers the boundary can tell apart would
        // share a cache entry.
        Assert.NotEqual(value, CallerPartitionDerivation.Derive("token-b", "http://host/api/full", ["tools.invoke"], key));
        Assert.NotEqual(value, CallerPartitionDerivation.Derive("token-a", "http://host/api/other", ["tools.invoke"], key));
        Assert.NotEqual(value, CallerPartitionDerivation.Derive("token-a", "http://host/api/full", ["tools.admin"], key));

        // A different process key derives a different value for the same identity, which is what
        // makes a stored partition useless to anyone who does not hold the key.
        Assert.NotEqual(
            value,
            CallerPartitionDerivation.Derive("token-a", "http://host/api/full", ["tools.invoke"], RandomNumberGenerator.GetBytes(32)));
    }

    /// <summary>
    /// The scope set is normalized, because order and repetition are not authorization facts.
    /// </summary>
    /// <remarks>
    /// An issuer may order the scope claim any way it likes and may repeat a scope; two tokens
    /// that require the same scopes to be present authorize identically, so a partition that
    /// differed by layout would split one caller into two cache partitions for no reason.
    /// </remarks>
    [Fact]
    public void Scope_order_and_repetition_do_not_change_the_partition()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);

        string canonical = CallerPartitionDerivation.Derive(
            "token-a",
            "http://host/api/full",
            ["tools.admin", "tools.invoke"],
            key);

        Assert.Equal(
            canonical,
            CallerPartitionDerivation.Derive("token-a", "http://host/api/full", ["tools.invoke", "tools.admin"], key));

        Assert.Equal(
            canonical,
            CallerPartitionDerivation.Derive("token-a", "http://host/api/full", ["tools.invoke", "tools.admin", "tools.invoke"], key));
    }

    /// <summary>
    /// Length-delimited encoding keeps concatenation boundaries out of the derived identity.
    /// </summary>
    /// <remarks>
    /// A derivation that joined its inputs without saying where each one ended would call
    /// <c>("ab", "c")</c> and <c>("a", "bc")</c> the same identity, and two callers distinguished
    /// only by where one string stopped and the next began would share a cache entry.
    /// </remarks>
    [Fact]
    public void Adjacent_input_boundaries_cannot_collide()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);

        Assert.NotEqual(
            CallerPartitionDerivation.Derive("ab", "c", ["s"], key),
            CallerPartitionDerivation.Derive("a", "bc", ["s"], key));
    }

    // ---- what the middleware settles -----------------------------------------------------

    [Fact]
    public async Task Different_bearers_for_one_resource_and_scope_set_get_different_partitions()
    {
        string resource = $"{Scheme}://{Host}{FullAddress}";

        Outcome first = await InvokeAsync(
            new StubValidator(_ => Active(resource, "tools.invoke")),
            ProtectedManifest(),
            authorization: "Bearer token-a");
        Outcome second = await InvokeAsync(
            new StubValidator(_ => Active(resource, "tools.invoke")),
            ProtectedManifest(),
            authorization: "Bearer token-b");

        Assert.True(first.NextCalled);
        Assert.True(second.NextCalled);

        CallerPartition one = Assert.IsType<CallerPartition>(first.Admission.CallerPartition);
        CallerPartition two = Assert.IsType<CallerPartition>(second.Admission.CallerPartition);

        Assert.True(one.IsCallerSpecific);
        Assert.True(two.IsCallerSpecific);
        Assert.NotEqual(one.OpaqueValue, two.OpaqueValue);

        // The value names the caller without carrying it: the presented token must not be
        // recoverable from what a later cache key or diagnostic would record.
        Assert.DoesNotContain("token-a", one.OpaqueValue, StringComparison.Ordinal);
    }

    /// <summary>
    /// A token admitted for one address is a different caller than the same token at another.
    /// </summary>
    /// <remarks>
    /// The canonical resource is part of what the boundary decided: a client authorized for one
    /// addressed surface and the same client authorized for its sibling are two authorization
    /// scopes, and a response admitted for one must not be served for the other.
    /// </remarks>
    [Fact]
    public async Task One_bearer_on_two_resources_gets_two_partitions()
    {
        Outcome onFull = await InvokeAsync(
            new StubValidator(_ => Active($"{Scheme}://{Host}{FullAddress}", "tools.invoke", "tools.admin")),
            ProtectedManifest(),
            address: FullAddress,
            requestPath: FullAddress);
        Outcome onOther = await InvokeAsync(
            new StubValidator(_ => Active($"{Scheme}://{Host}{OtherAddress}", "tools.invoke", "tools.admin")),
            ProtectedManifest(),
            address: OtherAddress,
            requestPath: OtherAddress);

        Assert.True(onFull.NextCalled);
        Assert.True(onOther.NextCalled);

        // Both runs carried one bearer and one scope set; only the addressed resource differs.
        Assert.NotEqual(
            onFull.Admission.CallerPartition!.OpaqueValue,
            onOther.Admission.CallerPartition!.OpaqueValue);
    }

    [Fact]
    public async Task One_bearer_with_two_scope_sets_gets_two_partitions()
    {
        string resource = $"{Scheme}://{Host}{FullAddress}";

        Outcome invokeOnly = await InvokeAsync(
            new StubValidator(_ => Active(resource, "tools.invoke")),
            ProtectedManifest(),
            authorization: "Bearer token-a");
        Outcome withAdmin = await InvokeAsync(
            new StubValidator(_ => Active(resource, "tools.invoke", "tools.admin")),
            ProtectedManifest(),
            authorization: "Bearer token-a");

        Assert.True(invokeOnly.NextCalled);

        // The wider token is admitted too: the surface's scope set is a requirement, not a
        // ceiling. It is nevertheless a different authorization scope, so it is a different
        // partition.
        Assert.True(withAdmin.NextCalled);
        Assert.NotEqual(
            invokeOnly.Admission.CallerPartition!.OpaqueValue,
            withAdmin.Admission.CallerPartition!.OpaqueValue);
    }

    /// <summary>
    /// No optional identity claim is a prerequisite of being partitioned.
    /// </summary>
    /// <remarks>
    /// <see cref="TokenVerification"/> carries audience, scopes and expiry and nothing else, so
    /// the derivation cannot depend on <c>sub</c> or <c>client_id</c> even accidentally: an
    /// issuer that omits them, which a standards-compliant issuer is free to do, still yields a
    /// caller-specific partition.
    /// </remarks>
    [Fact]
    public async Task A_token_whose_verification_carries_no_identity_claim_still_partitions()
    {
        string resource = $"{Scheme}://{Host}{FullAddress}";

        Outcome outcome = await InvokeAsync(
            new StubValidator(_ => Active(resource, "tools.invoke")),
            ProtectedManifest(),
            authorization: "Bearer token-a");

        Assert.True(outcome.NextCalled);

        CallerPartition partition = Assert.IsType<CallerPartition>(outcome.Admission.CallerPartition);

        Assert.True(partition.IsCallerSpecific);
    }

    // ---- what is settled when the boundary refuses ---------------------------------------

    [Fact]
    public async Task An_inactive_token_is_challenged_without_settling_a_partition()
    {
        Outcome refused = await InvokeAsync(
            new StubValidator(_ => TokenVerification.Inactive),
            ProtectedManifest(),
            authorization: "Bearer token-a");

        Assert.False(refused.NextCalled);
        Assert.Equal(StatusCodes.Status401Unauthorized, refused.StatusCode);

        // No caller-specific partition was settled. A refusal that left a partition behind would
        // let a cache admit or serve under an identity the boundary never accepted.
        Assert.Null(refused.Admission.CallerPartition);
    }

    [Fact]
    public async Task A_token_for_another_resource_is_refused_without_settling_a_partition()
    {
        Outcome refused = await InvokeAsync(
            new StubValidator(_ => Active($"{Scheme}://{Host}/api/nothing", "tools.invoke")),
            ProtectedManifest(),
            authorization: "Bearer token-a");

        Assert.False(refused.NextCalled);
        Assert.Equal(StatusCodes.Status404NotFound, refused.StatusCode);
        Assert.Null(refused.Admission.CallerPartition);
    }

    [Fact]
    public async Task A_token_missing_a_required_scope_is_refused_without_settling_a_partition()
    {
        Outcome refused = await InvokeAsync(
            new StubValidator(_ => Active($"{Scheme}://{Host}{FullAddress}", "tools.write")),
            ProtectedManifest(),
            authorization: "Bearer token-a");

        Assert.False(refused.NextCalled);
        Assert.Equal(StatusCodes.Status404NotFound, refused.StatusCode);
        Assert.Null(refused.Admission.CallerPartition);
    }

    // ---- mounts that authorize nobody ----------------------------------------------------

    /// <summary>
    /// An open mount states one public partition rather than leaving the identity unset.
    /// </summary>
    /// <remarks>
    /// Every caller of an open mount is indistinguishable to the boundary, and saying so is
    /// different from saying nothing: an unset partition is a cache bypass, while the public
    /// partition is an explicit identity that a cache may use for a mount served without tokens.
    /// The bearer is not even validated, because there is nothing to validate it against.
    /// </remarks>
    [Fact]
    public async Task An_open_mount_settles_the_public_partition()
    {
        StubValidator validator = new(_ => TokenVerification.Inactive);

        Outcome served = await InvokeAsync(
            validator,
            OpenManifest(),
            authorization: null);

        Assert.True(served.NextCalled);
        Assert.Equal(CallerPartition.Public, served.Admission.CallerPartition);
        Assert.False(served.Admission.CallerPartition!.IsCallerSpecific);
        Assert.Null(validator.Presented);
    }

    /// <summary>A host endpoint that addresses no surface has no mount decision to make.</summary>
    [Fact]
    public async Task A_request_without_an_admission_passes_through_untouched()
    {
        bool nextCalled = false;
        var middleware = new MountAuthorizationMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            new StubValidator(_ => TokenVerification.Inactive),
            new CallerPartitionKey());

        var context = new DefaultHttpContext();

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    // ---- harness ------------------------------------------------------------------------

    private static TokenVerification Active(string audience, params string[] scopes)
        => new(true, audience, scopes);

    /// <summary>One protected mount with a default surface and a sibling that declares more.</summary>
    private static string ProtectedManifest()
        => """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": {
                  "inline": {
                    "name": "Partition API",
                    "authenticationRequired": true,
                    "surfaces": [
                      {
                        "slug": "full",
                        "isDefault": true,
                        "requiredScopes": ["tools.invoke"],
                        "operations": [ { "operation": "read-value" } ]
                      },
                      {
                        "slug": "other",
                        "requiredScopes": ["tools.invoke", "tools.admin"],
                        "operations": [ { "operation": "read-value" } ]
                      }
                    ]
                  }
                },
                "policy": { "inline": { "baseUrl": "https://api.example.test/" } },
                "operations": {
                  "inline": {
                    "operations": [ { "key": "GET /value", "method": "GET", "path": "/value" } ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "read-value",
                        "name": "Read value",
                        "inputSchema": { "type": "object" },
                        "binding": { "type": "http", "operation": "GET /value" }
                      }
                    ]
                  }
                }
              }
            }
            """;

    /// <summary>
    /// The same topology served without tokens. Scopes are absent rather than empty, because a
    /// scope under an open mount restricts no token and the loader refuses the combination.
    /// </summary>
    private static string OpenManifest()
        => """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": {
                  "inline": {
                    "name": "Partition API",
                    "authenticationRequired": false,
                    "surfaces": [
                      {
                        "slug": "full",
                        "isDefault": true,
                        "operations": [ { "operation": "read-value" } ]
                      }
                    ]
                  }
                },
                "policy": { "inline": { "baseUrl": "https://api.example.test/" } },
                "operations": {
                  "inline": {
                    "operations": [ { "key": "GET /value", "method": "GET", "path": "/value" } ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "read-value",
                        "name": "Read value",
                        "inputSchema": { "type": "object" },
                        "binding": { "type": "http", "operation": "GET /value" }
                      }
                    ]
                  }
                }
              }
            }
            """;

    /// <summary>What one middleware invocation decided.</summary>
    private sealed record Outcome(
        bool NextCalled,
        EngineRequestGenerationAdmission Admission,
        int StatusCode);

    /// <summary>
    /// Runs the real middleware over a real started runtime, generation and admission.
    /// </summary>
    /// <param name="validator">The validation standing the test declares for the offered token.</param>
    /// <param name="manifest">The mount document to load.</param>
    /// <param name="authorization">The Authorization header, or <c>null</c> to offer none.</param>
    /// <param name="address">The admitted surface address the request reached.</param>
    /// <param name="requestPath">The raw request path, which the canonical resource preserves.</param>
    private async Task<Outcome> InvokeAsync(
        StubValidator validator,
        string manifest,
        string? authorization = "Bearer token-a",
        string address = FullAddress,
        string requestPath = FullAddress)
    {
        string bundle = ServedManifests.Write(_root, "mount-" + Guid.NewGuid().ToString("N"), manifest);
        string store = Directory.CreateDirectory(
            Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName;

        RuntimeStartResult started = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", bundle)], store));

        Assert.True(
            started.Started,
            "The Manifest must load: " + string.Join("; ", started.Refusals.Select(refusal => refusal.Code + " " + refusal.Message)));

        EngineExecution execution = EngineExecution.Create(started, ServedEngine.Permissive());

        try
        {
            var generation = new EngineGeneration(0, MountSet.From(started), execution, ownsExecution: false);

            Assert.True(generation.TryResolve(address, out SurfaceResolution? resolution));
            Assert.NotNull(resolution);

            string resourceIdentity = MountAuthorization.CanonicalResource(Scheme, Host, requestPath);
            var admission = new EngineRequestGenerationAdmission(
                address,
                requestPath,
                resourceIdentity,
                generation,
                resolution);

            bool nextCalled = false;
            var middleware = new MountAuthorizationMiddleware(
                _ =>
                {
                    nextCalled = true;
                    return Task.CompletedTask;
                },
                validator,
                new CallerPartitionKey());

            var context = new DefaultHttpContext();
            context.Request.Scheme = Scheme;
            context.Request.Host = new HostString(Host);
            context.Request.Method = HttpMethods.Post;
            context.Request.Path = requestPath;

            if (authorization is not null)
            {
                context.Request.Headers.Authorization = authorization;
            }

            context.SetEndpoint(new Endpoint(
                static _ => Task.CompletedTask,
                new EndpointMetadataCollection(new SurfaceEndpoint(address)),
                "caller-partition-test"));
            context.Features.Set(admission);

            await middleware.InvokeAsync(context);

            return new Outcome(nextCalled, admission, context.Response.StatusCode);
        }
        finally
        {
            execution.Dispose();
        }
    }

    /// <summary>A validator whose standing is stated by the test, recording what it saw.</summary>
    private sealed class StubValidator(Func<string, TokenVerification> verify) : ITokenValidator
    {
        /// <summary>The last presented token, or <c>null</c> when validation never ran.</summary>
        public string? Presented { get; private set; }

        public Task<TokenVerification> ValidateAsync(string token, CancellationToken cancellationToken)
        {
            Presented = token;
            return Task.FromResult(verify(token));
        }
    }
}
