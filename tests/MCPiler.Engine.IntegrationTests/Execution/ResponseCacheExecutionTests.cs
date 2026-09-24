using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

#pragma warning disable VSTHRD003 // Bounded task-completion barriers coordinate concurrent invocations.

namespace MCPiler.Engine.IntegrationTests.Execution;

public sealed class ResponseCacheExecutionTests
{
    [Fact]
    public async Task Identical_successful_requests_hit_cache_and_reapply_output_transform()
    {
        int sends = 0;
        string? observedUserAgent = null;
        string? observedAcceptEncoding = null;
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            observedUserAgent = context.Request.Headers.UserAgent.ToString();
            observedAcceptEncoding = context.Request.Headers.AcceptEncoding.ToString();
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.Headers["X-Page"] = "page-1";
            context.Response.Headers["Vary"] = "User-Agent, Accept-Encoding, Host";
            await context.Response.WriteAsync("{\"data\":{\"id\":7},\"noise\":true}", context.RequestAborted);
        });

        ManifestOperation operation = ExecutionManifests.Operation();
        var manifest = ExecutionManifests.For(
            host.Address,
            operation: operation,
            binding: new TransformedHttpBinding(
                new HttpBinding(operation.Key),
                OutputProgram: OutputProjection()),
            responseCache: new ResponseCachePolicySettings(300));

        using CachedHarness harness = new();
        EngineExecutionResult first = await InvokeAsync(harness, manifest);
        EngineExecutionResult second = await InvokeAsync(harness, manifest);

        Assert.True(first.Succeeded, first.FailureReason);
        Assert.True(second.Succeeded, second.FailureReason);
        Assert.Equal(1, sends);
        Assert.Equal(1, harness.Cache.EntryCount);
        Assert.Equal(UpstreamClientFactory.UserAgent, observedUserAgent);
        Assert.Equal(UpstreamRequestDefaults.AcceptEncoding, observedAcceptEncoding);
        Assert.Equal(200, second.StatusCode);
        Assert.Equal("page-1", second.ResponseHeaders!["X-Page"].Single());
        Assert.Equal(Encoding.UTF8.GetString(first.ResponseBody!), Encoding.UTF8.GetString(second.ResponseBody!));
        Assert.Contains("\"result\":{\"id\":7}", Encoding.UTF8.GetString(second.ResponseBody!), StringComparison.Ordinal);
        Assert.Contains("\"page\":\"page-1\"", Encoding.UTF8.GetString(second.ResponseBody!), StringComparison.Ordinal);
    }

    [Fact]
    public async Task No_store_and_unsuccessful_responses_are_returned_but_never_retained()
    {
        int noStoreSends = 0;
        await using LoopbackHost noStoreHost = await StartAsync(async context =>
        {
            Interlocked.Increment(ref noStoreSends);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            context.Response.Headers["Cache-Control"] = "public, no-store";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        int refusedStatusSends = 0;
        await using LoopbackHost refusedStatusHost = await StartAsync(async context =>
        {
            Interlocked.Increment(ref refusedStatusSends);
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            context.Response.ContentType = "application/json";
            context.Response.Headers["Cache-Control"] = "max-age=120";
            await context.Response.WriteAsync("{\"retry\":true}", context.RequestAborted);
        });

        using CachedHarness noStoreHarness = new();
        ManifestDocument noStoreManifest = Cacheable(noStoreHost.Address);
        EngineExecutionResult noStoreFirst = await InvokeAsync(noStoreHarness, noStoreManifest);
        EngineExecutionResult noStoreSecond = await InvokeAsync(noStoreHarness, noStoreManifest);

        Assert.True(noStoreFirst.Succeeded, noStoreFirst.FailureReason);
        Assert.True(noStoreSecond.Succeeded, noStoreSecond.FailureReason);
        Assert.Equal(2, noStoreSends);
        Assert.Equal(0, noStoreHarness.Cache.EntryCount);

        using CachedHarness refusedHarness = new();
        ManifestDocument refusedManifest = Cacheable(refusedStatusHost.Address);
        EngineExecutionResult refusedFirst = await InvokeAsync(refusedHarness, refusedManifest);
        EngineExecutionResult refusedSecond = await InvokeAsync(refusedHarness, refusedManifest);

        Assert.True(refusedFirst.Succeeded, refusedFirst.FailureReason);
        Assert.True(refusedSecond.Succeeded, refusedSecond.FailureReason);
        Assert.Equal(StatusCodes.Status429TooManyRequests, refusedSecond.StatusCode);
        Assert.Equal(2, refusedStatusSends);
        Assert.Equal(0, refusedHarness.Cache.EntryCount);
    }

    [Fact]
    public async Task Redirected_responses_are_returned_normally_but_not_admitted()
    {
        int sends = 0;
        ConcurrentQueue<string?> directives = new();
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            directives.Enqueue(context.Request.Headers["Cache-Control"].FirstOrDefault());
            if (context.Request.Path == "/thing")
            {
                context.Response.StatusCode = StatusCodes.Status302Found;
                context.Response.Headers.Location = "/final";
                return;
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        using CachedHarness harness = new();
        ManifestDocument manifest = Cacheable(host.Address);
        EngineExecutionResult first = await InvokeAsync(harness, manifest);
        EngineExecutionResult second = await InvokeAsync(harness, manifest);

        Assert.True(first.Succeeded, first.FailureReason);
        Assert.True(second.Succeeded, second.FailureReason);
        Assert.Equal(4, sends);
        Assert.Equal(0, harness.Cache.EntryCount);
    }

    [Fact]
    public async Task Cache_entry_size_limit_bypasses_admission_without_failing_live_response()
    {
        int sends = 0;
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("still-a-valid-live-response", context.RequestAborted);
        });

        using CachedHarness harness = new(new ResponseCacheOptions { MaxBodyBytes = 4 });
        ManifestDocument manifest = Cacheable(host.Address);
        EngineExecutionResult first = await InvokeAsync(harness, manifest);
        EngineExecutionResult second = await InvokeAsync(harness, manifest);

        Assert.True(first.Succeeded, first.FailureReason);
        Assert.True(second.Succeeded, second.FailureReason);
        Assert.Equal("still-a-valid-live-response", Encoding.UTF8.GetString(second.ResponseBody!));
        Assert.Equal(2, sends);
        Assert.Equal(0, harness.Cache.EntryCount);
    }

    [Fact]
    public async Task Cache_hit_rechecks_narrower_invocation_response_limit()
    {
        int sends = 0;
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"payload\":\"0123456789\"}", context.RequestAborted);
        });

        using CachedHarness harness = new();
        ManifestDocument manifest = Cacheable(host.Address);
        EngineExecutionResult warmed = await InvokeAsync(harness, manifest);
        EngineExecutionResult narrowed = await InvokeAsync(harness, manifest, responseSizeLimitBytes: 8);
        EngineExecutionResult ordinary = await InvokeAsync(harness, manifest);

        Assert.True(warmed.Succeeded, warmed.FailureReason);
        Assert.Equal(ExecutionFailureKind.ResponseSize, narrowed.Failure);
        Assert.Null(narrowed.ResponseBody);
        Assert.True(ordinary.Succeeded, ordinary.FailureReason);
        Assert.Equal(2, sends);
    }

    [Fact]
    public async Task Arguments_headers_and_materialized_body_each_separate_request_keys()
    {
        ConcurrentQueue<string> requests = new();
        await using LoopbackHost host = await StartAsync(async context =>
        {
            using MemoryStream body = new();
            await context.Request.Body.CopyToAsync(body, context.RequestAborted);
            requests.Enqueue(string.Join(
                "|",
                context.Request.QueryString.Value,
                context.Request.Headers["X-Mode"].ToString(),
                Encoding.UTF8.GetString(body.ToArray())));
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        ManifestOperation operation = ExecutionManifests.Operation(
            parameters:
            [
                new ManifestParameter("id", ParameterLocation.Query),
                new ManifestParameter("X-Mode", ParameterLocation.Header),
            ],
            requestBody: new ManifestRequestBody(
                new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal)
                {
                    ["application/json"] = new("application/json"),
                }));
        ManifestDocument manifest = ExecutionManifests.For(
            host.Address,
            operation: operation,
            responseCache: new ResponseCachePolicySettings(300));

        using CachedHarness harness = new();
        JsonObject original = RequestArguments("a", "one", "body-a");
        Assert.True((await InvokeAsync(harness, manifest, original)).Succeeded);
        Assert.True((await InvokeAsync(harness, manifest, RequestArguments("a", "one", "body-a"))).Succeeded);
        Assert.True((await InvokeAsync(harness, manifest, RequestArguments("b", "one", "body-a"))).Succeeded);
        Assert.True((await InvokeAsync(harness, manifest, RequestArguments("a", "two", "body-a"))).Succeeded);
        Assert.True((await InvokeAsync(harness, manifest, RequestArguments("a", "one", "body-b"))).Succeeded);

        Assert.Equal(4, requests.Count);
        Assert.Equal(4, harness.Cache.EntryCount);
        Assert.Contains("?id=a|one|\"body-a\"", requests);
        Assert.Contains("?id=b|one|\"body-a\"", requests);
        Assert.Contains("?id=a|two|\"body-a\"", requests);
        Assert.Contains("?id=a|one|\"body-b\"", requests);
    }

    [Fact]
    public async Task Request_no_cache_directive_bypasses_lookup_and_admission()
    {
        int sends = 0;
        ConcurrentQueue<string?> directives = new();
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            directives.Enqueue(context.Request.Headers["Cache-Control"].FirstOrDefault());
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        ManifestOperation operation = ExecutionManifests.Operation(
            parameters: [new ManifestParameter("Cache-Control", ParameterLocation.Header)]);
        ManifestDocument manifest = ExecutionManifests.For(
            host.Address,
            operation: operation,
            responseCache: new ResponseCachePolicySettings(300));

        using CachedHarness harness = new();
        JsonObject arguments = new() { ["Cache-Control"] = "no-cache" };
        EngineExecutionResult first = await InvokeAsync(harness, manifest, (JsonObject)arguments.DeepClone());
        EngineExecutionResult second = await InvokeAsync(harness, manifest, (JsonObject)arguments.DeepClone());

        Assert.True(first.Succeeded, first.FailureReason);
        Assert.True(second.Succeeded, second.FailureReason);
        Assert.All(directives, directive => Assert.Equal("no-cache", directive));
        Assert.Equal(2, sends);
        Assert.Equal(0, harness.Cache.EntryCount);
    }

    [Fact]
    public async Task A_non_get_operation_uses_the_live_path_without_evicting_a_cached_get()
    {
        int sends = 0;
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"method\":\"" + context.Request.Method + "\"}", context.RequestAborted);
        });

        ManifestOperation get = ExecutionManifests.Operation();
        ManifestOperation post = ExecutionManifests.Operation(method: "POST");
        ManifestDocument manifest = ExecutionManifests.For(
            host.Address,
            operation: get,
            responseCache: new ResponseCachePolicySettings(300)) with
        {
            Operations = new OperationsSection([get, post]),
            AgentSurface = new AgentSurfaceSection(
            [
                new AgentOperationEntry(
                    ExecutionManifests.Slug,
                    "Get thing",
                    new HttpBinding(get.Key),
                    ResponseCache: new ResponseCachePolicySettings(300)),
                new AgentOperationEntry("post-thing", "Post thing", new HttpBinding(post.Key)),
            ]),
        };

        using CachedHarness harness = new();
        EngineExecutionResult warmedGet = await InvokeAsync(harness, manifest);
        EngineExecutionResult mutation = await InvokeAsync(harness, manifest, slug: "post-thing");
        EngineExecutionResult cachedGet = await InvokeAsync(harness, manifest);

        Assert.True(warmedGet.Succeeded, warmedGet.FailureReason);
        Assert.True(mutation.Succeeded, mutation.FailureReason);
        Assert.True(cachedGet.Succeeded, cachedGet.FailureReason);
        Assert.Equal("{\"method\":\"GET\"}", Encoding.UTF8.GetString(cachedGet.ResponseBody!));
        Assert.Equal(2, sends);
        Assert.Equal(1, harness.Cache.EntryCount);
    }

    [Fact]
    public async Task Concurrent_identical_execution_misses_share_one_upstream_send()
    {
        const int callers = 8;
        int sends = 0;
        TaskCompletionSource upstreamEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseUpstream = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            upstreamEntered.TrySetResult();
            await releaseUpstream.Task.WaitAsync(context.RequestAborted);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        using CachedHarness harness = new();
        ManifestDocument manifest = Cacheable(host.Address);
        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<EngineExecutionResult>[] invocations = Enumerable.Range(0, callers)
            .Select(async _ =>
            {
                await start.Task;
                return await InvokeAsync(harness, manifest);
            })
            .ToArray();

        start.TrySetResult();
        try
        {
            using CancellationTokenSource waitBudget = CancellationTokenSource.CreateLinkedTokenSource(
                TestContext.Current.CancellationToken);
            waitBudget.CancelAfter(TimeSpan.FromSeconds(10));
            await upstreamEntered.Task.WaitAsync(waitBudget.Token);
            await WaitUntilAsync(() => harness.Cache.WaitingCallerCount == callers - 1, waitBudget.Token);
            Assert.Equal(1, sends);
        }
        finally
        {
            releaseUpstream.TrySetResult();
        }

        EngineExecutionResult[] results = await Task.WhenAll(invocations);

        Assert.All(results, result => Assert.True(result.Succeeded, result.FailureReason));
        Assert.All(results, result => Assert.Equal("{\"ok\":true}", Encoding.UTF8.GetString(result.ResponseBody!)));
        Assert.Equal(1, sends);
        Assert.Equal(1, harness.Cache.EntryCount);
    }

    [Fact]
    public async Task Ineligible_no_store_producer_is_not_shared_with_joined_execution_callers()
    {
        const int callers = 5;
        int sends = 0;
        TaskCompletionSource upstreamEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseUpstream = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            upstreamEntered.TrySetResult();
            await releaseUpstream.Task.WaitAsync(context.RequestAborted);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            context.Response.Headers["Cache-Control"] = "no-store";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        using CachedHarness harness = new();
        ManifestDocument manifest = Cacheable(host.Address);
        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<EngineExecutionResult>[] invocations = Enumerable.Range(0, callers)
            .Select(async _ =>
            {
                await start.Task;
                return await InvokeAsync(harness, manifest);
            })
            .ToArray();

        start.TrySetResult();
        try
        {
            using CancellationTokenSource waitBudget = CancellationTokenSource.CreateLinkedTokenSource(
                TestContext.Current.CancellationToken);
            waitBudget.CancelAfter(TimeSpan.FromSeconds(10));
            await upstreamEntered.Task.WaitAsync(waitBudget.Token);
            await WaitUntilAsync(() => harness.Cache.WaitingCallerCount == callers - 1, waitBudget.Token);
            Assert.Equal(1, sends);
        }
        finally
        {
            releaseUpstream.TrySetResult();
        }

        EngineExecutionResult[] results = await Task.WhenAll(invocations);

        Assert.All(results, result => Assert.True(result.Succeeded, result.FailureReason));
        Assert.Equal(callers, sends);
        Assert.Equal(0, harness.Cache.EntryCount);
    }

    private static async Task WaitUntilAsync(Func<bool> predicate, CancellationToken cancellationToken)
    {
        while (!predicate())
        {
            await Task.Delay(TimeSpan.FromMilliseconds(1), cancellationToken);
        }
    }

    [Fact]
    public async Task Credential_rotation_without_manifest_change_separates_cache_entries()
    {
        int sends = 0;
        ConcurrentQueue<string?> authorization = new();
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            authorization.Enqueue(context.Request.Headers.Authorization);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        string variable = "MCPILER_RESPONSE_CACHE_SECRET_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(variable, "credential-one");
        try
        {
            ManifestOperation operation = ExecutionManifests.Operation();
            ManifestDocument manifest = ExecutionManifests.For(
                host.Address,
                operation: operation,
                binding: new HttpBinding(operation.Key, CredentialRef: ["api"]),
                credentials: new CredentialsSection(
                [
                    new ManifestCredential(
                        "api",
                        CredentialScheme.Bearer,
                        "Authorization",
                        CredentialReference.Env(variable)),
                ]),
                responseCache: new ResponseCachePolicySettings(300));

            using CachedHarness harness = new();
            EngineExecutionResult first = await InvokeAsync(harness, manifest);
            EngineExecutionResult sameAuthority = await InvokeAsync(harness, manifest);
            Environment.SetEnvironmentVariable(variable, "credential-two");
            EngineExecutionResult rotated = await InvokeAsync(harness, manifest);
            EngineExecutionResult sameRotatedAuthority = await InvokeAsync(harness, manifest);

            Assert.True(first.Succeeded, first.FailureReason);
            Assert.True(sameAuthority.Succeeded, sameAuthority.FailureReason);
            Assert.True(rotated.Succeeded, rotated.FailureReason);
            Assert.True(sameRotatedAuthority.Succeeded, sameRotatedAuthority.FailureReason);
            Assert.Equal(2, sends);
            Assert.Equal(["Bearer credential-one", "Bearer credential-two"], authorization);
            Assert.Equal(first.AuthorityFingerprint, sameAuthority.AuthorityFingerprint);
            Assert.NotEqual(first.AuthorityFingerprint, rotated.AuthorityFingerprint);
            Assert.Equal(rotated.AuthorityFingerprint, sameRotatedAuthority.AuthorityFingerprint);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [Fact]
    public async Task Response_derived_destination_is_rechecked_against_current_origin_policy_before_lookup()
    {
        var transport = new SessionDestinationTransport();
        using AuthenticationRuntime authentication = new(transport);
        byte[] identityKey = RandomNumberGenerator.GetBytes(32);
        using ResponseCache cache = new("/api", "generation", ResponseCacheOptions.Default, identityKey);
        ExecutionService service = new(
            transport,
            new ManifestSecretResolver(),
            files: null,
            authentication,
            cache,
            identityKey);

        ManifestDocument allowed = DestinationManifest(allowedDestination: true);
        ManifestDocument narrowed = DestinationManifest(allowedDestination: false);
        ExecutionRequest Request(ManifestDocument manifest)
            => new(manifest, ExecutionManifests.Slug, []) { CallerPartition = CallerPartition.Public };

        EngineExecutionResult warmed = await service.ExecuteAsync(Request(allowed), TestContext.Current.CancellationToken);
        Assert.True(warmed.Succeeded, warmed.FailureReason);
        Assert.Equal(1, cache.EntryCount);

        EngineExecutionResult refused = await service.ExecuteAsync(Request(narrowed), TestContext.Current.CancellationToken);

        Assert.Equal(ExecutionFailureKind.OriginPolicy, refused.Failure);
        Assert.Equal(2, transport.SessionAcquisitions);
        Assert.Equal(1, transport.BusinessRequests);
        Assert.Equal(1, cache.EntryCount);
    }

    [Fact]
    public async Task Automatic_cookie_state_bypasses_cache_after_set_cookie_without_changing_live_requests()
    {
        int sends = 0;
        ConcurrentQueue<string> cookies = new();
        await using LoopbackHost host = await StartAsync(async context =>
        {
            int arrival = Interlocked.Increment(ref sends);
            cookies.Enqueue(context.Request.Headers["Cookie"].ToString());
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            if (arrival == 1)
            {
                context.Response.Headers["Set-Cookie"] = "session=one; Path=/; HttpOnly";
            }

            await context.Response.WriteAsync($"{{\"call\":{arrival}}}", context.RequestAborted);
        });

        using CachedHarness harness = new();
        ManifestDocument manifest = Cacheable(host.Address);
        EngineExecutionResult first = await InvokeAsync(harness, manifest);
        EngineExecutionResult second = await InvokeAsync(harness, manifest);
        EngineExecutionResult third = await InvokeAsync(harness, manifest);

        Assert.True(first.Succeeded, first.FailureReason);
        Assert.True(second.Succeeded, second.FailureReason);
        Assert.True(third.Succeeded, third.FailureReason);
        Assert.Equal(3, sends);
        Assert.Equal(string.Empty, cookies.ElementAt(0));
        Assert.Equal("session=one", cookies.ElementAt(1));
        Assert.Equal("session=one", cookies.ElementAt(2));
        Assert.Equal(0, harness.Cache.EntryCount);
    }

    [Fact]
    public async Task Binary_responses_keep_file_classification_and_never_enter_cache()
    {
        int sends = 0;
        byte[] payload = "%PDF-1.7\ncache-file"u8.ToArray();
        await using LoopbackHost host = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref sends);
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/pdf";
                await context.Response.Body.WriteAsync(payload, context.RequestAborted);
            },
            TestContext.Current.CancellationToken);

        string fileRoot = Path.Combine(Path.GetTempPath(), "mcpiler-response-cache-file-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fileRoot);
        try
        {
            FileHandleStore files = new(FileHandleStoreOptions.For(fileRoot));
            using CachedHarness harness = new(files: files);
            ManifestOperation operation = ExecutionManifests.Operation(
                responses: ExecutionManifests.Declares("200", "application/pdf"));
            ManifestDocument manifest = ExecutionManifests.For(
                host.Address,
                operation: operation,
                responseCache: new ResponseCachePolicySettings(300));

            EngineExecutionResult first = await InvokeAsync(harness, manifest);
            EngineExecutionResult second = await InvokeAsync(harness, manifest);

            Assert.True(first.Succeeded, first.FailureReason);
            Assert.True(second.Succeeded, second.FailureReason);
            Assert.NotNull(first.ResponseFile);
            Assert.NotNull(second.ResponseFile);
            Assert.NotEqual(first.ResponseFile!.Id, second.ResponseFile!.Id);
            Assert.Null(second.ResponseBody);
            Assert.Equal(2, sends);
            Assert.Equal(0, harness.Cache.EntryCount);
        }
        finally
        {
            Directory.Delete(fileRoot, recursive: true);
        }
    }

    private static ManifestDocument Cacheable(Uri baseUrl)
        => ExecutionManifests.For(baseUrl, responseCache: new ResponseCachePolicySettings(300));

    private static ManifestDocument DestinationManifest(bool allowedDestination)
    {
        const string authOrigin = "https://auth.example.test";
        const string destinationOrigin = "https://api.example.test";
        const string profileId = "exchange-profile";

        JsonObject configuration = JsonNode.Parse(
            """
            {
              "strategyId": "bounded-token-session-exchange",
              "inputs": { "username": "owner" },
              "endpoint": "https://auth.example.test/session",
              "method": "POST",
              "request": {
                "mediaType": "application/x-www-form-urlencoded",
                "fields": { "username": { "source": "input", "slot": "username" } }
              },
              "response": { "token": { "source": "jsonPointer", "selector": "/token" } },
              "destination": {
                "selector": { "source": "jsonPointer", "selector": "/destination" },
                "allowedOrigins": ["https://api.example.test"]
              },
              "injection": { "location": "header", "name": "Authorization", "prefix": "Bearer " },
              "defaultLifetimeSeconds": 3600,
              "safetySkewSeconds": 15,
              "authFailureStatusCodes": [401]
            }
            """)!.AsObject();

        AuthenticationProfile profile = new(
            profileId,
            AuthenticationKind.TokenSessionExchange,
            configuration,
            [authOrigin],
            [destinationOrigin],
            [],
            ScopeFingerprint: null,
            Slots: []);
        ManifestOperation operation = ExecutionManifests.Operation();
        string[] allowedOrigins = allowedDestination
            ? ["https://base.example.test", destinationOrigin]
            : ["https://base.example.test"];

        return new ManifestDocument(
            ManifestFormatSupport.Maximum,
            new ServerSection("response-cache-destination"),
            new PolicySection(new Uri("https://base.example.test"), allowedOrigins),
            new OperationsSection([operation]),
            new AgentSurfaceSection(
            [
                new AgentOperationEntry(
                    ExecutionManifests.Slug,
                    "Get thing",
                    new HttpBinding(operation.Key, AuthenticationRef: profileId),
                    ResponseCache: new ResponseCachePolicySettings(300)),
            ]),
            CredentialsSection.Empty,
            new AuthenticationSection([profile]));
    }

    private static JsonObject RequestArguments(string id, string mode, string body)
        => new()
        {
            ["id"] = id,
            ["X-Mode"] = mode,
            ["body"] = body,
        };

    private static JsonObject OutputProjection()
        => new()
        {
            ["transformVersion"] = 1,
            ["direction"] = "output",
            ["base"] = "passthrough",
            ["limits"] = new JsonObject
            {
                ["maxSteps"] = 64,
                ["maxDepth"] = 32,
                ["maxNodes"] = 8192,
                ["maxOutputBytes"] = 262144,
                ["maxArrayFanout"] = 1024,
            },
            ["steps"] = new JsonArray(
                new JsonObject
                {
                    ["op"] = "copy",
                    ["source"] = "/body/data",
                    ["target"] = "/result",
                    ["onMissing"] = "error",
                },
                new JsonObject
                {
                    ["op"] = "copy",
                    ["source"] = "/headers/X-Page",
                    ["target"] = "/page",
                    ["onMissing"] = "error",
                }),
        };

    private static Task<LoopbackHost> StartAsync(RequestDelegate handler)
        => LoopbackHost.StartAsync(handler, TestContext.Current.CancellationToken);

    private static async Task<EngineExecutionResult> InvokeAsync(
        CachedHarness harness,
        ManifestDocument manifest,
        JsonObject? arguments = null,
        long? responseSizeLimitBytes = null,
        string slug = ExecutionManifests.Slug)
        => await harness.Service.ExecuteAsync(
            new ExecutionRequest(manifest, slug, arguments ?? [])
            {
                CallerPartition = CallerPartition.Public,
                ResponseSizeLimitBytes = responseSizeLimitBytes,
            },
            TestContext.Current.CancellationToken);

    private sealed class CachedHarness : IDisposable
    {
        private readonly UpstreamClientFactory _clients;

        internal CachedHarness(ResponseCacheOptions? options = null, FileHandleStore? files = null)
        {
            byte[] identityKey = RandomNumberGenerator.GetBytes(32);
            _clients = new UpstreamClientFactory(new OutboundConnectionPolicy(static _ => false));
            Cache = new ResponseCache("/api", "generation-1", options ?? ResponseCacheOptions.Default, identityKey);
            Service = new ExecutionService(
                new UpstreamSender(_clients),
                new ManifestSecretResolver(),
                files,
                authentication: null,
                Cache,
                identityKey);
        }

        internal ResponseCache Cache { get; }

        internal ExecutionService Service { get; }

        public void Dispose()
        {
            Cache.Dispose();
            _clients.Dispose();
        }
    }

    private sealed class SessionDestinationTransport : IUpstreamTransport, IResponseCacheTransportState
    {
        internal int SessionAcquisitions { get; private set; }

        internal int BusinessRequests { get; private set; }

        public bool HasUnrepresentedRequestState => false;

        public Task<UpstreamResponse> SendAsync(
            UpstreamRequest request,
            UpstreamSendPolicy policy,
            CancellationToken cancellationToken)
        {
            if (string.Equals(request.Uri.Host, "auth.example.test", StringComparison.Ordinal))
            {
                SessionAcquisitions++;
                return Task.FromResult(Response(
                    200,
                    "application/json",
                    "{\"token\":\"session-token\",\"destination\":\"https://api.example.test\"}"));
            }

            if (string.Equals(request.Uri.Host, "api.example.test", StringComparison.Ordinal))
            {
                BusinessRequests++;
                return Task.FromResult(Response(200, "application/json", "{\"ok\":true}"));
            }

            throw new InvalidOperationException($"Unexpected fake upstream URI '{request.Uri}'.");
        }

        private static UpstreamResponse Response(int status, string mediaType, string body)
        {
            Dictionary<string, string[]> headers = new(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = [mediaType],
            };
            return new UpstreamResponse(status, headers, mediaType, new MemoryStream(Encoding.UTF8.GetBytes(body)));
        }
    }
}

#pragma warning restore VSTHRD003
