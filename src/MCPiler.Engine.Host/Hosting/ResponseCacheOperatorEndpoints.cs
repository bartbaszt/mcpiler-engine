using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// The authenticated, non-MCP operator channel for reading and clearing response-cache state.
/// </summary>
/// <remarks>
/// <para>
/// The channel is opt-in and entirely absent unless the operator names a dedicated secret file.
/// Absent configuration means no route is mapped, which is why the safe default needs no
/// request-time branch: nothing unauthenticated can reach cache state because nothing is there
/// to reach.
/// </para>
/// <para>
/// It is deliberately not an MCP tool. A live cache-clear is an operator action on one process,
/// not a capability a caller's MCP surface advertises; exposing it through the protocol would
/// make every client able to invalidate another client's warm cache and would put a mutation
/// behind a listing a caller reads rather than behind a deployment's own credential.
/// </para>
/// <para>
/// Nothing here mutates a Manifest, managed desired state, a credential or an in-flight
/// producer. The only state that changes is one mount's completed runtime cache entries and the
/// clear epoch that stops a pre-clear producer from repopulating them.
/// </para>
/// </remarks>
internal static class ResponseCacheOperatorEndpoints
{
    /// <summary>The base path of the operator channel.</summary>
    /// <remarks>
    /// A two-segment shape no Manifest prefix is expected to claim, and one that is never an MCP
    /// address. A mount mounted at this exact prefix would be unreachable, which is a
    /// configuration mistake the operator can see rather than a boundary Engine should silently
    /// resolve.
    /// </remarks>
    internal const string BasePath = "/.engine/response-cache";

    /// <summary>The read route: recent sanitized decisions for one mount.</summary>
    internal const string ReadPath = BasePath;

    /// <summary>The clear route: removes completed entries for one mount, optionally one operation.</summary>
    internal const string ClearPath = BasePath + "/clear";

    private const string MountQuery = "mount";
    private const string OperationQuery = "operation";

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Maps the operator channel when a secret was configured, and nothing otherwise.</summary>
    /// <param name="app">The application being built.</param>
    /// <param name="binding">The bound configuration, which carries the operator secret path.</param>
    internal static void Map(WebApplication app, HostBinding binding)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(binding);

        if (binding.ResponseCacheOperatorSecret is not { Length: > 0 } secret)
        {
            return;
        }

        // One authenticator instance for the process. The secret is already resident because
        // startup read and kept it; copying it per request would put a second copy of a live
        // credential in memory for the lifetime of the request.
        ResponseCacheOperatorGuard guard = new(secret);

        app.MapGet(ReadPath, (HttpContext context) => HandleAsync(context, guard, clear: false));
        app.MapPost(ClearPath, (HttpContext context) => HandleAsync(context, guard, clear: true));
    }

    private static async Task HandleAsync(HttpContext context, ResponseCacheOperatorGuard guard, bool clear)
    {
        // Authentication first, before a mount prefix is even read. A refused caller must not be
        // able to distinguish an unknown prefix from a mounted one, and a clear must not begin
        // before the caller is proven.
        if (!guard.IsAuthorized(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = "Bearer realm=\"engine-operator\"";
            return;
        }

        if (!IsTransportAcceptable(context.Request.IsHttps, context.Connection.RemoteIpAddress))
        {
            // Reached over plain http from somewhere other than loopback. Refuse before any cache
            // state is read or changed: the secret travels on this request, and a remote plaintext
            // channel would disclose both the credential and the observation.
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await WriteJsonAsync(
                    context,
                    new { error = "The operator channel requires https unless the request originates on loopback." })
                .ConfigureAwait(false);
            return;
        }

        if (!HasSupportedContract(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            await WriteJsonAsync(
                    context,
                    new { error = "The operator contract generation is missing or unsupported." })
                .ConfigureAwait(false);
            return;
        }

        if (!TryQuery(context.Request.Query, MountQuery, required: true, out string? mount, out string? queryFailure)
            || !TryQuery(context.Request.Query, OperationQuery, required: false, out string? operation, out queryFailure))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await WriteJsonAsync(context, new { error = queryFailure }).ConfigureAwait(false);
            return;
        }

        if (!context.RequestServices.GetRequiredService<EngineGenerationManager>().TryLease(out EngineGenerationLease? lease)
            || lease is null)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await WriteJsonAsync(context, new { error = "No generation is currently serving." }).ConfigureAwait(false);
            return;
        }

        // The lease is held for the whole operation, so a concurrent activation cannot dispose
        // the generation between resolving the mount and reading or clearing its cache.
        using (lease)
        {
            EngineExecution execution = lease.Generation.Execution;

            if (!execution.MountPrefixes.Contains(mount!, StringComparer.Ordinal))
            {
                // A stale target: the prefix is not mounted in the generation this request holds a
                // lease on. 404 rather than 200-with-zero, so an operator cannot read a successful
                // clear of a mount that is no longer served.
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await WriteJsonAsync(
                        context,
                        new { error = $"No mount '{mount}' is served by the current generation." })
                    .ConfigureAwait(false);
                return;
            }

            if (operation is { Length: > 0 } && !execution.MountDeclaresOperation(mount!, operation))
            {
                // Validate the slug through the mount's declared operations before either a scoped
                // read or a scoped clear touches cache state, so an unknown slug never grows epoch
                // state and reads and clears refuse it identically.
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await WriteJsonAsync(
                        context,
                        new { error = $"The mount '{mount}' declares no operation '{operation}'." })
                    .ConfigureAwait(false);
                return;
            }

            if (clear)
            {
                ResponseCacheScopedClear scoped = execution.ClearResponseCacheScoped(mount!, operation);

                switch (scoped.Scope)
                {
                    case ResponseCacheClearScope.MountUnknown:
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        await WriteJsonAsync(
                                context,
                                new { error = $"No mount '{mount}' is served by the current generation." })
                            .ConfigureAwait(false);
                        return;

                    case ResponseCacheClearScope.OperationUnknown:
                        // An unknown slug is refused without advancing an operation epoch, so an
                        // arbitrary caller-supplied value cannot grow the epoch map.
                        context.Response.StatusCode = StatusCodes.Status400BadRequest;
                        await WriteJsonAsync(
                                context,
                                new { error = $"The mount '{mount}' declares no operation '{operation}'." })
                            .ConfigureAwait(false);
                        return;

                    case ResponseCacheClearScope.CachingDisabled:
                        // The mount exists but carries no cache (caching disabled for the process).
                        // Reporting that is not a failure: nothing was there to clear.
                        context.Response.StatusCode = StatusCodes.Status200OK;
                        await WriteJsonAsync(context, new
                        {
                            mount,
                            operation,
                            removed = 0,
                            caching = "disabled",
                            manifestGenerationChanged = false,
                        }).ConfigureAwait(false);
                        return;

                    default:
                        ResponseCacheClearOutcome outcome = scoped.Outcome!;
                        context.Response.StatusCode = StatusCodes.Status200OK;
                        await WriteJsonAsync(context, new
                        {
                            mount = outcome.MountPrefix,
                            operation = outcome.OperationSlug,
                            removed = outcome.RemovedEntries,
                            caching = "enabled",
                            manifestGenerationChanged = false,
                        }).ConfigureAwait(false);
                        return;
                }
            }

            ResponseCacheObservation? observation = execution.ObserveScopedResponseCache(mount!, operation);

            context.Response.StatusCode = StatusCodes.Status200OK;
            await WriteJsonAsync(context, observation is null
                ? new
                {
                    mount,
                    caching = "disabled",
                    invocations = 0L,
                    upstreamSends = 0L,
                    recent = Array.Empty<object>(),
                }
                : new
                {
                    mount = observation.MountPrefix,
                    caching = "enabled",
                    observation.Invocations,
                    observation.UpstreamSends,
                    recent = observation.Recent,
                }).ConfigureAwait(false);
        }
    }

    private static bool HasSupportedContract(HttpRequest request)
    {
        if (!request.Headers.TryGetValue(CompatibilitySchema.ContractGenerationHeader, out var values)
            || values.Count != 1)
        {
            return false;
        }

        return string.Equals(
            values[0],
            CompatibilitySchema.ResponseCacheOperatorGeneration,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Whether the operator channel may be used over a request observed as
    /// <paramref name="isHttps"/> from <paramref name="remote"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// HTTPS is required unless the request genuinely originates on loopback. The scheme the
    /// caller passes is read after the forwarded-headers middleware, which only honours headers
    /// from configured proxies, so a remote client cannot present <c>X-Forwarded-Proto: https</c>
    /// and be believed unless the operator already trusted the address that set it.
    /// </para>
    /// <para>
    /// The predicate is separated from the request so the remote-plain-http refusal can be tested
    /// without a non-loopback listener, which no portable test can open.
    /// </para>
    /// </remarks>
    internal static bool IsTransportAcceptable(bool isHttps, IPAddress? remote)
        => isHttps || (remote is not null && IPAddress.IsLoopback(remote));

    private static bool TryQuery(
        IQueryCollection query,
        string name,
        bool required,
        out string? value,
        out string? failure)
    {
        value = null;
        failure = null;

        if (!query.TryGetValue(name, out Microsoft.Extensions.Primitives.StringValues values)
            || values.Count == 0)
        {
            if (required)
            {
                failure = $"The '{name}' query parameter is required.";
                return false;
            }

            return true;
        }

        // Repeated members are refused rather than resolved. Choosing one would let two callers
        // disagree about which scope they asked for while the response names only one.
        if (values.Count != 1)
        {
            failure = $"The '{name}' query parameter must be given exactly once.";
            return false;
        }

        value = values[0];

        if (string.IsNullOrEmpty(value))
        {
            failure = $"The '{name}' query parameter must not be empty.";
            return false;
        }

        return true;
    }

    private static async Task WriteJsonAsync(HttpContext context, object payload)
    {
        context.Response.ContentType = "application/json";
        await context.Response
            .WriteAsync(JsonSerializer.Serialize(payload, Json), context.RequestAborted)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Compares a presented bearer value against the configured operator secret.
    /// </summary>
    /// <remarks>
    /// The comparison hashes both sides before comparing, so it is constant-time with respect to
    /// content and does not leak the secret's length through the comparison itself. The secret is
    /// never written to a log or a response.
    /// </remarks>
    private sealed class ResponseCacheOperatorGuard
    {
        private readonly byte[] _expected;

        internal ResponseCacheOperatorGuard(string secret)
        {
            ArgumentException.ThrowIfNullOrEmpty(secret);
            _expected = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        }

        internal bool IsAuthorized(HttpRequest request)
        {
            string? header = request.Headers.Authorization;

            if (string.IsNullOrEmpty(header)
                || !header.StartsWith("Bearer ", StringComparison.Ordinal))
            {
                return false;
            }

            string presented = header["Bearer ".Length..].Trim();

            if (presented.Length == 0)
            {
                return false;
            }

            byte[] candidate = SHA256.HashData(Encoding.UTF8.GetBytes(presented));
            return CryptographicOperations.FixedTimeEquals(_expected, candidate);
        }
    }
}
