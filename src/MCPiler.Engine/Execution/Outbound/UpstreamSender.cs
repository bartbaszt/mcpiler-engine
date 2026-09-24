using System.Net.Http.Headers;
using System.Net;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.ResponseCaching;

namespace MCPiler.Engine.Execution.Outbound;

/// <summary>
/// Sends an exchange and follows its redirect chain under the governing perimeter.
/// </summary>
/// <remarks>
/// <para>
/// Every decision this component makes about a redirect is stated in <see cref="RedirectRules"/>
/// and read from there. What is left here is the part that needs a transport: constructing a
/// message, replaying a body, and turning a live response into captured metadata plus a stream.
/// </para>
/// <para>
/// The perimeter is checked at the top of every iteration, including the first. A check placed
/// only on redirect targets would trust the caller to have validated the initial destination,
/// and the one caller that forgot would open the socket this component exists to prevent.
/// </para>
/// <para>
/// No deadline is imposed here. The caller's token is the whole-exchange budget, and the client
/// carries an infinite timeout so that a slow exchange has exactly one deadline and therefore
/// exactly one classification.
/// </para>
/// </remarks>
public sealed class UpstreamSender : IUpstreamTransport, IResponseCacheTransportState
{
    private readonly UpstreamClientFactory _clients;
    private int _hasObservedSetCookie;

    /// <summary>Creates a sender over <paramref name="clients"/>.</summary>
    public UpstreamSender(UpstreamClientFactory clients)
    {
        ArgumentNullException.ThrowIfNull(clients);
        _clients = clients;
    }

    bool IResponseCacheTransportState.HasUnrepresentedRequestState
        => !_clients.CookieStateObservable || Volatile.Read(ref _hasObservedSetCookie) != 0;

    /// <inheritdoc />
    public async Task<UpstreamResponse> SendAsync(
        UpstreamRequest request,
        UpstreamSendPolicy policy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(policy);

        if (request.Body is not null && request.BodySource is not null)
        {
            throw new InvalidOperationException(
                "An upstream request cannot declare both materialized and replayable body sources.");
        }

        var client = _clients.Client(policy.Limits);
        var hopLimit = policy.Limits.RedirectHopLimit;

        var method = request.Method;
        var uri = request.Uri;
        var headers = request.Headers;
        var sensitiveQueryParameters = request.SensitiveQueryParameters;
        var preserveBody = true;
        bool followedRedirect = false;

        for (var hop = 0; ; hop++)
        {
            if (!policy.AllowedOrigins.IsAllowed(uri))
            {
                throw new OriginPolicyViolationException(
                    UpstreamUriRedactor.Redact(uri, sensitiveQueryParameters));
            }

            if (hop > hopLimit)
            {
                throw new RedirectLimitException(hopLimit);
            }

            // The signature covers the exact request that will be sent, so it is computed here,
            // after the redirect rules have decided this hop's method, destination and headers,
            // and before the message is built. A hook that rewrites the destination is honoured
            // by the next iteration's perimeter check, because the rewritten request is what the
            // loop continues with.
            UpstreamRequest hopRequest = request with
            {
                Method = method,
                Uri = uri,
                Headers = headers,
                Body = preserveBody ? request.Body : null,
                BodySource = preserveBody ? request.BodySource : null,
                BodyMediaType = preserveBody ? request.BodyMediaType : null,
                SensitiveQueryParameters = sensitiveQueryParameters,
            };

            if (policy.SignRequest is { } sign)
            {
                hopRequest = await sign(hopRequest, hop, cancellationToken).ConfigureAwait(false);
                method = hopRequest.Method;
                uri = hopRequest.Uri;
                headers = hopRequest.Headers;
                sensitiveQueryParameters = hopRequest.SensitiveQueryParameters;
            }

            using var message = Build(method, uri, headers, hopRequest);

            HttpResponseMessage response;
            try
            {
                response = await client
                    .SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The budget, or the caller. Either way the distinction belongs to whoever owns
                // the token, and rewriting it here would hide which one expired.
                throw;
            }
            catch (Exception ex)
            {
                throw Translate(ex, uri, hopRequest.SensitiveQueryParameters);
            }

            // SocketsHttpHandler's default CookieContainer is mutable state that does not appear
            // on UpstreamRequest. Once a response has supplied cookies, cache identity can no
            // longer be proven from the request model alone, so the service bypasses this
            // transport's cache path rather than merging callers under an incomplete key.
            if (response.Headers.Contains("Set-Cookie"))
            {
                Interlocked.Exchange(ref _hasObservedSetCookie, 1);
            }

            if (!RedirectRules.IsRedirect((int)response.StatusCode))
            {
                return await CaptureAsync(response, uri, followedRedirect, cancellationToken).ConfigureAwait(false);
            }

            var location = response.Headers.Location;
            if (location is null)
            {
                response.Dispose();
                throw new MalformedRedirectException(
                    UpstreamUriRedactor.Redact(uri, hopRequest.SensitiveQueryParameters));
            }

            var next = RedirectRules.ResolveLocation(uri, location);
            var sameOrigin = RedirectRules.IsSameOrigin(uri, next);
            var (nextMethod, nextPreservesBody) = RedirectRules.NextRequest((int)response.StatusCode, method);

            response.Dispose();

            headers = Carry(headers, sameOrigin, hopRequest.SensitiveHeaders);
            method = nextMethod;
            preserveBody = preserveBody && nextPreservesBody;
            uri = next;
            followedRedirect = true;
        }
    }

    /// <summary>
    /// Builds one message. <paramref name="body"/> is null when the redirect semantics dropped
    /// the body, which is also when the content headers must not be replayed.
    /// </summary>
    private static HttpRequestMessage Build(
        string method,
        Uri uri,
        IReadOnlyDictionary<string, string[]> headers,
        UpstreamRequest? body)
    {
        var message = new HttpRequestMessage(new HttpMethod(method), uri);

        foreach (var (name, values) in headers)
        {
            // Content headers are refused by this collection and belong on the content below.
            // Adding without validation keeps a compiled header byte-identical rather than
            // letting the framework reformat it.
            message.Headers.TryAddWithoutValidation(name, values);
        }

        if (!headers.Keys.Any(static name => string.Equals(name, "Accept-Encoding", StringComparison.OrdinalIgnoreCase)))
        {
            // Keep automatic decompression's implicit request dimension visible to cache-key
            // construction. SocketsHttpHandler does not add a second default when this header is
            // already present.
            message.Headers.TryAddWithoutValidation("Accept-Encoding", UpstreamRequestDefaults.AcceptEncoding);
        }

        if (body?.BodySource is { } source)
        {
            message.Content = new ReplayableBodyContent(source);

            if (body.BodyMediaType is { } mediaType)
            {
                message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(mediaType);
            }
        }
        else if (body?.Body is { } bytes)
        {
            // A fresh content per hop rather than a reused one: content is single-read, and the
            // previous message owning it has already been released.
            message.Content = new ByteArrayContent(bytes);

            if (body.BodyMediaType is { } mediaType)
            {
                // Parsed rather than constructed, because a compiled multipart media type
                // carries the mandatory boundary parameter and the constructor refuses any
                // value that has parameters.
                message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(mediaType);
            }
        }

        return message;
    }

    /// <summary>The headers the next hop carries.</summary>
    private static Dictionary<string, string[]> Carry(
        IReadOnlyDictionary<string, string[]> headers,
        bool sameOrigin,
        IReadOnlyCollection<string> sensitiveHeaders)
    {
        var carried = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, values) in headers)
        {
            if (!RedirectRules.IsDroppedOnRedirect(name, sameOrigin, sensitiveHeaders))
            {
                carried[name] = values;
            }
        }

        return carried;
    }

    /// <summary>
    /// Captures status, headers, media type and the final request URI as values, and hands over
    /// the body stream with the response's lifetime attached.
    /// </summary>
    /// <remarks>
    /// Reading metadata after the response is released happens to work today. It is not a
    /// contract, and depending on it puts a result's status and headers one framework change
    /// away from being wrong.
    /// </remarks>
    private static async Task<UpstreamResponse> CaptureAsync(
        HttpResponseMessage response,
        Uri effectiveUri,
        bool wasRedirected,
        CancellationToken cancellationToken)
    {
        try
        {
            var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

            foreach (var header in response.Headers)
            {
                headers[header.Key] = [.. header.Value];
            }

            // Content headers win a name collision: they describe the payload that will actually
            // be read. Without them the map could not report Content-Type, Content-Length or
            // Content-Encoding, which are the three a reader most often needs.
            foreach (var header in response.Content.Headers)
            {
                headers[header.Key] = [.. header.Value];
            }

            var mediaType = response.Content.Headers.ContentType?.MediaType;
            var body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

            return new UpstreamResponse(
                (int)response.StatusCode,
                headers,
                mediaType,
                body,
                new ResponseOwner(response),
                effectiveUri,
                wasRedirected);
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Turns a transport fault into an Engine failure, preserving a containment refusal that the
    /// framework wrapped.
    /// </summary>
    /// <remarks>
    /// A refusal raised from the connect callback does not reach a caller as itself: the client
    /// wraps it, so a classifier matching on the outer type would report a blocked private
    /// address as an ordinary connection failure and an operator would look for a firewall
    /// instead of a policy. Unwrapping first is what keeps the address-containment
    /// classification reachable at all.
    /// </remarks>
    private static Exception Translate(
        Exception exception,
        Uri uri,
        IReadOnlyCollection<string> sensitiveQueryParameters)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is AddressPolicyViolationException or HostResolutionException or FileRuntimeException)
            {
                return current;
            }
        }

        string message =
            $"The exchange with '{UpstreamUriRedactor.Redact(uri, sensitiveQueryParameters)}' failed before a response was observed.";

        // Framework exception trees can retain the original request URI. When a signer marked
        // query values sensitive, keep the public diagnostic useful but do not preserve an
        // unreviewed inner message that could reintroduce those values through logging.
        Exception? safeInner = sensitiveQueryParameters.Count == 0 ? exception : null;
        return new UpstreamTransportException(message, safeInner);
    }

    private sealed class ResponseOwner(HttpResponseMessage response) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            response.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Bridges a replayable Engine source into one HTTP hop without taking ownership of the
    /// source itself. Disposing the message closes only resources opened by that serialization;
    /// the execution owns the descriptor across body-preserving redirects.
    /// </summary>
    private sealed class ReplayableBodyContent(ReplayableBodySource source) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => source.CopyToAsync(stream, CancellationToken.None).AsTask();

        protected override Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context,
            CancellationToken cancellationToken)
            => source.CopyToAsync(stream, cancellationToken).AsTask();

        protected override bool TryComputeLength(out long length)
        {
            if (source.Length is { } known)
            {
                length = known;
                return true;
            }

            length = 0;
            return false;
        }
    }
}
