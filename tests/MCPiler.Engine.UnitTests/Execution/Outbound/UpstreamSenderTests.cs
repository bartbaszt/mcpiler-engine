using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Outbound;

/// <summary>
/// The redirect chain: per-hop perimeter revalidation, the hop ceiling, method and body
/// rewriting, and credential isolation between origins.
/// </summary>
/// <remarks>
/// A substituted transport stack is used rather than a socket. Nothing asserted here is a
/// property of a connection — the decisions are about statuses, methods and header names — and
/// a real server would make the same assertions slower without making them stronger. The
/// obligations that ARE properties of a connection (address containment, connect timeout, the
/// elapsed-time budget) are asserted in the integration suite instead.
/// </remarks>
public sealed class UpstreamSenderTests
{
    private static readonly OriginAllowList AllowApi = new(["https://api.example.com"]);
    private static readonly OriginAllowList AllowBoth =
        new(["https://api.example.com", "https://cdn.example.com"]);

    private static UpstreamSendPolicy Policy(OriginAllowList origins, int hopLimit = 5)
        => new(origins, OutboundLimits.Default with { RedirectHopLimit = hopLimit });

    [Fact]
    public async Task A_redirect_to_a_disallowed_origin_is_not_followed()
    {
        var handler = new RecordingHandler(_ => Redirect(302, "https://evil.example.com/path"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        var failure = await Assert.ThrowsAsync<OriginPolicyViolationException>(
            () => sender.SendAsync(Get("https://api.example.com/start"), Policy(AllowApi), TestContext.Current.CancellationToken));

        Assert.Equal("https://evil.example.com/path", failure.Uri.ToString());

        // One request, not two: the refusal happens before the second hop is attempted, so the
        // refused origin never sees a connection.
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task A_direct_target_outside_the_perimeter_is_refused_without_a_request()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        var failure = await Assert.ThrowsAsync<OriginPolicyViolationException>(
            () => sender.SendAsync(Get("https://other.example.com/x"), Policy(AllowApi), TestContext.Current.CancellationToken));

        Assert.Equal("https://other.example.com/x", failure.Uri.ToString());

        // The perimeter is checked on the first iteration too. Asserting the absence of the
        // request is the whole point: a check that ran after the send would also throw.
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task A_chain_longer_than_the_hop_limit_fails_as_a_hop_limit_breach()
    {
        var handler = new RecordingHandler(_ => Redirect(302, "https://api.example.com/next"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        var failure = await Assert.ThrowsAsync<RedirectLimitException>(
            () => sender.SendAsync(Get("https://api.example.com/start"), Policy(AllowApi, hopLimit: 2), TestContext.Current.CancellationToken));

        Assert.Equal(2, failure.HopLimit);
        Assert.Equal(3, handler.Requests.Count);
    }

    [Fact]
    public async Task A_redirect_to_an_allowed_origin_is_followed()
    {
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? Redirect(302, "https://cdn.example.com/end")
            : Ok("done"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        await using var response = await sender.SendAsync(
            Get("https://api.example.com/start"),
            Policy(AllowBoth),
            TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("done", await Text(response));
        Assert.Equal("https://cdn.example.com/end", handler.Requests[^1].Uri.ToString());
    }

    [Fact]
    public async Task A_response_with_a_redirect_status_and_no_location_is_a_malformed_redirect()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Redirect));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        // Not an origin refusal. An allow-list that rejected a destination the upstream never
        // named would send an operator looking for the wrong misconfiguration.
        var failure = await Assert.ThrowsAsync<MalformedRedirectException>(
            () => sender.SendAsync(Get("https://api.example.com/start"), Policy(AllowApi), TestContext.Current.CancellationToken));

        Assert.Equal("https://api.example.com/start", failure.Uri.ToString());
    }

    [Theory]
    [InlineData(307)]
    [InlineData(308)]
    public async Task A_method_preserving_redirect_replays_the_body(int redirectStatus)
    {
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? Redirect(redirectStatus, "https://api.example.com/end")
            : Ok("ok"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        await using var response = await sender.SendAsync(
            Post("https://api.example.com/start", "payload", "application/json"),
            Policy(AllowApi),
            TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, sent => Assert.Equal("POST", sent.Method));
        Assert.All(handler.Requests, sent => Assert.Equal("payload", sent.Body));
        Assert.Equal("application/json", handler.Requests[1].ContentHeaders["Content-Type"].Single());
    }

    [Theory]
    [InlineData(307)]
    [InlineData(308)]
    public async Task A_method_preserving_redirect_reopens_a_streaming_body_for_every_hop(int redirectStatus)
    {
        var source = new TrackingSource("streamed-payload"u8.ToArray());
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? Redirect(redirectStatus, "https://api.example.com/end")
            : Ok("ok"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        await using var response = await sender.SendAsync(
            new UpstreamRequest
            {
                Method = "POST",
                Uri = new Uri("https://api.example.com/start"),
                BodySource = source,
                BodyMediaType = "application/octet-stream",
            },
            Policy(AllowApi),
            TestContext.Current.CancellationToken);

        Assert.Equal(2, source.Copies);
        Assert.Equal("streamed-payload", handler.Requests[0].Body);
        Assert.Equal(handler.Requests[0].Body, handler.Requests[1].Body);
    }

    [Fact]
    public async Task See_other_rewrites_a_post_to_a_get_and_drops_the_body()
    {
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? Redirect(303, "https://api.example.com/end")
            : Ok("ok"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        await using var response = await sender.SendAsync(
            Post("https://api.example.com/start", "payload", "text/plain"),
            Policy(AllowApi),
            TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("POST", handler.Requests[0].Method);
        Assert.Equal("GET", handler.Requests[1].Method);
        Assert.Null(handler.Requests[1].Body);

        // A dropped body must drop its content headers with it. A GET announcing a
        // Content-Type for a body it does not carry describes a request that was not sent.
        Assert.Empty(handler.Requests[1].ContentHeaders);
    }

    [Fact]
    public async Task A_body_dropping_redirect_does_not_open_the_streaming_source_again()
    {
        var source = new TrackingSource("streamed-payload"u8.ToArray());
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? Redirect(303, "https://api.example.com/end")
            : Ok("ok"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        await using var response = await sender.SendAsync(
            new UpstreamRequest
            {
                Method = "POST",
                Uri = new Uri("https://api.example.com/start"),
                BodySource = source,
                BodyMediaType = "application/octet-stream",
            },
            Policy(AllowApi),
            TestContext.Current.CancellationToken);

        Assert.Equal(1, source.Copies);
        Assert.Null(handler.Requests[1].Body);
        Assert.Empty(handler.Requests[1].ContentHeaders);
    }

    [Fact]
    public async Task See_other_from_a_head_request_stays_a_head_request()
    {
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? Redirect(303, "https://api.example.com/end")
            : new HttpResponseMessage(HttpStatusCode.OK));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        await using var response = await sender.SendAsync(
            new UpstreamRequest { Method = "HEAD", Uri = new Uri("https://api.example.com/start") },
            Policy(AllowApi),
            TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("HEAD", handler.Requests[1].Method);
    }

    [Theory]
    [InlineData(301)]
    [InlineData(302)]
    public async Task A_legacy_post_redirect_rewrites_to_a_get_and_drops_the_body(int redirectStatus)
    {
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? Redirect(redirectStatus, "https://api.example.com/end")
            : Ok("ok"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        await using var response = await sender.SendAsync(
            Post("https://api.example.com/start", "payload", "text/plain"),
            Policy(AllowApi),
            TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("POST", handler.Requests[0].Method);
        Assert.Equal("GET", handler.Requests[1].Method);
        Assert.Null(handler.Requests[1].Body);
    }

    [Fact]
    public async Task A_cross_origin_redirect_strips_credentials_and_keeps_everything_else()
    {
        var handler = new RecordingHandler(request => request.RequestUri!.Host == "api.example.com"
            ? Redirect(307, "https://cdn.example.com/end")
            : Ok("ok"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        var request = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.com/start"),
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = ["Bearer secret-token"],
                ["Cookie"] = ["session=secret-cookie"],
                ["X-Custom-Credential"] = ["secret-header"],
                ["X-Authorization-Scheme"] = ["custom"],
                ["X-Correlation-Id"] = ["trace-123"],
            },

            // Only the configured name is declared. The three well-known ones are sensitive
            // whatever a contract says.
            SensitiveHeaders = ["X-Custom-Credential"],
        };

        await using var response = await sender.SendAsync(request, Policy(AllowBoth), TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);

        var first = handler.Requests[0].Headers;
        Assert.Contains("Authorization", first.Keys);
        Assert.Contains("Cookie", first.Keys);
        Assert.Contains("X-Custom-Credential", first.Keys);

        var second = handler.Requests[1].Headers;
        Assert.DoesNotContain("Authorization", second.Keys);
        Assert.DoesNotContain("Cookie", second.Keys);
        Assert.DoesNotContain("X-Custom-Credential", second.Keys);
        Assert.Equal("trace-123", second["X-Correlation-Id"].Single());

        // A header whose name merely contains a sensitive one is a different header. Stripping
        // it would remove something the contract depends on while suggesting a protection
        // nobody asked for.
        Assert.Equal("custom", second["X-Authorization-Scheme"].Single());
    }

    [Fact]
    public async Task A_same_origin_redirect_preserves_credentials()
    {
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? RelativeRedirect(307, "/end")
            : Ok("ok"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        var request = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.com/start"),
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = ["Bearer secret-token"],
                ["X-Custom-Credential"] = ["secret-header"],
            },
            SensitiveHeaders = ["X-Custom-Credential"],
        };

        await using var response = await sender.SendAsync(request, Policy(AllowApi), TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);

        var second = handler.Requests[1].Headers;
        Assert.Equal("Bearer secret-token", second["Authorization"].Single());
        Assert.Equal("secret-header", second["X-Custom-Credential"].Single());

        // A relative Location resolved against the current request, which is what makes the
        // same-origin judgement possible at all.
        Assert.Equal("https://api.example.com/end", handler.Requests[1].Uri.ToString());
    }

    [Fact]
    public async Task The_host_header_never_survives_a_redirect()
    {
        var handler = new RecordingHandler(request => request.RequestUri!.PathAndQuery == "/start"
            ? RelativeRedirect(307, "/end")
            : Ok("ok"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        var request = new UpstreamRequest
        {
            Method = "GET",
            Uri = new Uri("https://api.example.com/start"),
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Host"] = ["api.example.com"],
            },
        };

        await using var response = await sender.SendAsync(request, Policy(AllowApi), TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.DoesNotContain("Host", handler.Requests[1].Headers.Keys);
    }

    [Fact]
    public async Task Response_metadata_and_content_headers_are_captured_together()
    {
        var handler = new RecordingHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            };
            response.Headers.TryAddWithoutValidation("X-Trace", "abc");

            // Stated by the upstream rather than left to the harness to compute: a substituted
            // content does not populate its own length, and the assertion below is about the map
            // carrying what the upstream sent, not about who calculated it. A real server states
            // it, which the integration suite observes.
            response.Content.Headers.ContentLength = 2;
            return response;
        });
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        await using var response = await sender.SendAsync(
            Get("https://api.example.com/thing"),
            Policy(AllowApi),
            TestContext.Current.CancellationToken);

        Assert.Equal(201, response.StatusCode);
        Assert.Equal("application/json", response.MediaType);
        Assert.Equal("abc", response.Headers["X-Trace"].Single());

        // Content headers belong in the map: they are the ones a diagnosis needs, and a map
        // built from message headers alone cannot report either of these.
        Assert.Contains("Content-Type", response.Headers.Keys);
        Assert.Contains("Content-Length", response.Headers.Keys);
    }

    [Fact]
    public async Task An_unrecognized_transport_fault_is_reported_as_a_transport_failure()
    {
        var handler = new RecordingHandler(_ => throw new InvalidOperationException("socket exploded"));
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        var failure = await Assert.ThrowsAsync<UpstreamTransportException>(
            () => sender.SendAsync(Get("https://api.example.com/start"), Policy(AllowApi), TestContext.Current.CancellationToken));

        Assert.IsType<InvalidOperationException>(failure.InnerException);
    }

    [Fact]
    public async Task A_containment_refusal_survives_the_frameworks_wrapping()
    {
        // The client wraps whatever the connect callback raises. A classifier reading the outer
        // type would report a refused private address as an ordinary connection failure, and an
        // operator would look for a firewall instead of a policy.
        var handler = new RecordingHandler(_ => throw new HttpRequestException(
            "connection failed",
            new AddressPolicyViolationException("internal.example.com", "10.0.0.7")));

        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        var failure = await Assert.ThrowsAsync<AddressPolicyViolationException>(
            () => sender.SendAsync(Get("https://api.example.com/start"), Policy(AllowApi), TestContext.Current.CancellationToken));

        Assert.Equal("10.0.0.7", failure.Address);
    }

    [Fact]
    public async Task Cancellation_is_not_rewritten_as_a_transport_failure()
    {
        using var cancelled = new CancellationTokenSource();
        var handler = new RecordingHandler(_ =>
        {
            cancelled.Cancel();
            throw new TaskCanceledException();
        });
        using var clients = new UpstreamClientFactory(_ => handler);
        var sender = new UpstreamSender(clients);

        // Whoever owns the token decides whether this was a budget expiry or an abandoned
        // request. Wrapping it here would erase that distinction before it could be made.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sender.SendAsync(Get("https://api.example.com/start"), Policy(AllowApi), cancelled.Token));
    }

    private static UpstreamRequest Get(string uri)
        => new() { Method = "GET", Uri = new Uri(uri) };

    private static UpstreamRequest Post(string uri, string body, string mediaType)
        => new()
        {
            Method = "POST",
            Uri = new Uri(uri),
            Body = Encoding.UTF8.GetBytes(body),
            BodyMediaType = mediaType,
        };

    private static HttpResponseMessage Redirect(int status, string location)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status);
        response.Headers.Location = new Uri(location);
        return response;
    }

    private static HttpResponseMessage RelativeRedirect(int status, string location)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status);
        response.Headers.Location = new Uri(location, UriKind.Relative);
        return response;
    }

    private static HttpResponseMessage Ok(string body)
        => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "text/plain") };

    private static async Task<string> Text(UpstreamResponse response)
    {
        var bytes = await BoundedResponseReader.ReadAllWithLimitAsync(
            response.Body,
            1024,
            TestContext.Current.CancellationToken);

        return Encoding.UTF8.GetString(bytes);
    }

    private sealed class TrackingSource(byte[] bytes) : ReplayableBodySource
    {
        public int Copies { get; private set; }

        public override long? Length => bytes.LongLength;

        public override async ValueTask CopyToAsync(Stream destination, CancellationToken cancellationToken)
        {
            Copies++;
            await destination.WriteAsync(bytes, cancellationToken);
        }

        public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed record RecordedRequest(
        Uri Uri,
        string Method,
        string? Body,
        IReadOnlyDictionary<string, string[]> Headers,
        IReadOnlyDictionary<string, string[]> ContentHeaders);

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);

            Requests.Add(new RecordedRequest(
                request.RequestUri!,
                request.Method.Method,
                body,
                request.Headers.ToDictionary(h => h.Key, h => h.Value.ToArray(), StringComparer.OrdinalIgnoreCase),
                request.Content?.Headers.ToDictionary(h => h.Key, h => h.Value.ToArray(), StringComparer.OrdinalIgnoreCase)
                    ?? new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)));

            return respond(request);
        }
    }
}
