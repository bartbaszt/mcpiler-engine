using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>One MCP exchange over Streamable HTTP, spoken as bytes.</summary>
/// <param name="Status">The HTTP status.</param>
/// <param name="MediaType">The response media type, or the empty string.</param>
/// <param name="Body">The response body verbatim.</param>
/// <param name="Payload">
/// The JSON-RPC message the body carried, with any event-stream framing removed.
/// </param>
internal sealed record McpExchange(HttpStatusCode Status, string MediaType, string Body, string Payload);

/// <summary>
/// A client that speaks the wire rather than the SDK.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not the protocol SDK's own client. Both sides of this repository consume one
/// SDK, so a client from the same package would agree with the server about anything the two
/// misunderstand together, and the whole point of asserting the wire is to see the bytes a
/// third-party client would receive.
/// </para>
/// <para>
/// It is also what makes a byte comparison possible. A typed client hands back objects, and
/// comparing objects would assert that two renderings are equal after this harness
/// re-rendered them; comparing the payload the server sent asserts what the server sent.
/// </para>
/// </remarks>
internal sealed class McpHttpSession : IDisposable
{
    /// <summary>The protocol revision these tests negotiate.</summary>
    public const string ProtocolVersion = "2025-06-18";

    private const string SessionHeader = "Mcp-Session-Id";

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly Uri _endpoint;

    private McpHttpSession(Uri endpoint) => _endpoint = endpoint;

    /// <summary>The session identifier the server issued, when it issued one.</summary>
    public string? SessionId { get; private set; }

    /// <summary>The initialize result, which is where the server's capabilities travel.</summary>
    public string Handshake { get; private set; } = string.Empty;

    /// <summary>Sends one request to <paramref name="endpoint"/> without establishing a session.</summary>
    public static async Task<McpExchange> SendAsync(
        Uri endpoint,
        string method,
        int id,
        CancellationToken cancellationToken)
    {
        using McpHttpSession session = new(endpoint);
        return await session.PostAsync(Request(method, id), cancellationToken);
    }

    /// <summary>Initializes a session against <paramref name="endpoint"/>.</summary>
    public static async Task<McpHttpSession> OpenAsync(Uri endpoint, CancellationToken cancellationToken)
    {
        McpHttpSession session = new(endpoint);

        try
        {
            McpExchange initialize = await session.PostAsync(Initialize(), cancellationToken);

            if (initialize.Status != HttpStatusCode.OK)
            {
                throw new InvalidOperationException(
                    $"initialize was answered with {(int)initialize.Status}: {initialize.Body}");
            }

            session.Handshake = initialize.Payload;

            // A notification carries no identifier and expects no result; the server accepts it
            // and the session is then usable.
            _ = await session.PostAsync("""{"jsonrpc":"2.0","method":"notifications/initialized"}""", cancellationToken);

            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    /// <summary>Sends one request on this session.</summary>
    public Task<McpExchange> RequestAsync(string method, int id, CancellationToken cancellationToken)
        => PostAsync(Request(method, id), cancellationToken);

    /// <summary>Calls a tool on this session with the supplied arguments as JSON text.</summary>
    /// <remarks>
    /// The arguments are written as bytes rather than serialized from an object, so a test can
    /// send a value a typed client would refuse to construct - which is exactly what validation
    /// has to be measured against.
    /// </remarks>
    public Task<McpExchange> CallAsync(
        string tool,
        string argumentsJson,
        int id,
        CancellationToken cancellationToken)
        => PostAsync(
            "{\"jsonrpc\":\"2.0\",\"id\":"
                + id.ToString(CultureInfo.InvariantCulture)
                + ",\"method\":\"tools/call\",\"params\":{\"name\":\""
                + tool
                + "\",\"arguments\":"
                + argumentsJson
                + "}}",
            cancellationToken);

    public void Dispose() => _http.Dispose();

    private static string Initialize()
        => "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\""
            + ProtocolVersion
            + "\",\"capabilities\":{},\"clientInfo\":{\"name\":\"engine-wire-tests\",\"version\":\"1.0\"}}}";

    private static string Request(string method, int id)
        => "{\"jsonrpc\":\"2.0\",\"id\":"
            + id.ToString(CultureInfo.InvariantCulture)
            + ",\"method\":\""
            + method
            + "\",\"params\":{}}";

    private async Task<McpExchange> PostAsync(string body, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

        // Both media types, because the specification requires a client to accept either and a
        // server is free to choose. Accepting only one would make this harness the reason a
        // response looked the way it did.
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

        if (SessionId is { } session)
        {
            request.Headers.Add(SessionHeader, session);
        }

        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken);

        if (SessionId is null && response.Headers.TryGetValues(SessionHeader, out IEnumerable<string>? issued))
        {
            SessionId = issued.FirstOrDefault();
        }

        string text = await response.Content.ReadAsStringAsync(cancellationToken);

        return new McpExchange(
            response.StatusCode,
            response.Content.Headers.ContentType?.MediaType ?? string.Empty,
            text,
            Unframe(text));
    }

    /// <summary>
    /// Strips event-stream framing, leaving the JSON-RPC message the server sent.
    /// </summary>
    /// <remarks>
    /// Framing is the transport's; the message is the product's. Comparing framed bodies would
    /// make an event name or a retry hint look like a change in the tool list.
    /// </remarks>
    private static string Unframe(string body)
    {
        if (!body.Contains("data:", StringComparison.Ordinal))
        {
            return body;
        }

        StringBuilder payload = new();

        foreach (string line in body.Split('\n'))
        {
            string trimmed = line.TrimEnd('\r');

            if (trimmed.StartsWith("data:", StringComparison.Ordinal))
            {
                payload.Append(trimmed["data:".Length..].TrimStart());
            }
        }

        return payload.ToString();
    }
}
