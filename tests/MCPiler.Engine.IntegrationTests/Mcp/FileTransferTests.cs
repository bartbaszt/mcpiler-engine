using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// File capabilities through the listening Engine host: transfer, invocation, resource isolation
/// and binary-result download.
/// </summary>
public sealed class FileTransferTests : IDisposable
{
    private static readonly byte[] UploadPayload = Encoding.UTF8.GetBytes("streamed upload payload");
    private static readonly byte[] DownloadPayload = [0, 1, 2, 3, 0x80, 0xFE, 0xFF, 9];
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-transfer-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public FileTransferTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task Same_resource_upload_invocation_and_binary_download_round_trip()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        RecordingLoggerProvider logs = new();
        byte[]? received = null;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                if (context.Request.Path == "/upload")
                {
                    using MemoryStream copy = new();
                    await context.Request.Body.CopyToAsync(copy, context.RequestAborted);
                    received = copy.ToArray();
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{}", context.RequestAborted);
                    return;
                }

                context.Response.ContentType = "application/octet-stream";
                await context.Response.Body.WriteAsync(DownloadPayload, context.RequestAborted);
            },
            Token);

        await using ServedEngine engine = await ServeAsync(
            upstream.Address,
            scoped: true,
            authorization.Address,
            loggerProvider: logs);
        using HttpClient http = new();
        string parent = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";
        string token = authorization.Mint(parent, "tools.invoke");

        string uploadHandle = await UploadAsync(
            http,
            engine.At("/api/full/files/upload"),
            UploadPayload,
            token);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            Token,
            bearerToken: token);
        McpExchange upload = await session.CallAsync(
            "upload-file",
            JsonSerializer.Serialize(new { attachment = uploadHandle }),
            11,
            Token);

        Assert.Equal(HttpStatusCode.OK, upload.Status);
        Assert.Equal(UploadPayload, received);

        McpExchange binary = await session.CallAsync("download-file", "{}", 12, Token);
        string downloadHandle = HandleFromToolResult(binary.Payload);

        using HttpRequestMessage downloadRequest = new(HttpMethod.Get, engine.At("/api/full/files/" + downloadHandle));
        downloadRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using HttpResponseMessage downloaded = await http.SendAsync(
            downloadRequest,
            HttpCompletionOption.ResponseHeadersRead,
            Token);

        Assert.Equal(HttpStatusCode.OK, downloaded.StatusCode);
        Assert.Equal("application/octet-stream", downloaded.Content.Headers.ContentType?.MediaType);
        Assert.Equal(DownloadPayload.LongLength, downloaded.Content.Headers.ContentLength);
        Assert.Equal(DownloadPayload, await downloaded.Content.ReadAsByteArrayAsync(Token));

        string renderedLogs = string.Join('\n', logs.Messages);
        Assert.DoesNotContain(uploadHandle, renderedLogs, StringComparison.Ordinal);
        Assert.DoesNotContain(downloadHandle, renderedLogs, StringComparison.Ordinal);
        Assert.DoesNotContain(Encoding.UTF8.GetString(UploadPayload), renderedLogs, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToHexString(DownloadPayload), renderedLogs, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Bare_default_and_slug_qualified_addresses_do_not_share_capabilities()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref arrivals);
                await context.Request.Body.CopyToAsync(Stream.Null, context.RequestAborted);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);

        await using ServedEngine engine = await ServeAsync(upstream.Address, scoped: false);
        using HttpClient http = new();

        string bareHandle = await UploadAsync(http, engine.At("/api/files/upload"), UploadPayload);

        using McpHttpSession slug = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);
        McpExchange refused = await slug.CallAsync(
            "upload-file",
            JsonSerializer.Serialize(new { attachment = bareHandle }),
            21,
            Token);

        Assert.Contains("No file handle", refused.Payload, StringComparison.Ordinal);
        Assert.Equal(0, Volatile.Read(ref arrivals));

        using HttpResponseMessage crossDownload = await http.GetAsync(
            engine.At("/api/full/files/" + bareHandle),
            Token);
        using HttpResponseMessage unknown = await http.GetAsync(
            engine.At("/api/full/files/" + NeverIssuedCapability()),
            Token);

        Assert.Equal(HttpStatusCode.NotFound, crossDownload.StatusCode);
        Assert.Equal(unknown.StatusCode, crossDownload.StatusCode);
        Assert.Equal(
            await unknown.Content.ReadAsByteArrayAsync(Token),
            await crossDownload.Content.ReadAsByteArrayAsync(Token));
    }

    [Fact]
    public async Task Protected_transfer_uses_the_parent_resource_for_challenge_and_audience()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);
        await using ServedEngine engine = await ServeAsync(
            upstream.Address,
            scoped: true,
            authorization.Address);

        using HttpClient http = new();
        Uri upload = engine.At("/api/full/files/upload");

        using HttpResponseMessage challenged = await http.PostAsync(
            upload,
            new ByteArrayContent(UploadPayload),
            Token);

        Assert.Equal(HttpStatusCode.Unauthorized, challenged.StatusCode);
        Assert.Contains(
            "/.well-known/oauth-protected-resource/api/full",
            challenged.Headers.WwwAuthenticate.Single().ToString(),
            StringComparison.Ordinal);
        Assert.DoesNotContain("/files/upload", challenged.Headers.WwwAuthenticate.Single().ToString(), StringComparison.Ordinal);

        string parent = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";
        string child = parent + "/files/upload";

        using HttpResponseMessage wrongAudience = await AuthorizedUploadAsync(
            http,
            upload,
            authorization.Mint(child, "tools.invoke"));
        Assert.Equal(HttpStatusCode.NotFound, wrongAudience.StatusCode);

        using NeverSerializedContent unopened = new();
        using HttpRequestMessage refusedBeforeBody = new(HttpMethod.Post, upload) { Content = unopened };
        refusedBeforeBody.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            authorization.Mint(child, "tools.invoke"));
        refusedBeforeBody.Headers.ExpectContinue = true;
        using HttpResponseMessage refusedWithoutPayload = await http.SendAsync(refusedBeforeBody, Token);
        Assert.Equal(HttpStatusCode.NotFound, refusedWithoutPayload.StatusCode);
        Assert.False(unopened.SerializationStarted);

        using HttpResponseMessage admitted = await AuthorizedUploadAsync(
            http,
            upload,
            authorization.Mint(parent, "tools.invoke"));
        Assert.Equal(HttpStatusCode.OK, admitted.StatusCode);
    }

    [Fact]
    public async Task Upload_limit_is_enforced_by_the_streaming_store_before_a_capability_is_issued()
    {
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);
        string files = Directory.CreateDirectory(
            Path.Combine(_root, "limited-files-" + Guid.NewGuid().ToString("N"))).FullName;
        await using ServedEngine engine = await ServeAsync(
            upstream.Address,
            scoped: false,
            uploadLimitBytes: 1024,
            filesRoot: files);
        using HttpClient http = new();
        using ByteArrayContent content = new(new byte[4096]);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using HttpResponseMessage refused = await http.PostAsync(
            engine.At("/api/full/files/upload?fileName=too-large.bin"),
            content,
            Token);

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Empty(Directory.EnumerateFiles(files));
        Assert.DoesNotContain("handle", await refused.Content.ReadAsStringAsync(Token), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_own_expired_capability_is_distinct_from_a_never_issued_capability_on_download()
    {
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);
        await using ServedEngine engine = await ServeAsync(
            upstream.Address,
            scoped: false,
            handleLifetimeSeconds: 0.05);
        using HttpClient http = new();

        string handle = await UploadAsync(http, engine.At("/api/full/files/upload"), UploadPayload);
        await Task.Delay(TimeSpan.FromMilliseconds(120), Token);

        using HttpResponseMessage expired = await http.GetAsync(
            engine.At("/api/full/files/" + handle),
            Token);
        using HttpResponseMessage never = await http.GetAsync(
            engine.At("/api/full/files/" + NeverIssuedCapability()),
            Token);

        Assert.Equal(HttpStatusCode.Gone, expired.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, never.StatusCode);
    }

    [Fact]
    public async Task Inactive_bearer_is_challenged_before_transfer_admission()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: false, Token);
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);
        string files = Directory.CreateDirectory(
            Path.Combine(_root, "inactive-files-" + Guid.NewGuid().ToString("N"))).FullName;
        await using ServedEngine engine = await ServeAsync(
            upstream.Address,
            scoped: true,
            authorization.Address,
            filesRoot: files);
        using HttpClient http = new();
        string parent = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";

        using HttpResponseMessage refused = await AuthorizedUploadAsync(
            http,
            engine.At("/api/full/files/upload"),
            authorization.Mint(parent, "tools.invoke"));

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Empty(Directory.EnumerateFiles(files));
    }

    [Fact]
    public async Task A_capability_from_another_mount_is_unknown_equivalent_on_download()
    {
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);
        string firstManifest = ServedManifests.Write(
            _root,
            "transfer-a-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: false));
        string secondManifest = ServedManifests.Write(
            _root,
            "transfer-b-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: false));
        string files = Directory.CreateDirectory(
            Path.Combine(_root, "mount-files-" + Guid.NewGuid().ToString("N"))).FullName;

        await using ServedEngine engine = await ServedEngine.StartAsync(
            new RuntimeOptions(
                [new MountRequest("/api", firstManifest), new MountRequest("/other", secondManifest)],
                files),
            Token);
        using HttpClient http = new();

        string handle = await UploadAsync(http, engine.At("/api/full/files/upload"), UploadPayload);
        using HttpResponseMessage cross = await http.GetAsync(
            engine.At("/other/full/files/" + handle),
            Token);
        using HttpResponseMessage unknown = await http.GetAsync(
            engine.At("/other/full/files/" + NeverIssuedCapability()),
            Token);

        Assert.Equal(HttpStatusCode.NotFound, cross.StatusCode);
        Assert.Equal(unknown.StatusCode, cross.StatusCode);
        Assert.Equal(
            await unknown.Content.ReadAsByteArrayAsync(Token),
            await cross.Content.ReadAsByteArrayAsync(Token));
    }

    private async Task<ServedEngine> ServeAsync(
        Uri upstream,
        bool scoped,
        Uri? issuer = null,
        long? uploadLimitBytes = null,
        double? handleLifetimeSeconds = null,
        string? filesRoot = null,
        ILoggerProvider? loggerProvider = null)
    {
        string manifest = ServedManifests.Write(
            _root,
            "transfer-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream, scoped, uploadLimitBytes, handleLifetimeSeconds));
        string files = filesRoot ?? Directory.CreateDirectory(
            Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName;

        return await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", manifest)], files),
            Token,
            authorization: issuer is null
                ? null
                : new HostAuthorizationOptions(issuer.AbsoluteUri, HostTokenValidation.Introspection),
            loggerProvider: loggerProvider);
    }

    private static async Task<string> UploadAsync(
        HttpClient http,
        Uri endpoint,
        byte[] payload,
        string? bearerToken = null)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(endpoint + "?fileName=input.bin"))
        {
            Content = new ByteArrayContent(payload),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        if (bearerToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        }

        using HttpResponseMessage response = await http.SendAsync(request, Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument document = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(Token),
            cancellationToken: Token);

        JsonElement root = document.RootElement;
        Assert.Equal("input.bin", root.GetProperty("fileName").GetString());
        Assert.Equal("application/octet-stream", root.GetProperty("mediaType").GetString());
        Assert.Equal(payload.LongLength, root.GetProperty("length").GetInt64());
        Assert.False(root.TryGetProperty("id", out _));
        Assert.False(root.TryGetProperty("storagePointer", out _));
        return root.GetProperty("handle").GetString()!;
    }

    private static async Task<HttpResponseMessage> AuthorizedUploadAsync(
        HttpClient http,
        Uri endpoint,
        string token)
    {
        HttpRequestMessage request = new(HttpMethod.Post, endpoint)
        {
            Content = new ByteArrayContent(UploadPayload),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return await http.SendAsync(request, Token);
    }

    private static string HandleFromToolResult(string payload)
    {
        using JsonDocument document = JsonDocument.Parse(payload);
        string text = document.RootElement
            .GetProperty("result")
            .GetProperty("content")[0]
            .GetProperty("text")
            .GetString()!;
        const string Prefix = "handle '";
        int start = text.IndexOf(Prefix, StringComparison.Ordinal);
        Assert.True(start >= 0, text);
        start += Prefix.Length;
        int end = text.IndexOf('\'', start);
        Assert.True(end > start, text);
        return text[start..end];
    }

    private static string NeverIssuedCapability()
        => Convert.ToBase64String(new byte[32])
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

    private static string Manifest(
        Uri upstream,
        bool scoped,
        long? uploadLimitBytes = null,
        double? handleLifetimeSeconds = null)
    {
        string scopes = scoped ? ", \"requiredScopes\": [\"tools.invoke\"]" : string.Empty;
        List<string> fileSettings = [];

        if (uploadLimitBytes is { } limit)
        {
            fileSettings.Add($"\"uploadSizeLimitBytes\": {limit}");
        }

        if (handleLifetimeSeconds is { } lifetime)
        {
            fileSettings.Add(FormattableString.Invariant($"\"handleLifetimeSeconds\": {lifetime}"));
        }

        string filePolicy = fileSettings.Count == 0
            ? string.Empty
            : ", \"files\": { " + string.Join(", ", fileSettings) + " }";

        return $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": {
                  "name": "File API",
                  "surfaces": [
                    { "slug": "full", "isDefault": true{{scopes}},
                      "operations": [ { "operation": "upload-file" }, { "operation": "download-file" } ] }
                  ]
                } },
                "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}"{{filePolicy}} } },
                "operations": { "inline": { "operations": [
                  {
                    "key": "POST /upload", "method": "POST", "path": "/upload",
                    "requestBody": { "required": true, "content": {
                      "application/octet-stream": { "schema": { "type": "string" } }
                    } }
                  },
                  { "key": "GET /binary", "method": "GET", "path": "/binary" }
                ] } },
                "agentSurface": { "inline": { "operations": [
                  {
                    "slug": "upload-file", "name": "Upload file",
                    "inputSchema": {
                      "type": "object", "required": ["attachment"],
                      "properties": { "attachment": { "type": "string", "x-mcp-file": true } }
                    },
                    "binding": {
                      "type": "transformedHttp",
                      "base": { "operation": "POST /upload" },
                      "inputProgram": {
                        "transformVersion": 1, "direction": "input", "base": "passthrough",
                        "limits": { "maxSteps": 64, "maxDepth": 32, "maxNodes": 8192,
                          "maxOutputBytes": 262144, "maxArrayFanout": 1024 },
                        "steps": [ { "op": "fileRef", "source": "/attachment", "target": "/body", "onMissing": "error" } ]
                      }
                    }
                  },
                  { "slug": "download-file", "name": "Download file",
                    "binding": { "type": "http", "operation": "GET /binary" } }
                ] } }
              }
            }
            """;
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages.ToArray();

        public ILogger CreateLogger(string categoryName) => new RecordingLogger(_messages);

        public void Dispose() { }

        private sealed class RecordingLogger(
            System.Collections.Concurrent.ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
                => messages.Enqueue(formatter(state, exception));
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
}
