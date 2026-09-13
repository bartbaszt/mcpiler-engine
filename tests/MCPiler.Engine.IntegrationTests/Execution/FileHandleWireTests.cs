using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Files;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// A handle crossing the execution boundary: issued in a wire form that names nothing, redeemed
/// only by the invocation presenting it.
/// </summary>
/// <remarks>
/// <para>
/// The tests drive <see cref="ExecutionService"/> the way a host does. A stored binary response
/// becomes a handle in its wire form; a later invocation presents that form through a file slot
/// and the payload is attached by the redemption step; and the refusal for a handle from another
/// scope is compared byte for byte with the refusal for one that never existed.
/// </para>
/// <para>
/// The upstream is a loopback listener that counts arrivals, so "the refused handle cost
/// nothing" is a count rather than an inference.
/// </para>
/// </remarks>
public sealed class FileHandleWireTests : IDisposable
{
    private static readonly byte[] Payload = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];

    private readonly List<string> _roots = [];

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_stored_response_is_issued_in_a_wire_form_that_names_nothing()
    {
        var store = NewStore();
        var reference = await Issue(store, "a-connector");
        string wire = Wire(store, reference);

        Assert.True(HandleCodec.IsWireForm(wire));
        Assert.DoesNotContain(reference.Id, wire, StringComparison.Ordinal);
        Assert.DoesNotContain(reference.StoragePointer, wire, StringComparison.Ordinal);
        Assert.DoesNotContain(reference.ContentHash, wire, StringComparison.Ordinal);
        Assert.DoesNotContain(reference.Scope, wire, StringComparison.Ordinal);
        Assert.False(HandleCodec.IsWireForm(reference.StoragePointer));
    }

    [Fact]
    public async Task Handles_issued_in_sequence_share_no_recoverable_relation()
    {
        var store = NewStore();
        var forms = new List<string>();

        for (var index = 0; index < 4; index++)
        {
            FileHandleReference issued = await Issue(store, "a-connector");
            forms.Add(Wire(store, issued));
        }

        Assert.Equal(4, forms.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task A_later_invocation_of_the_same_scope_redeems_the_handle()
    {
        var arrivals = new List<byte[]>();
        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                using var buffer = new MemoryStream();
                await context.Request.Body.CopyToAsync(buffer, context.RequestAborted);
                arrivals.Add(buffer.ToArray());
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);

        var store = NewStore();
        var mine = await Issue(store, "/api");
        string mineWire = Wire(store, mine);

        using var clients = new UpstreamClientFactory(Permissive());
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver(), store);

        var result = await service.ExecuteAsync(
            new ExecutionRequest(FileSlotManifest(host.Address), UploadSlug, new JsonObject
            {
                ["attachment"] = mineWire,
            })
            {
                Scope = "/api",
            },
            Token);

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        _ = Assert.Single(arrivals);
    }

    [Fact]
    public async Task A_handle_from_another_scope_is_refused_byte_identically_to_a_never_issued_one()
    {
        var arrivals = new List<byte[]>();
        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                using var buffer = new MemoryStream();
                await context.Request.Body.CopyToAsync(buffer, context.RequestAborted);
                arrivals.Add(buffer.ToArray());
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);

        var store = NewStore();
        var theirs = await Issue(store, "other-mount");
        string theirsWire = Wire(store, theirs);
        _ = await Issue(store, "/api");

        var crossScope = await Invoke(store, host.Address, theirsWire);
        var neverIssued = await Invoke(store, host.Address, HandleCodec.NewWire());

        // One refusal, byte for byte, whatever the truth about the presented handle is.
        Assert.Equal(ExecutionFailureKind.Compilation, crossScope.Failure);
        Assert.Equal(ExecutionFailureKind.Compilation, neverIssued.Failure);
        Assert.Equal(neverIssued.FailureReason, crossScope.FailureReason);

        // Neither refusal reproduced the presented form, and neither reached the upstream.
        Assert.DoesNotContain(theirsWire, crossScope.FailureReason!, StringComparison.Ordinal);
        Assert.Empty(arrivals);
    }

    [Fact]
    public async Task An_expired_handle_is_distinguished_from_a_never_issued_one()
    {
        var arrivals = new List<byte[]>();
        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                using var buffer = new MemoryStream();
                await context.Request.Body.CopyToAsync(buffer, context.RequestAborted);
                arrivals.Add(buffer.ToArray());
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);

        var root = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), "mcpiler-wire-" + Guid.NewGuid().ToString("N")));
        _roots.Add(root.FullName);

        var clock = new MutableClock(DateTimeOffset.UtcNow);
        var issuingStore = new FileHandleStore(
            new FileHandleStoreOptions(root.FullName, TimeSpan.FromMinutes(1), 1024 * 1024, false, [], TimeSpan.FromMinutes(5)),
            clock);
        var reference = await Issue(issuingStore, "/api");
        string wire = Wire(issuingStore, reference);

        clock.Now = clock.GetUtcNow().AddHours(2);

        using var clients = new UpstreamClientFactory(Permissive());
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver(), issuingStore);

        var result = await service.ExecuteAsync(
            new ExecutionRequest(FileSlotManifest(host.Address), UploadSlug, new JsonObject
            {
                ["attachment"] = wire,
            })
            {
                Scope = "/api",
            },
            Token);

        // Expiry is a fact about a handle the caller itself was given, not about anyone else's
        // namespace, so it keeps its own answer.
        Assert.Equal(ExecutionFailureKind.Compilation, result.Failure);
        Assert.Contains("expired", result.FailureReason!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "expired",
            RedemptionAuthorization.UnknownMessage,
            StringComparison.OrdinalIgnoreCase);
        Assert.Empty(arrivals);
    }

    [Fact]
    public async Task A_failed_redemption_never_carries_the_presented_handle()
    {
        var arrivals = new List<byte[]>();
        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                using var buffer = new MemoryStream();
                await context.Request.Body.CopyToAsync(buffer, context.RequestAborted);
                arrivals.Add(buffer.ToArray());
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);

        var store = NewStore();
        var presented = await Issue(store, "other-mount");
        string presentedWire = Wire(store, presented);

        var result = await Invoke(store, host.Address, presentedWire);

        string rendered = string.Join(
            '\n',
            result.FailureReason ?? string.Empty,
            result.FailureDetail?.ToJsonString() ?? string.Empty,
            result.ToString());

        Assert.DoesNotContain(presentedWire, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(presented.Id, rendered, StringComparison.Ordinal);
        Assert.Empty(arrivals);
    }

    [Fact]
    public async Task A_presented_handle_reaches_the_upstream_as_bytes_not_as_a_string()
    {
        var arrivals = new List<byte[]>();
        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                using var buffer = new MemoryStream();
                await context.Request.Body.CopyToAsync(buffer, context.RequestAborted);
                arrivals.Add(buffer.ToArray());
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            Token);

        var store = NewStore();
        var mine = await Issue(store, "/api");
        string mineWire = Wire(store, mine);

        using var clients = new UpstreamClientFactory(Permissive());
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver(), store);

        var result = await service.ExecuteAsync(
            new ExecutionRequest(FileSlotManifest(host.Address), UploadSlug, new JsonObject
            {
                ["attachment"] = mineWire,
            })
            {
                Scope = "/api",
            },
            Token);

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        byte[] sent = Assert.Single(arrivals);
        string body = Encoding.UTF8.GetString(sent);

        // The payload crossed as bytes under the file part; the handle text never travelled.
        Assert.Contains(mine.FileName, body, StringComparison.Ordinal);
        Assert.DoesNotContain(mineWire, body, StringComparison.Ordinal);
        Assert.DoesNotContain("payload for report.png", body, StringComparison.Ordinal);
    }

    private const string UploadSlug = "upload-thing";

    private sealed class MutableClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static Manifest.Model.ManifestDocument FileSlotManifest(Uri upstream)
    {
        var operation = new ManifestOperation(
            ManifestOperation.BuildKey("POST", "/upload"),
            "POST",
            "/upload",
            UpstreamId: "upload-thing",
            RequestBody: new ManifestRequestBody(new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal)
            {
                ["multipart/form-data"] = new("multipart/form-data"),
            }));

        return new ManifestDocument(
            ManifestFormatSupport.Maximum,
            new ServerSection("test-server", Version: "1.0.0"),
            new PolicySection(upstream),
            new OperationsSection([operation]),
            new AgentSurfaceSection(
            [
                new AgentOperationEntry(
                    UploadSlug,
                    "Upload thing",
                    new TransformedHttpBinding(
                        new HttpBinding(operation.Key),
                        InputProgram: FileSlotProgram()),
                    InputSchema: ManifestSchema.From(new JsonObject
                    {
                        ["type"] = "object",
                        ["properties"] = new JsonObject
                        {
                            ["attachment"] = new JsonObject
                            {
                                ["type"] = "string",
                                ["x-mcp-file"] = true,
                            },
                        },
                    })),
            ]));
    }

    private static JsonObject FileSlotProgram() => new()
    {
        ["transformVersion"] = 1,
        ["direction"] = "input",
        ["base"] = "passthrough",
        ["limits"] = new JsonObject
        {
            ["maxSteps"] = 64,
            ["maxDepth"] = 32,
            ["maxNodes"] = 8192,
            ["maxOutputBytes"] = 262144,
            ["maxArrayFanout"] = 1024,
        },
        ["steps"] = new JsonArray
        {
            new JsonObject
            {
                ["op"] = "fileRef",
                ["source"] = "/attachment",
                ["target"] = "/body/attachment",
                ["onMissing"] = "error",
            },
        },
    };

    private async Task<EngineExecutionResult> Invoke(
        FileHandleStore store,
        Uri upstream,
        string presented)
    {
        using var clients = new UpstreamClientFactory(Permissive());
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver(), store);

        return await service.ExecuteAsync(
            new ExecutionRequest(FileSlotManifest(upstream), UploadSlug, new JsonObject
            {
                ["attachment"] = presented,
            })
            {
                Scope = "/api",
            },
            Token);
    }

    private static OutboundConnectionPolicy Permissive() => new(_ => false);

    private FileHandleStore NewStore()
    {
        var root = Path.Combine(Path.GetTempPath(), "mcpiler-wire-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);

        return new FileHandleStore(FileHandleStoreOptions.For(root));
    }

    private static async Task<FileHandleReference> Issue(FileHandleStore store, string scope)
        => await store.IssueAsync(
            new MemoryStream(Payload),
            "report.png",
            "image/png",
            scope,
            TestContext.Current.CancellationToken);

    private static string Wire(FileHandleStore store, FileHandleReference reference)
        => store.WireFormFor(reference.Id);

    public void Dispose()
    {
        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
