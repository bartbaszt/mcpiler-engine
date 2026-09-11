using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// Which exposure strategy a mounted Manifest serves, and what can move it.
/// </summary>
/// <remarks>
/// A Manifest is immutable and its exposure is compiled, so the strategy a surface serves is a
/// property of the artifact. Nothing the operator supplies may move it; serving a different
/// strategy means mounting a different Manifest. That is a claim about the whole accepted
/// setting set rather than about any one setting, so it is asserted by varying all of them.
/// </remarks>
public sealed class ExposureStrategyTests : IDisposable
{
    private readonly List<string> _roots = [];

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_surface_that_curates_nothing_for_direct_advertisement_publishes_only_the_navigator()
    {
        string root = Root();
        string bundle = ServedManifests.Write(root, "pets", ServedManifests.NavigatorOnly);
        string files = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;

        await using var engine = await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", bundle)], files),
            Token);

        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);
        var listed = await session.RequestAsync("tools/list", 2, Token);

        // The trio and nothing else. A catalogue sits behind the surface and none of it is
        // published, which is what "Hybrid degenerates to Navigator" has to look like on the
        // wire rather than in a strategy field nobody can observe.
        Assert.Equal(
            [ManifestTool.NavigatorDiscover, ManifestTool.NavigatorDescribe, ManifestTool.NavigatorInvoke],
            Names(listed.Payload));
    }

    [Fact]
    public async Task No_setting_this_host_accepts_changes_what_a_surface_exposes()
    {
        string root = Root();
        string bundle = ServedManifests.Write(root, "pets", ServedManifests.ThreeSurfaces);

        string plainListing = await ListingAsync(
            bundle,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [HostConfiguration.FileStoreRootKey] = Files(root, "plain"),
            });

        string configuredListing = await ListingAsync(
            bundle,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [HostConfiguration.FileStoreRootKey] = Files(root, "configured"),
                [HostConfiguration.ListenKey] = "http://127.0.0.1:9999",
                [HostConfiguration.TransportKey] = "http",
                [HostConfiguration.RequireSealedKey] = "false",
                [HostConfiguration.AllowInlineSecretsKey] = "true",
                [HostConfiguration.ServedContentRootKey] = Files(root, "served"),
                [HostConfiguration.MountNarrowingPrefix + "/api:RedirectHopLimit"] = "1",
                [HostConfiguration.FloorPrefix + "Concurrency"] = "1",
            });

        // Byte-identical, not merely equivalent. Every setting the host accepts was moved off
        // its default in the second run, including the two that narrow the policy a Manifest
        // compiled, and the surface published exactly the same tools.
        Assert.Equal(plainListing, configuredListing);

        // Two equal failures would satisfy the comparison above and prove nothing, so the
        // listing has to be shown to be a listing.
        Assert.Equal(["list-pets", "add-pet"], Names(plainListing));
    }

    /// <summary>
    /// Serves one bundle under one set of host settings and returns the listing payload.
    /// </summary>
    /// <remarks>
    /// Bound through <see cref="HostConfiguration"/> rather than assembled as runtime options,
    /// because the claim is about what an operator can supply. Options built directly would
    /// skip the only component that decides which settings exist.
    /// </remarks>
    private async Task<string> ListingAsync(string bundle, Dictionary<string, string> settings)
    {
        bool bound = HostConfiguration.TryBind(
            [new KeyValuePair<string, string>("/api", bundle)],
            [.. settings],
            out HostBinding? binding,
            out IReadOnlyList<string> refusals);

        Assert.True(bound, string.Join("; ", refusals));

        await using var engine = await ServedEngine.StartAsync(binding!.Runtime, Token);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        return (await session.RequestAsync("tools/list", 2, Token)).Payload;
    }

    private static string[] Names(string listing)
    {
        using var document = JsonDocument.Parse(listing);

        return [.. document.RootElement
            .GetProperty("result")
            .GetProperty("tools")
            .EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString()!)];
    }

    private static string Files(string root, string name)
        => Directory.CreateDirectory(Path.Combine(root, name)).FullName;

    private string Root()
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-exposure-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);
        Directory.CreateDirectory(root);
        return root;
    }

    public void Dispose()
    {
        foreach (string root in _roots)
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
