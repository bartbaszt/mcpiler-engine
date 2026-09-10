using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json.Nodes;
using System.Threading;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Replays the shared client-policy corpus against the production upstream client factory.
/// </summary>
/// <remarks>
/// <para>
/// The corpus is authored rather than generated. A corpus generated from this factory would
/// record whatever this implementation believes, so a setting both implementations get wrong
/// would be invisible in two green suites at once.
/// </para>
/// <para>
/// The compiling host carries the same file byte-identically and replays it against its own
/// factory. Neither side reads the other's code; they agree because they agree with the same
/// document. This side cannot check that the two copies match — the other repository may not be
/// present in a standalone checkout — so that assertion lives with the copy that can.
/// </para>
/// </remarks>
public sealed class ClientPolicyCorpusTests
{
    private static string CorpusPath => Path.Combine(TestRepository.Fixture("http"), "client-policy.json");

    public static TheoryData<string> CaseNames()
    {
        var data = new TheoryData<string>();
        foreach (var name in Cases().Select(entry => entry["name"]!.GetValue<string>()))
        {
            data.Add(name);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void EveryAuthoredCaseProducesTheHandlerTheCorpusStates(string name)
    {
        var testCase = Cases().Single(entry => entry["name"]!.GetValue<string>() == name);
        var policy = testCase["policy"]!.AsObject();
        var expected = testCase["client"]!.AsObject();

        var limits = new OutboundLimits(
            TimeSpan.FromSeconds(policy["connectTimeoutSeconds"]!.GetValue<double>()),
            policy["maxConnectionsPerServer"]!.GetValue<int>(),
            RedirectHopLimit: 5);

        using var handler = UpstreamClientFactory.CreateSocketsHandler(limits, new OutboundConnectionPolicy());

        Assert.Equal(expected["allowAutoRedirect"]!.GetValue<bool>(), handler.AllowAutoRedirect);
        Assert.Equal(
            TimeSpan.FromSeconds(expected["connectTimeoutSeconds"]!.GetValue<double>()),
            handler.ConnectTimeout);
        Assert.Equal(expected["maxConnectionsPerServer"]!.GetValue<int>(), handler.MaxConnectionsPerServer);
        Assert.Equal(Decompression(expected), handler.AutomaticDecompression);
        Assert.Equal(expected["hasConnectCallback"]!.GetValue<bool>(), handler.ConnectCallback is not null);
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void EveryAuthoredCaseProducesTheClientDeadlineTheCorpusStates(string name)
    {
        var testCase = Cases().Single(entry => entry["name"]!.GetValue<string>() == name);
        var policy = testCase["policy"]!.AsObject();
        var expected = testCase["client"]!.AsObject();

        var limits = new OutboundLimits(
            TimeSpan.FromSeconds(policy["connectTimeoutSeconds"]!.GetValue<double>()),
            policy["maxConnectionsPerServer"]!.GetValue<int>(),
            RedirectHopLimit: 5);

        using var factory = new UpstreamClientFactory();

        var client = factory.Client(limits);

        Assert.Equal("none", expected["perClientDeadline"]!.GetValue<string>());
        Assert.Equal(Timeout.InfiniteTimeSpan, client.Timeout);

        Assert.Equal(
            expected["userAgentPresent"]!.GetValue<bool>(),
            client.DefaultRequestHeaders.UserAgent.Count > 0);
    }

    /// <summary>
    /// The corpus is not empty and every case states both halves.
    /// </summary>
    /// <remarks>
    /// A replay over an empty or half-written corpus passes and proves nothing.
    /// </remarks>
    [Fact]
    public void TheCorpusStatesAPolicyAndAClientForEveryNamedCase()
    {
        var cases = Cases().ToList();

        Assert.True(cases.Count >= 4, $"The corpus has shrunk to {cases.Count} cases.");

        foreach (var entry in cases)
        {
            Assert.False(string.IsNullOrWhiteSpace(entry["name"]!.GetValue<string>()));
            Assert.NotNull(entry["policy"]);
            Assert.NotNull(entry["client"]);
            Assert.NotNull(entry["why"]);
        }

        Assert.Equal(
            cases.Count,
            cases.Select(entry => entry["name"]!.GetValue<string>()).Distinct(StringComparer.Ordinal).Count());
    }

    private static DecompressionMethods Decompression(JsonObject expected)
    {
        var methods = DecompressionMethods.None;

        foreach (var entry in expected["automaticDecompression"]!.AsArray())
        {
            methods |= entry!.GetValue<string>() switch
            {
                "gzip" => DecompressionMethods.GZip,
                "deflate" => DecompressionMethods.Deflate,
                "brotli" => DecompressionMethods.Brotli,
                var other => throw new InvalidOperationException($"The corpus names an unknown decompression method '{other}'."),
            };
        }

        return methods;
    }

    private static IEnumerable<JsonObject> Cases()
        => JsonNode.Parse(File.ReadAllText(CorpusPath))!["cases"]!
            .AsArray()
            .Select(entry => entry!.AsObject());
}
