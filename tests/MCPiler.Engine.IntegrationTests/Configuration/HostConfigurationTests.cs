using System;
using System.Collections.Generic;
using System.Linq;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Configuration;

/// <summary>
/// What the deployable accepts as configuration, and what it says about the rest.
/// </summary>
/// <remarks>
/// The interesting assertions here are refusals. A configuration surface that ignores what
/// it does not understand produces a process whose behaviour disagrees with the file that
/// started it, and the operator has no way to see the disagreement except by watching what
/// the process does.
/// </remarks>
public sealed class HostConfigurationTests
{
    [Fact]
    public void The_shutdown_drain_window_defaults_to_one_hundred_seconds()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out _));
        Assert.Equal(TimeSpan.FromSeconds(100), binding!.Lifecycle.DrainTimeout);
    }

    [Fact]
    public void The_shutdown_drain_window_can_be_narrowed_in_whole_seconds()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.DrainTimeoutSecondsKey] = "2",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out _));
        Assert.Equal(TimeSpan.FromSeconds(2), binding!.Lifecycle.DrainTimeout);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("later")]
    public void The_shutdown_drain_window_refuses_non_positive_or_non_whole_values(string value)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.DrainTimeoutSecondsKey] = value,
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        string refusal = Assert.Single(refusals);
        Assert.Contains(HostConfiguration.DrainTimeoutSecondsKey, refusal, StringComparison.Ordinal);
        Assert.Contains("positive whole number of seconds", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unrecognized_setting_is_refused_by_name_and_the_message_lists_what_is_accepted()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            ["base-url"] = "https://elsewhere.example.com",
        };

        bool bound = HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals);

        Assert.False(bound);
        Assert.Null(binding);
        string refusal = Assert.Single(refusals);
        Assert.Contains("'base-url'", refusal, StringComparison.Ordinal);
        Assert.Contains(HostConfiguration.FileStoreRootKey, refusal, StringComparison.Ordinal);
    }

    /// <summary>
    /// The three things a Manifest compiles are absent from the accepted set, by name.
    /// </summary>
    /// <remarks>
    /// Asserted explicitly rather than left to the default branch, because these are the
    /// settings a hurried deployment most wants and the ones that would quietly move the
    /// truth out of the reviewed artifact.
    /// </remarks>
    [Theory]
    [InlineData("base-url")]
    [InlineData("allowed-origins")]
    [InlineData("credential")]
    [InlineData("upstream-request-timeout")]
    public void A_setting_a_manifest_compiles_is_not_configurable(string key)
    {
        Assert.DoesNotContain(key, HostConfiguration.AcceptedKeys, StringComparer.Ordinal);

        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [key] = "anything",
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(refusals, message => message.Contains($"'{key}'", StringComparison.Ordinal));
    }

    [Fact]
    public void A_file_store_root_is_required_because_an_issued_handle_needs_somewhere_to_live()
    {
        Assert.False(HostConfiguration.TryBind(Mounts(), [.. Empty()], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(refusals, message => message.Contains(HostConfiguration.FileStoreRootKey, StringComparison.Ordinal));
    }

    [Fact]
    public void A_bound_narrowed_on_one_mount_reaches_that_mount_and_no_other()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.MountNarrowingPrefix + "/one:RedirectHopLimit"] = "2",
            [HostConfiguration.FloorPrefix + "Concurrency"] = "4",
        };

        List<KeyValuePair<string, string>> mounts =
        [
            new("/one", "/manifests/one"),
            new("/two", "/manifests/two"),
        ];

        Assert.True(HostConfiguration.TryBind(mounts, [.. settings], out HostBinding? binding, out _));

        RuntimeOptions options = binding!.Runtime;

        Assert.Equal("2", options.Mounts[0].Narrowing["RedirectHopLimit"]);
        Assert.Empty(options.Mounts[1].Narrowing);
        Assert.Equal("4", options.Floors["Concurrency"]);
    }

    [Fact]
    public void A_mount_narrowing_key_that_names_no_bound_is_refused_for_its_shape()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.MountNarrowingPrefix + "onlyoneword"] = "2",
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(refusals, message => message.Contains("does not name a mount and a bound", StringComparison.Ordinal));
    }

    [Fact]
    public void A_switch_given_something_other_than_true_or_false_is_refused()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.RequireSealedKey] = "yes",
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(refusals, message => message.Contains("not true or false", StringComparison.Ordinal));
    }

    /// <summary>
    /// The narrowable bounds are not restated by the host, so they cannot drift from the library.
    /// </summary>
    /// <remarks>
    /// This is the assertion that keeps the prefixed key family honest. The host validates the
    /// prefix and the shape; which bound names exist is the library's list, and a bound added
    /// there becomes configurable without anyone editing the host.
    /// </remarks>
    [Fact]
    public void The_host_states_no_bound_names_of_its_own()
    {
        IReadOnlyList<string> bounds = [.. PolicyNarrowing.ProtectedLimits.Select(limit => limit.Name)];

        Assert.NotEmpty(bounds);
        Assert.All(bounds, bound => Assert.DoesNotContain(bound, HostConfiguration.AcceptedKeys, StringComparer.Ordinal));
    }

    private static List<KeyValuePair<string, string>> Mounts() => [new("/api", "/manifests/api")];

    private static Dictionary<string, string> Empty() => new(StringComparer.Ordinal);
}
