using System;
using System.Collections.Generic;
using System.IO;
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
    public void A_master_key_is_not_a_host_setting_because_engine_persists_no_protected_secret_material()
    {
        const string key = "master-key";

        Assert.DoesNotContain(key, HostConfiguration.AcceptedKeys, StringComparer.Ordinal);

        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [key] = "verification-only",
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

    /// <summary>
    /// A process that names no mode serves its local Manifests.
    /// </summary>
    /// <remarks>
    /// The default matters more than the explicit value. Every deployment written before managed
    /// mode existed names local mounts and no mode, and if the absent key meant anything but file
    /// mode those command lines would start refusing.
    /// </remarks>
    [Fact]
    public void An_absent_mode_serves_the_local_mounts()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out _));
        Assert.Equal(HostDeploymentMode.File, binding!.Mode);
    }

    [Fact]
    public void The_file_mode_may_be_stated_explicitly_with_local_mounts()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ModeKey] = HostConfiguration.FileModeName,
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out _));
        Assert.Equal(HostDeploymentMode.File, binding!.Mode);
    }

    [Fact]
    public void File_mode_binds_repeatable_external_resources_by_exact_surface_route()
    {
        List<KeyValuePair<string, string>> settings =
        [
            new(HostConfiguration.FileStoreRootKey, "/var/lib/mcpiler"),
            new(
                HostConfiguration.ExternalResourcePrefix + "/api/full",
                "https://tunnel.example.test/v1/mcp/one"),
            new(
                HostConfiguration.ExternalResourcePrefix + "/crm/default",
                "https://tunnel.example.test/v1/mcp/two/"),
        ];

        Assert.True(HostConfiguration.TryBind(Mounts(), settings, out HostBinding? binding, out IReadOnlyList<string> refusals));

        Assert.Empty(refusals);
        Assert.Equal("https://tunnel.example.test/v1/mcp/one", binding!.ExternalResources["/api/full"]);
        Assert.Equal("https://tunnel.example.test/v1/mcp/two/", binding.ExternalResources["/crm/default"]);
        Assert.False(binding.ExternalResources.ContainsKey("/api"));
    }

    [Theory]
    [InlineData("http://tunnel.example.test/v1/mcp/one")]
    [InlineData("/v1/mcp/one")]
    [InlineData("https://tunnel.example.test/v1/mcp/one?channel=main")]
    [InlineData("https://tunnel.example.test/v1/mcp/one#fragment")]
    public void File_mode_refuses_invalid_external_resource_uris(string resource)
    {
        List<KeyValuePair<string, string>> settings =
        [
            new(HostConfiguration.FileStoreRootKey, "/var/lib/mcpiler"),
            new(HostConfiguration.ExternalResourcePrefix + "/api/full", resource),
        ];

        Assert.False(HostConfiguration.TryBind(Mounts(), settings, out _, out IReadOnlyList<string> refusals));
        Assert.Contains(
            refusals,
            refusal => refusal.Contains("external resource", StringComparison.Ordinal)
                && refusal.Contains("HTTPS", StringComparison.Ordinal));
    }

    [Fact]
    public void File_mode_refuses_one_external_resource_assigned_to_two_surface_routes()
    {
        const string resource = "https://tunnel.example.test/v1/mcp/shared";
        List<KeyValuePair<string, string>> settings =
        [
            new(HostConfiguration.FileStoreRootKey, "/var/lib/mcpiler"),
            new(HostConfiguration.ExternalResourcePrefix + "/api/full", resource),
            new(HostConfiguration.ExternalResourcePrefix + "/crm/default", resource),
        ];

        Assert.False(HostConfiguration.TryBind(Mounts(), settings, out _, out IReadOnlyList<string> refusals));
        Assert.Contains(
            refusals,
            refusal => refusal.Contains("already assigned", StringComparison.Ordinal)
                && refusal.Contains("/api/full", StringComparison.Ordinal)
                && refusal.Contains("/crm/default", StringComparison.Ordinal));
    }

    [Fact]
    public void Managed_mode_refuses_local_external_resource_configuration()
    {
        List<KeyValuePair<string, string>> settings =
        [
            new(HostConfiguration.FileStoreRootKey, "/var/lib/mcpiler"),
            new(HostConfiguration.ModeKey, HostConfiguration.ManagedModeName),
            new(HostConfiguration.ManagementEndpointKey, "https://platform.example.test"),
            new(HostConfiguration.DeploymentIdKey, "deployment-1"),
            new(HostConfiguration.DeploymentSecretFileKey, "/run/secrets/deployment"),
            new(
                HostConfiguration.ExternalResourcePrefix + "/api/full",
                "https://tunnel.example.test/v1/mcp/one"),
        ];

        Assert.False(HostConfiguration.TryBind([], settings, out _, out IReadOnlyList<string> refusals));
        Assert.Contains(
            refusals,
            refusal => refusal.Contains(HostConfiguration.ManagedModeName, StringComparison.Ordinal)
                && refusal.Contains("--external-resource", StringComparison.Ordinal));
    }

    /// <summary>
    /// A managed process refuses local mounts, because the two are competing authorities.
    /// </summary>
    /// <remarks>
    /// The refusal has to name both halves. An operator who set the mode and left a mount on the
    /// command line from an earlier deployment needs to know which line to remove, and a message
    /// that only said "invalid configuration" would leave them reading the whole command line.
    /// </remarks>
    [Fact]
    public void A_managed_mode_with_local_mounts_is_refused_before_a_listener_could_exist()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ModeKey] = HostConfiguration.ManagedModeName,
            [HostConfiguration.ManagementEndpointKey] = "https://platform.example.test",
            [HostConfiguration.DeploymentIdKey] = "deployment-1",
            [HostConfiguration.DeploymentSecretFileKey] = "/run/secrets/deployment",
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));

        // The mode refusal is the one this test is about; the other settings are present so the
        // managed half is complete and the competing-authority refusal is not joined by
        // "incomplete managed configuration" findings.
        string refusal = Assert.Single(
            refusals,
            entry => entry.Contains(HostConfiguration.ModeKey, StringComparison.Ordinal));

        // The message names the competing setting the operator must remove. This is the only
        // place the two authorities are reconciled, so the message is part of the contract.
        Assert.Contains("--mount", refusal, StringComparison.Ordinal);
        Assert.Contains(HostConfiguration.FileModeName, refusal, StringComparison.Ordinal);
    }

    /// <summary>
    /// Managed mode with no local mounts is exactly the shape managed mode exists for.
    /// </summary>
    /// <remarks>
    /// The bind must succeed: the mounts come from synchronization, so an empty local mount list is
    /// correct rather than incomplete. A refusal here would make managed mode unreachable.
    /// </remarks>
    [Fact]
    public void A_managed_mode_without_local_mounts_binds()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ModeKey] = HostConfiguration.ManagedModeName,
            [HostConfiguration.ManagementEndpointKey] = "https://platform.example.test",
            [HostConfiguration.DeploymentIdKey] = "deployment-1",
            [HostConfiguration.DeploymentSecretFileKey] = "/run/secrets/deployment",
        };

        Assert.True(HostConfiguration.TryBind([], [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));

        Assert.Empty(refusals);
        Assert.Equal(HostDeploymentMode.Managed, binding!.Mode);
        Assert.Empty(binding.Runtime.Mounts);
        Assert.NotNull(binding.Managed);
        Assert.Equal("deployment-1", binding.Managed!.DeploymentId);
    }

    /// <summary>
    /// A managed process names all three synchronization settings or none of them.
    /// </summary>
    /// <remarks>
    /// Each omission is reported separately so an operator fixing one at a time still sees the
    /// whole shape they have to supply, rather than discovering the next one on the next restart.
    /// </remarks>
    [Fact]
    public void A_managed_mode_without_synchronization_settings_is_refused_by_name()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ModeKey] = HostConfiguration.ManagedModeName,
        };

        Assert.False(HostConfiguration.TryBind([], [.. settings], out _, out IReadOnlyList<string> refusals));

        Assert.Contains(refusals, entry => entry.Contains(HostConfiguration.ManagementEndpointKey, StringComparison.Ordinal));
        Assert.Contains(refusals, entry => entry.Contains(HostConfiguration.DeploymentIdKey, StringComparison.Ordinal));
        Assert.Contains(refusals, entry => entry.Contains(HostConfiguration.DeploymentSecretFileKey, StringComparison.Ordinal));
    }

    /// <summary>
    /// A remote management endpoint must be https, because it carries the deployment secret.
    /// </summary>
    /// <remarks>
    /// Loopback is exempt so tests and local diagnostics can run without a certificate. The
    /// distinction is the host, not the scheme, so a remote plain-http endpoint is the case this
    /// pins.
    /// </remarks>
    [Theory]
    [InlineData("http://platform.example.test")]
    [InlineData("http://192.0.2.10:8080")]
    public void A_remote_management_endpoint_over_http_is_refused(string endpoint)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ModeKey] = HostConfiguration.ManagedModeName,
            [HostConfiguration.ManagementEndpointKey] = endpoint,
            [HostConfiguration.DeploymentIdKey] = "deployment-1",
            [HostConfiguration.DeploymentSecretFileKey] = "/run/secrets/deployment",
        };

        Assert.False(HostConfiguration.TryBind([], [.. settings], out _, out IReadOnlyList<string> refusals));

        Assert.Contains(
            refusals,
            entry => entry.Contains(HostConfiguration.ManagementEndpointKey, StringComparison.Ordinal)
                && entry.Contains("https", StringComparison.Ordinal));
    }

    /// <summary>
    /// A loopback management endpoint may be plain http, which is what tests and local diagnostics use.
    /// </summary>
    [Theory]
    [InlineData("http://127.0.0.1:5099")]
    [InlineData("http://localhost:5099")]
    [InlineData("https://platform.example.test")]
    public void A_safe_management_endpoint_binds(string endpoint)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ModeKey] = HostConfiguration.ManagedModeName,
            [HostConfiguration.ManagementEndpointKey] = endpoint,
            [HostConfiguration.DeploymentIdKey] = "deployment-1",
            [HostConfiguration.DeploymentSecretFileKey] = "/run/secrets/deployment",
        };

        Assert.True(HostConfiguration.TryBind([], [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
        Assert.Equal(endpoint, binding!.Managed!.Endpoint.ToString().TrimEnd('/'));
    }

    /// <summary>
    /// A file-mode process accepts no synchronization settings, because none of them would be read.
    /// </summary>
    [Fact]
    public void A_file_mode_process_refuses_synchronization_settings()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ManagementEndpointKey] = "https://platform.example.test",
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));

        Assert.Contains(refusals, entry => entry.Contains(HostConfiguration.ManagementEndpointKey, StringComparison.Ordinal));
    }

    /// <summary>
    /// An explicitly file-mode process with no mounts is refused by name rather than by the library.
    /// </summary>
    /// <remarks>
    /// The library would refuse the empty mount set anyway, but naming the mode is what tells an
    /// operator who set it that the setting is the one that has no content to serve.
    /// </remarks>
    [Fact]
    public void An_explicit_file_mode_without_mounts_is_refused()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ModeKey] = HostConfiguration.FileModeName,
        };

        Assert.False(HostConfiguration.TryBind([], [.. settings], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(refusals, message => message.Contains(HostConfiguration.ModeKey, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("platform")]
    [InlineData("remote")]
    [InlineData("File")]
    public void A_mode_outside_the_two_accepted_spellings_is_refused(string value)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ModeKey] = value,
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));

        string refusal = Assert.Single(refusals);
        Assert.Contains(HostConfiguration.ModeKey, refusal, StringComparison.Ordinal);
        Assert.Contains(HostConfiguration.FileModeName, refusal, StringComparison.Ordinal);
        Assert.Contains(HostConfiguration.ManagedModeName, refusal, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("example.com:8080")]
    [InlineData("example.com:80")]
    [InlineData("[::1]")]
    [InlineData("[::1]:8080")]
    [InlineData("HOST.EXAMPLE")]
    public void An_allowed_host_preserves_the_declared_scheme_neutral_authority(string authority)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.AllowedHostKey] = authority,
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
        Assert.Equal([authority], binding!.AllowedHosts);
    }

    [Theory]
    [InlineData("http://0.0.0.0:8080")]
    [InlineData("http://[::]:8080")]
    public void A_wildcard_listener_does_not_derive_an_allowed_host(string listen)
    {
        Dictionary<string, string> settings = AuthorizedHttpSettings(listen);

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
        Assert.Empty(binding!.AllowedHosts);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8080", "127.0.0.1:8080")]
    [InlineData("http://[::1]:8080", "[::1]:8080")]
    [InlineData("http://127.0.0.1:80", "127.0.0.1:80")]
    [InlineData("https://example.com:443", "example.com:443")]
    [InlineData("http://[::1]:80", "[::1]:80")]
    [InlineData("http://example.com", "example.com")]
    [InlineData("https://example.com", "example.com")]
    public void A_concrete_listener_derives_its_authority(string listen, string expected)
    {
        Dictionary<string, string> settings = AuthorizedHttpSettings(listen);

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
        Assert.Equal([expected], binding!.AllowedHosts);
    }

    /// <summary>
    /// A browser origin is stored in the canonical spelling every comparison uses.
    /// </summary>
    /// <remarks>
    /// The header a browser sends carries no path, query or trailing slash, so accepting those
    /// spellings in configuration and comparing them verbatim would make a correctly written
    /// setting silently admit nothing.
    /// </remarks>
    [Theory]
    [InlineData("https://studio.example.test", "https://studio.example.test")]
    [InlineData("https://studio.example.test/", "https://studio.example.test")]
    [InlineData("http://127.0.0.1:5099", "http://127.0.0.1:5099")]
    public void An_allowed_browser_origin_binds_in_its_canonical_spelling(string declared, string expected)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.AllowedOriginKey] = declared,
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
        Assert.Equal([expected], binding!.AllowedOrigins);
    }

    /// <summary>
    /// A value that is not an origin is refused, because it would admit nothing.
    /// </summary>
    [Theory]
    [InlineData("studio.example.test")]
    [InlineData("https://studio.example.test/studio")]
    [InlineData("https://studio.example.test?x=1")]
    [InlineData("ftp://studio.example.test")]
    public void A_value_that_is_not_a_browser_origin_is_refused(string value)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.AllowedOriginKey] = value,
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));

        string refusal = Assert.Single(refusals);
        Assert.Contains(HostConfiguration.AllowedOriginKey, refusal, StringComparison.Ordinal);
    }

    /// <summary>
    /// An absent origin list is the right default: no browser page may call a served address,
    /// while every non-browser client is unaffected.
    /// </summary>
    [Fact]
    public void No_configured_origin_means_no_browser_origin_is_admitted()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
        Assert.Empty(binding!.AllowedOrigins);
    }

    /// <summary>
    /// The resource-server credential is one decision: an identity and the file holding its
    /// secret, or neither.
    /// </summary>
    /// <remarks>
    /// An identity with no secret authenticates to nobody and a secret with no identity has no
    /// name to present, so each half alone is refused where it is written rather than as a 401
    /// the operator would debug at the issuer.
    /// </remarks>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void A_half_configured_introspection_client_is_refused(bool withClientId, bool withSecretFile)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "https://issuer.example.test",
            [HostConfiguration.TokenValidationKey] = "introspection",
        };

        if (withClientId)
        {
            settings[HostConfiguration.IntrospectionClientIdKey] = "engine-resource-server";
        }

        if (withSecretFile)
        {
            settings[HostConfiguration.IntrospectionClientSecretFileKey] = "/run/secrets/introspection";
        }

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));

        string refusal = Assert.Single(refusals);
        Assert.Contains(
            withClientId
                ? HostConfiguration.IntrospectionClientSecretFileKey
                : HostConfiguration.IntrospectionClientIdKey,
            refusal,
            StringComparison.Ordinal);
    }

    /// <summary>Both halves together bind and are carried through.</summary>
    [Fact]
    public void A_complete_introspection_client_binds()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "https://issuer.example.test",
            [HostConfiguration.TokenValidationKey] = "introspection",
            [HostConfiguration.IntrospectionClientIdKey] = "engine-resource-server",
            [HostConfiguration.IntrospectionClientSecretFileKey] = "/run/secrets/introspection",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
        Assert.Equal("engine-resource-server", binding!.Authorization!.IntrospectionClientId);
        Assert.Equal("/run/secrets/introspection", binding.Authorization.IntrospectionClientSecretFile);
    }

    /// <summary>An introspection credential under the jwks mode is refused.</summary>
    /// <remarks>
    /// The jwks mode never calls an introspection endpoint, so the credential could not be used.
    /// Accepting it would tell an operator the resource identity is configured when every
    /// validation takes the other path, which is the same class of mistake as an introspection
    /// endpoint under jwks.
    /// </remarks>
    [Fact]
    public void An_introspection_client_under_the_jwks_mode_is_refused()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "https://issuer.example.test",
            [HostConfiguration.TokenValidationKey] = "jwks",
            [HostConfiguration.IntrospectionClientIdKey] = "engine-resource-server",
            [HostConfiguration.IntrospectionClientSecretFileKey] = "/run/secrets/introspection",
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));

        string refusal = Assert.Single(refusals);
        Assert.Contains(HostConfiguration.TokenValidationKey, refusal, StringComparison.Ordinal);
    }

    /// <summary>An introspection client without an issuer is refused: it authenticates to nobody.</summary>
    [Fact]
    public void An_introspection_client_without_an_issuer_is_refused()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IntrospectionClientIdKey] = "engine-resource-server",
            [HostConfiguration.IntrospectionClientSecretFileKey] = "/run/secrets/introspection",
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));

        string refusal = Assert.Single(refusals);
        Assert.Contains(HostConfiguration.IssuerKey, refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void Introspection_cache_ttl_defaults_to_thirty_seconds()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "https://issuer.example.test",
            [HostConfiguration.TokenValidationKey] = HostConfiguration.IntrospectionModeName,
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out _));
        Assert.Equal(30, binding!.Authorization!.IntrospectionCacheTtlSeconds);
    }

    [Theory]
    [InlineData("0", 0)]
    [InlineData("45", 45)]
    public void Introspection_cache_ttl_accepts_zero_and_positive_whole_seconds(string value, int expected)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "https://issuer.example.test",
            [HostConfiguration.TokenValidationKey] = HostConfiguration.IntrospectionModeName,
            [HostConfiguration.IntrospectionCacheTtlSecondsKey] = value,
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out _));
        Assert.Equal(expected, binding!.Authorization!.IntrospectionCacheTtlSeconds);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("later")]
    public void Introspection_cache_ttl_refuses_negative_or_non_integer_values(string value)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "https://issuer.example.test",
            [HostConfiguration.TokenValidationKey] = HostConfiguration.IntrospectionModeName,
            [HostConfiguration.IntrospectionCacheTtlSecondsKey] = value,
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        string refusal = Assert.Single(refusals);
        Assert.Contains(HostConfiguration.IntrospectionCacheTtlSecondsKey, refusal, StringComparison.Ordinal);
        Assert.Contains("non-negative whole number", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void Introspection_cache_ttl_is_refused_under_jwks_mode()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "https://issuer.example.test",
            [HostConfiguration.TokenValidationKey] = HostConfiguration.JwksModeName,
            [HostConfiguration.IntrospectionCacheTtlSecondsKey] = "30",
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        string refusal = Assert.Single(refusals);
        Assert.Contains(HostConfiguration.IntrospectionCacheTtlSecondsKey, refusal, StringComparison.Ordinal);
        Assert.Contains(HostConfiguration.JwksModeName, refusal, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HostConfiguration.IssuerKey, "http://issuer.example.test", HostConfiguration.IntrospectionModeName)]
    [InlineData(HostConfiguration.IntrospectionEndpointKey, "http://issuer.example.test/introspect", HostConfiguration.IntrospectionModeName)]
    [InlineData(HostConfiguration.JwksUriKey, "http://issuer.example.test/jwks", HostConfiguration.JwksModeName)]
    public void A_remote_http_authorization_trust_address_is_refused(
        string key,
        string address,
        string validation)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "https://issuer.example.test",
            [HostConfiguration.TokenValidationKey] = validation,
            [key] = address,
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(
            refusals,
            refusal => refusal.Contains($"'{key}'", StringComparison.Ordinal)
                && refusal.Contains("https", StringComparison.Ordinal));
    }

    [Fact]
    public void Loopback_http_authorization_trust_addresses_are_allowed()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.IssuerKey] = "http://127.0.0.1:5099",
            [HostConfiguration.TokenValidationKey] = HostConfiguration.IntrospectionModeName,
            [HostConfiguration.IntrospectionEndpointKey] = "http://localhost:5100/introspect",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
    }

    /// <summary>
    /// Both new keys are accepted settings rather than unknown ones.
    /// </summary>
    /// <remarks>
    /// An unknown setting is refused by name, so a key that was added to the binder but not to
    /// the accepted list would be reported as a typo in an otherwise valid deployment.
    /// </remarks>
    [Fact]
    public void The_introspection_client_settings_are_accepted_keys()
    {
        Assert.Contains(HostConfiguration.IntrospectionClientIdKey, HostConfiguration.AcceptedKeys);
        Assert.Contains(HostConfiguration.IntrospectionClientSecretFileKey, HostConfiguration.AcceptedKeys);
    }

    [Fact]
    public void Response_cache_host_settings_narrow_each_hard_ceiling()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ResponseCacheMaxBodyBytesKey] = "1048576",
            [HostConfiguration.ResponseCacheMaxRetainedBytesKey] = "33554432",
            [HostConfiguration.ResponseCacheMaxEntriesKey] = "128",
            [HostConfiguration.ResponseCacheMaxTtlSecondsKey] = "3600",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out IReadOnlyList<string> refusals));
        Assert.Empty(refusals);
        Assert.Equal(1_048_576, binding!.Runtime.ResponseCache.MaxBodyBytes);
        Assert.Equal(33_554_432, binding.Runtime.ResponseCache.MaxRetainedBytesPerMount);
        Assert.Equal(128, binding.Runtime.ResponseCache.MaxEntriesPerMount);
        Assert.Equal(3600, binding.Runtime.ResponseCache.MaxTtlSeconds);
    }

    [Fact]
    public void A_zero_response_cache_ceiling_disables_the_cache_without_refusing_the_host()
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ResponseCacheMaxTtlSecondsKey] = "0",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. settings], out HostBinding? binding, out _));
        Assert.True(binding!.Runtime.ResponseCache.IsDisabled);
    }

    [Theory]
    [InlineData(HostConfiguration.ResponseCacheMaxBodyBytesKey, "8388609", "8388608")]
    [InlineData(HostConfiguration.ResponseCacheMaxRetainedBytesKey, "268435457", "268435456")]
    [InlineData(HostConfiguration.ResponseCacheMaxEntriesKey, "4097", "4096")]
    [InlineData(HostConfiguration.ResponseCacheMaxTtlSecondsKey, "86401", "86400")]
    public void A_response_cache_widening_is_refused_with_the_hard_ceiling_named(
        string key,
        string attempted,
        string hardMaximum)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [key] = attempted,
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(refusals, refusal =>
            refusal.Contains(key, StringComparison.Ordinal)
            && refusal.Contains(attempted, StringComparison.Ordinal)
            && refusal.Contains(hardMaximum, StringComparison.Ordinal)
            && refusal.Contains("only narrow", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("later")]
    public void A_malformed_response_cache_ceiling_is_refused(string value)
    {
        Dictionary<string, string> settings = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ResponseCacheMaxTtlSecondsKey] = value,
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. settings], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(refusals, refusal =>
            refusal.Contains(HostConfiguration.ResponseCacheMaxTtlSecondsKey, StringComparison.Ordinal)
            && refusal.Contains("non-negative whole number", StringComparison.Ordinal));
    }

    /// <summary>
    /// The operator channel is opt-in, and its credential is a file the operator names.
    /// </summary>
    /// <remarks>
    /// Absent configuration must mean the channel is not mapped at all, so the assertion that
    /// matters is the empty secret plus the accepted key. The secret is read at bind time, so a
    /// valid file is proven here rather than at the first operator request.
    /// </remarks>
    [Fact]
    public void The_response_cache_operator_secret_is_optional_and_read_at_bind_time()
    {
        Assert.Contains(HostConfiguration.ResponseCacheOperatorSecretFileKey, HostConfiguration.AcceptedKeys);

        Dictionary<string, string> withoutChannel = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
        };

        Assert.True(HostConfiguration.TryBind(Mounts(), [.. withoutChannel], out HostBinding? closed, out _));

        // The safe default: no secret means no operator route exists, so nothing has to be
        // refused at request time.
        Assert.Null(closed!.ResponseCacheOperatorSecret);

        string path = Path.Combine(Path.GetTempPath(), "mcpiler-operator-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, "operator-secret-value\n");

        try
        {
            Dictionary<string, string> withChannel = new(StringComparer.Ordinal)
            {
                [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
                [HostConfiguration.ResponseCacheOperatorSecretFileKey] = path,
            };

            Assert.True(HostConfiguration.TryBind(Mounts(), [.. withChannel], out HostBinding? open, out _));

            // The trailing newline an editor adds is not part of the secret.
            Assert.Equal("operator-secret-value", open!.ResponseCacheOperatorSecret);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_missing_or_empty_response_cache_operator_secret_file_is_refused_at_bind_time()
    {
        Dictionary<string, string> missing = new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ResponseCacheOperatorSecretFileKey] =
                Path.Combine(Path.GetTempPath(), "mcpiler-absent-" + Guid.NewGuid().ToString("N")),
        };

        Assert.False(HostConfiguration.TryBind(Mounts(), [.. missing], out _, out IReadOnlyList<string> refusals));
        Assert.Contains(
            refusals,
            refusal => refusal.Contains(HostConfiguration.ResponseCacheOperatorSecretFileKey, StringComparison.Ordinal)
                || refusal.Contains("does not exist", StringComparison.Ordinal));

        string empty = Path.Combine(Path.GetTempPath(), "mcpiler-empty-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(empty, "\n");

        try
        {
            Dictionary<string, string> blank = new(StringComparer.Ordinal)
            {
                [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
                [HostConfiguration.ResponseCacheOperatorSecretFileKey] = empty,
            };

            Assert.False(HostConfiguration.TryBind(Mounts(), [.. blank], out _, out IReadOnlyList<string> refused));
            Assert.Contains(refused, refusal => refusal.Contains("empty", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(empty);
        }
    }

    private static Dictionary<string, string> AuthorizedHttpSettings(string listen)
        => new(StringComparer.Ordinal)
        {
            [HostConfiguration.FileStoreRootKey] = "/var/lib/mcpiler",
            [HostConfiguration.ListenKey] = listen,
            [HostConfiguration.IssuerKey] = "https://issuer.example",
            [HostConfiguration.TokenValidationKey] = HostConfiguration.IntrospectionModeName,
            [HostConfiguration.IntrospectionEndpointKey] = "https://issuer.example/introspect",
        };

    private static List<KeyValuePair<string, string>> Mounts() => [new("/api", "/manifests/api")];

    private static Dictionary<string, string> Empty() => new(StringComparer.Ordinal);
}
