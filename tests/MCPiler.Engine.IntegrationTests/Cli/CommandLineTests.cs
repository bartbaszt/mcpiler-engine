using System;
using System.Collections.Generic;
using System.Linq;

using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Host.Configuration;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Cli;

/// <summary>
/// Reading arguments, and the deliberate absence of a second opinion about settings.
/// </summary>
public sealed class CommandLineTests
{
    [Theory]
    [InlineData("serve", HostVerb.Serve)]
    [InlineData("inspect", HostVerb.Inspect)]
    [InlineData("version", HostVerb.Version)]
    [InlineData("compatibility", HostVerb.Compatibility)]
    public void A_known_verb_is_read(string argument, HostVerb expected)
    {
        CommandLineResult parsed = CommandLine.Parse([argument]);

        Assert.Equal(expected, parsed.Verb);
        Assert.Empty(parsed.Refusals);
    }

    [Theory]
    [InlineData(new[] { "files", "list" }, HostVerb.FilesList)]
    [InlineData(new[] { "files", "sweep" }, HostVerb.FilesSweep)]
    public void A_files_subcommand_is_read(string[] arguments, HostVerb expected)
    {
        CommandLineResult parsed = CommandLine.Parse(arguments);

        Assert.Equal(expected, parsed.Verb);
        Assert.Empty(parsed.Refusals);
    }

    [Fact]
    public void Files_show_carries_its_identifier()
    {
        CommandLineResult parsed = CommandLine.Parse(["files", "show", "abc123"]);

        Assert.Equal(HostVerb.FilesShow, parsed.Verb);
        Assert.Equal("abc123", parsed.Operand);
    }

    [Fact]
    public void Files_show_without_an_identifier_is_refused()
    {
        CommandLineResult parsed = CommandLine.Parse(["files", "show"]);

        Assert.Null(parsed.Verb);
        Assert.Contains(parsed.Refusals, refusal => refusal.Contains("handle identifier", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unknown_verb_is_refused_by_name()
    {
        CommandLineResult parsed = CommandLine.Parse(["deploy"]);

        Assert.False(parsed.Recognized);
        Assert.Contains(parsed.Refusals, refusal => refusal.Contains("'deploy'", StringComparison.Ordinal));
    }

    [Fact]
    public void The_compatibility_option_is_a_whole_command_line()
    {
        CommandLineResult parsed = CommandLine.Parse(["--compatibility"]);

        Assert.Equal(HostVerb.Compatibility, parsed.Verb);
        Assert.Empty(parsed.Refusals);
    }

    [Fact]
    public void The_version_option_is_a_whole_command_line()
    {
        CommandLineResult parsed = CommandLine.Parse(["--version"]);

        Assert.Equal(HostVerb.Version, parsed.Verb);
        Assert.Empty(parsed.Refusals);
    }

    [Fact]
    public void A_mount_is_a_prefix_and_a_directory()
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--mount", "/api=/srv/api", "--mount", "/crm=/srv/crm"]);

        Assert.Equal(
            [new KeyValuePair<string, string>("/api", "/srv/api"), new KeyValuePair<string, string>("/crm", "/srv/crm")],
            parsed.Mounts);
    }

    [Theory]
    [InlineData("/api")]
    [InlineData("=/srv/api")]
    [InlineData("/api=")]
    public void A_malformed_mount_is_refused(string value)
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--mount", value]);

        Assert.NotEmpty(parsed.Refusals);
        Assert.Empty(parsed.Mounts);
    }

    [Fact]
    public void A_mount_limit_becomes_the_prefixed_setting_the_binder_reads()
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--mount-limit", "/api:RedirectHopLimit=2"]);

        Assert.Contains(
            new KeyValuePair<string, string>(HostConfiguration.MountNarrowingPrefix + "/api:RedirectHopLimit", "2"),
            parsed.Settings);
    }

    [Fact]
    public void A_floor_becomes_the_prefixed_setting_the_binder_reads()
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--floor", "RedirectHopLimit=1"]);

        Assert.Contains(
            new KeyValuePair<string, string>(HostConfiguration.FloorPrefix + "RedirectHopLimit", "1"),
            parsed.Settings);
    }

    [Fact]
    public void External_resource_bindings_are_repeatable_and_preserve_exact_values()
    {
        CommandLineResult parsed = CommandLine.Parse(
            [
                "serve",
                "--external-resource", "/api/full=https://tunnel.example.test/v1/mcp/one",
                "--external-resource=/crm/default=https://tunnel.example.test/v1/mcp/two/",
            ]);

        Assert.Empty(parsed.Refusals);
        Assert.Equal(
            [
                new KeyValuePair<string, string>(
                    HostConfiguration.ExternalResourcePrefix + "/api/full",
                    "https://tunnel.example.test/v1/mcp/one"),
                new KeyValuePair<string, string>(
                    HostConfiguration.ExternalResourcePrefix + "/crm/default",
                    "https://tunnel.example.test/v1/mcp/two/"),
            ],
            parsed.Settings.Where(setting => setting.Key.StartsWith(HostConfiguration.ExternalResourcePrefix, StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("/api/full")]
    [InlineData("=https://tunnel.example.test/v1/mcp/one")]
    [InlineData("/api/full=")]
    public void A_malformed_external_resource_mapping_is_refused_as_cli_syntax(string value)
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--external-resource", value]);

        Assert.NotEmpty(parsed.Refusals);
        Assert.DoesNotContain(
            parsed.Settings,
            setting => setting.Key.StartsWith(HostConfiguration.ExternalResourcePrefix, StringComparison.Ordinal));
    }

    [Fact]
    public void A_switch_with_no_value_is_true()
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--require-sealed", "--file-store-root", "/var/files"]);

        Assert.Contains(new KeyValuePair<string, string>("require-sealed", "true"), parsed.Settings);
        Assert.Contains(new KeyValuePair<string, string>("file-store-root", "/var/files"), parsed.Settings);
    }

    /// <summary>
    /// A following option is never eaten as a value.
    /// </summary>
    /// <remarks>
    /// The alternative reading turns <c>--require-sealed --listen x</c> into a switch set to
    /// the string "--listen" and silently drops the listen address, which is exactly the
    /// class of misconfiguration nobody notices until traffic arrives.
    /// </remarks>
    [Fact]
    public void An_option_following_a_switch_is_not_consumed_as_its_value()
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--allow-inline-secrets", "--listen", "http://127.0.0.1:8080"]);

        Assert.Contains(new KeyValuePair<string, string>("allow-inline-secrets", "true"), parsed.Settings);
        Assert.Contains(new KeyValuePair<string, string>("listen", "http://127.0.0.1:8080"), parsed.Settings);
    }

    [Fact]
    public void An_inline_value_is_read()
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--listen=http://127.0.0.1:9", "--require-sealed=false"]);

        Assert.Contains(new KeyValuePair<string, string>("listen", "http://127.0.0.1:9"), parsed.Settings);
        Assert.Contains(new KeyValuePair<string, string>("require-sealed", "false"), parsed.Settings);
    }

    [Fact]
    public void A_repeated_setting_survives_as_two_entries()
    {
        CommandLineResult parsed = CommandLine.Parse(
            ["serve", "--served-content-root", "/srv/a", "--served-content-root", "/srv/b"]);

        Assert.Equal(
            ["/srv/a", "/srv/b"],
            parsed.Settings.Where(setting => setting.Key == "served-content-root").Select(setting => setting.Value));
    }

    /// <summary>
    /// Which settings exist is decided in one place, and it is not here.
    /// </summary>
    /// <remarks>
    /// An unrecognized option is passed through as a setting so the binder refuses it by name
    /// against its own accepted list. A second list here would be a second answer to the same
    /// question, and the two would part company the first time one was extended.
    /// </remarks>
    [Fact]
    public void An_unrecognized_option_is_passed_to_the_binder_rather_than_judged_here()
    {
        CommandLineResult parsed = CommandLine.Parse(["serve", "--base-url", "https://evil.example.com"]);

        Assert.Empty(parsed.Refusals);
        Assert.Contains(new KeyValuePair<string, string>("base-url", "https://evil.example.com"), parsed.Settings);

        Assert.False(HostConfiguration.TryBind(parsed.Mounts, parsed.Settings, out _, out IReadOnlyList<string> refusals));
        Assert.Contains(refusals, refusal => refusal.Contains("'base-url'", StringComparison.Ordinal));
    }
}
