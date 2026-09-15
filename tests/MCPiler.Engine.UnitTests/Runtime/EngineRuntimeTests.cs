using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Runtime;

/// <summary>
/// What the host refuses to start with, and what it silently accepts.
/// </summary>
/// <remarks>
/// <para>
/// Every case here asserts two things: the diagnostic an operator reads, and that
/// <see cref="RuntimeStartResult.Mounts"/> is empty. The second is the one that matters. A
/// refusal that still returns a mount would let a caller open a listener over a partially
/// configured process, and the whole reason the refusal exists is that a partially served
/// process is indistinguishable from an upstream fault.
/// </para>
/// <para>
/// Manifests are authored per test rather than shared, because most of these cases are about
/// the relationship between a compiled bound and a configured one, and a shared fixture would
/// make that relationship implicit.
/// </para>
/// </remarks>
public sealed class EngineRuntimeTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-runtime-" + Guid.NewGuid().ToString("N"));

    public EngineRuntimeTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void A_process_with_nothing_mounted_is_refused_rather_than_serving_an_empty_surface()
    {
        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([], FileStore()));

        Assert.False(result.Started);
        Assert.Equal("host/no-mount", Assert.Single(result.Refusals).Code);
        Assert.Empty(result.Mounts);
    }

    /// <summary>
    /// An absent bundle is reported by the loader, and the refusal still says which mount.
    /// </summary>
    /// <remarks>
    /// The code is the loader's rather than one this seam invents, because whether a
    /// directory holds a Manifest is the loader's question and asking it twice would put a
    /// second existence decision in a component that reaches nothing. What the seam adds is
    /// the mount and the path, which is what makes the message actionable when several
    /// Manifests are configured.
    /// </remarks>
    [Fact]
    public void A_mount_naming_an_absent_manifest_is_refused_and_the_refusal_names_the_mount()
    {
        string absent = Path.Combine(_root, "nowhere");
        MountRequest mount = new("/api", absent);

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([mount], FileStore()));

        StartupRefusal refusal = Assert.Single(result.Refusals);
        Assert.Equal("/api", refusal.Mount);
        Assert.Equal(absent, refusal.Manifest);
        Assert.Empty(result.Mounts);
    }

    [Fact]
    public void Two_manifests_on_one_prefix_are_refused_rather_than_resolved_by_order()
    {
        MountRequest first = new("/api", Manifest("first"));
        MountRequest second = new("/api", Manifest("second"));

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([first, second], FileStore()));

        Assert.Contains(result.Refusals, refusal => refusal.Code == "host/prefix-duplicate");
        Assert.Empty(result.Mounts);
    }

    [Fact]
    public void An_unrecognized_bound_is_refused_by_name_rather_than_ignored()
    {
        MountRequest mount = Mount("one") with
        {
            Narrowing = new Dictionary<string, string>(StringComparer.Ordinal) { ["RedirectHopLmit"] = "2" },
        };

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([mount], FileStore()));

        StartupRefusal refusal = Assert.Single(result.Refusals);
        Assert.Equal("host/limit-unknown", refusal.Code);
        Assert.Equal("RedirectHopLmit", refusal.Setting);
        Assert.Empty(result.Mounts);
    }

    [Fact]
    public void A_bound_given_a_value_of_the_wrong_shape_is_refused_and_says_what_was_expected()
    {
        MountRequest mount = Mount("one") with
        {
            Narrowing = new Dictionary<string, string>(StringComparer.Ordinal) { ["UpstreamRequestTimeout"] = "30" },
        };

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([mount], FileStore()));

        StartupRefusal refusal = Assert.Single(result.Refusals);
        Assert.Equal("host/limit-malformed", refusal.Code);
        Assert.Contains("00:01:40", refusal.Message, StringComparison.Ordinal);
        Assert.Empty(result.Mounts);
    }

    [Fact]
    public void A_narrowing_bound_takes_effect_and_the_process_starts()
    {
        MountRequest mount = Mount("one", hopLimit: 5) with
        {
            Narrowing = new Dictionary<string, string>(StringComparer.Ordinal) { ["RedirectHopLimit"] = "2" },
        };

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([mount], FileStore()));

        Assert.True(result.Started, Describe(result));
        Assert.Equal(2, Assert.Single(result.Mounts).Policy.EffectiveLimits.RedirectHopLimit);
    }

    [Fact]
    public void A_widening_bound_fails_the_process_and_names_both_values()
    {
        MountRequest mount = Mount("one", hopLimit: 2) with
        {
            Narrowing = new Dictionary<string, string>(StringComparer.Ordinal) { ["RedirectHopLimit"] = "5" },
        };

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([mount], FileStore()));

        StartupRefusal refusal = Assert.Single(result.Refusals);
        Assert.Equal("policy/limit-widened", refusal.Code);
        Assert.Equal("RedirectHopLimit", refusal.Setting);
        Assert.Contains("5", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("2", refusal.Message, StringComparison.Ordinal);
        Assert.NotNull(refusal.Manifest);
        Assert.Empty(result.Mounts);
    }

    [Fact]
    public void Configuration_adding_an_origin_the_manifest_does_not_compile_fails_the_process()
    {
        MountRequest mount = Mount("one") with { AllowedOrigins = ["https://elsewhere.example.com"] };

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([mount], FileStore()));

        Assert.Equal("policy/limit-widened", Assert.Single(result.Refusals).Code);
        Assert.Empty(result.Mounts);
    }

    [Fact]
    public void An_unsealed_manifest_under_require_sealed_fails_the_process()
    {
        RuntimeOptions options = new([Mount("one")], FileStore()) { RequireSealed = true };

        RuntimeStartResult result = EngineRuntime.Start(options);

        Assert.False(result.Started, Describe(result));
        Assert.Empty(result.Mounts);
    }

    [Fact]
    public void An_inline_credential_without_the_switch_fails_the_process()
    {
        MountRequest mount = new("/api", Author("inline", InlineCredentialManifest));

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([mount], FileStore()));

        Assert.False(result.Started, Describe(result));
        Assert.Contains(result.Refusals, refusal => refusal.Code.StartsWith("credential/", StringComparison.Ordinal));
        Assert.Empty(result.Mounts);
    }

    [Fact]
    public void A_file_store_root_that_does_not_exist_fails_the_process()
    {
        RuntimeOptions options = new([Mount("one")], Path.Combine(_root, "absent-store"));

        RuntimeStartResult result = EngineRuntime.Start(options);

        StartupRefusal refusal = Assert.Single(result.Refusals);
        Assert.Equal("host/file-store-unusable", refusal.Code);
        Assert.Equal("FileStoreRoot", refusal.Setting);
        Assert.Empty(result.Mounts);
    }

    /// <summary>
    /// One bad mount takes the process down, and the good ones are not served in the meantime.
    /// </summary>
    [Fact]
    public void One_widened_mount_fails_the_whole_process_and_the_others_are_not_served()
    {
        MountRequest good = Mount("one") with { Prefix = "/one" };
        MountRequest bad = Mount("two", hopLimit: 2) with
        {
            Prefix = "/two",
            Narrowing = new Dictionary<string, string>(StringComparer.Ordinal) { ["RedirectHopLimit"] = "9" },
        };
        MountRequest alsoGood = Mount("three") with { Prefix = "/three" };

        RuntimeStartResult result = EngineRuntime.Start(new RuntimeOptions([good, bad, alsoGood], FileStore()));

        Assert.False(result.Started);
        Assert.Empty(result.Mounts);
    }

    /// <summary>
    /// A floor is a ceiling for every mount and an error for none.
    /// </summary>
    /// <remarks>
    /// The tighter Manifest keeps its own value because a floor states what no mount may
    /// exceed, not what every mount must be. Refusing the tighter one would make a
    /// process-wide setting unusable the moment two Manifests disagree, which is the normal
    /// case.
    /// </remarks>
    [Fact]
    public void A_floor_narrows_the_looser_manifest_leaves_the_tighter_one_and_refuses_neither()
    {
        MountRequest tighter = Mount("tight", hopLimit: 2) with { Prefix = "/tight" };
        MountRequest looser = Mount("loose", hopLimit: 8) with { Prefix = "/loose" };

        RuntimeOptions options = new([tighter, looser], FileStore())
        {
            Floors = new Dictionary<string, string>(StringComparer.Ordinal) { ["RedirectHopLimit"] = "5" },
        };

        RuntimeStartResult result = EngineRuntime.Start(options);

        Assert.True(result.Started, Describe(result));
        Assert.Equal(2, result.Mounts[0].Policy.EffectiveLimits.RedirectHopLimit);
        Assert.Equal(5, result.Mounts[1].Policy.EffectiveLimits.RedirectHopLimit);
    }

    [Fact]
    public void The_supported_manifest_format_range_is_reachable_without_naming_a_manifest_type()
    {
        Assert.False(string.IsNullOrWhiteSpace(EngineRuntime.SupportedManifestFormatRange));
    }

    private string FileStore()
    {
        string path = Path.Combine(_root, "files");
        Directory.CreateDirectory(path);
        return path;
    }

    private MountRequest Mount(string name, int? hopLimit = null) => new("/api", Manifest(name, hopLimit));

    private string Manifest(string name, int? hopLimit = null)
    {
        string limits = hopLimit is { } hops
            ? string.Create(CultureInfo.InvariantCulture, $", \"limits\": {{ \"redirectHopLimit\": {hops} }}")
            : string.Empty;

        return Author(name, $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Example API" } },
                "policy": { "inline": { "baseUrl": "https://api.example.com"{{limits}} } },
                "operations": {
                  "inline": {
                    "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "list-pets",
                        "name": "List pets",
                        "binding": { "type": "http", "operation": "GET /pets" }
                      }
                    ]
                  }
                }
              }
            }
            """);
    }

    private string Author(string name, string document)
    {
        string directory = Path.Combine(_root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), document);
        return directory;
    }

    private const string InlineCredentialManifest = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": { "name": "Example API" } },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "credentials": {
              "inline": {
                "credentials": [
                  { "id": "token", "scheme": "bearer", "slot": "Authorization", "value": { "inline": "s3cret" } }
                ]
              }
            },
            "operations": {
              "inline": {
                "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "list-pets",
                    "name": "List pets",
                    "binding": { "type": "http", "operation": "GET /pets", "credentialRef": ["token"] }
                  }
                ]
              }
            }
          }
        }
        """;

    private static string Describe(RuntimeStartResult result)
        => string.Join("; ", result.Refusals.Select(refusal => $"{refusal.Code}: {refusal.Message}"));
}
