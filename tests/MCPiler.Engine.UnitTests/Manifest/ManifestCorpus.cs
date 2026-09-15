using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using MCPiler.Engine.Manifest.Loading;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// The hand-authored fixture corpus, classified once for every suite that drives it.
/// </summary>
/// <remarks>
/// <para>
/// Several suites enumerate the same corpus. When each kept its own copy of "which directories
/// are bundles", adding one directory required the same decision in every copy, and a missed
/// copy showed up as an unrelated-looking failure in a distant suite. The classification lives
/// here so it is stated once.
/// </para>
/// <para>
/// A directory is a bundle when it holds a manifest root. Classifying positively rather than
/// excluding known names means a bundle whose root went missing appears as unaccounted support
/// material instead of quietly dropping out of the valid-fixture theories.
/// </para>
/// <para>
/// The format-0.3 authentication corpus lives one level down, under <c>manifest-0.3/</c>, so
/// each strategy keeps its own mount set and the directory name records the format version it
/// was authored against. Nested bundles are named by their corpus-relative path.
/// </para>
/// </remarks>
internal static class ManifestCorpus
{
    /// <summary>The subtree that carries the format-0.3 authentication corpus.</summary>
    public const string AuthenticationCorpusName = "manifest-0.3";

    /// <summary>
    /// The one bundle whose credentials use managed <c>fromProvider</c> references. It loads
    /// only under <see cref="ManifestLoadOptions.AllowProviderReferences"/>, and it is named
    /// here so the option choice is a stated classification rather than a path convention
    /// buried in a theory.
    /// </summary>
    public const string ManagedProviderFixture = AuthenticationCorpusName + "/managed-provider";

    /// <summary>The corpus root.</summary>
    public static string Root => TestRepository.Fixture("manifests");

    /// <summary>The hostile-case subtree.</summary>
    public static string HostileRoot => Path.Combine(Root, "hostile");

    /// <summary>The hostile bundles, one directory per case.</summary>
    public static string HostileBundleRoot => Path.Combine(HostileRoot, "bundle");

    /// <summary>The hostile document cases, all in one file.</summary>
    public static string DocumentCasesFile => Path.Combine(HostileRoot, "document-cases.json");

    /// <summary>Every directory that is a loadable bundle, ordinally ordered.</summary>
    public static IReadOnlyList<string> BundleNames() =>
        [.. RootDirectories().Where(IsBundle), .. NestedBundleNames()];

    /// <summary>The nested authentication bundles, by corpus-relative name.</summary>
    public static IReadOnlyList<string> NestedBundleNames() =>
        [.. Directory
            .GetDirectories(Path.Combine(Root, AuthenticationCorpusName))
            .Where(directory => File.Exists(Path.Combine(directory, DirectoryManifestSource.RootFileName)))
            .Select(directory => AuthenticationCorpusName + "/" + Path.GetFileName(directory))
            .Order(StringComparer.Ordinal)];

    /// <summary>
    /// The load options a bundle requires. Exactly one corpus bundle opts into managed provider
    /// references; every other bundle loads under the defaults, which is itself asserted.
    /// </summary>
    public static ManifestLoadOptions OptionsFor(string fixture) =>
        string.Equals(fixture, ManagedProviderFixture, StringComparison.Ordinal)
            ? ManifestLoadOptions.Default with { AllowProviderReferences = true }
            : ManifestLoadOptions.Default;

    /// <summary>
    /// Every directory that is not a bundle: hostile cases, shared byte fixtures, and the
    /// nested authentication container, whose bundles are reported by
    /// <see cref="NestedBundleNames"/>.
    /// </summary>
    public static IReadOnlyList<string> SupportingNames() =>
        [.. RootDirectories().Where(name =>
            !IsBundle(name) && !IsNestedContainer(name))];

    /// <summary>Whether <paramref name="name"/> names a directory holding a manifest root.</summary>
    public static bool IsBundle(string name) =>
        File.Exists(Path.Combine(Root, name, DirectoryManifestSource.RootFileName));

    private static bool IsNestedContainer(string name) =>
        string.Equals(name, AuthenticationCorpusName, StringComparison.Ordinal);

    private static IReadOnlyList<string> RootDirectories() =>
        [.. Directory
            .GetDirectories(Root)
            .Select(Path.GetFileName)
            .Select(name => name!)
            .Order(StringComparer.Ordinal)];
}
