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
/// </remarks>
internal static class ManifestCorpus
{
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
        [.. Directories().Where(IsBundle)];

    /// <summary>
    /// Every directory that is not a bundle: hostile cases and shared byte fixtures.
    /// </summary>
    public static IReadOnlyList<string> SupportingNames() =>
        [.. Directories().Where(name => !IsBundle(name))];

    /// <summary>Whether <paramref name="name"/> names a directory holding a manifest root.</summary>
    public static bool IsBundle(string name) =>
        File.Exists(Path.Combine(Root, name, DirectoryManifestSource.RootFileName));

    private static IReadOnlyList<string> Directories() =>
        [.. Directory
            .GetDirectories(Root)
            .Select(Path.GetFileName)
            .Select(name => name!)
            .Order(StringComparer.Ordinal)];
}
