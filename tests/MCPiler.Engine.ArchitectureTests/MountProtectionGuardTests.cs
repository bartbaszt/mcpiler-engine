using System.Text.RegularExpressions;

using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Guards the rule that exactly one member decides whether a mount is a protected resource.
/// </summary>
/// <remarks>
/// <para>
/// Protection was once inferred from a non-empty <c>requiredScopes</c> list, so a mount that
/// required a token while declaring no specific scope could not say so — and every Platform
/// export, which deliberately states no scope, was served without a token. The audience
/// binding, the per-request activity check and the <c>401</c> challenge were all vacuous for
/// it. The defect was not the inference itself; it was that a member whose defined meaning is
/// an <i>additional</i> restriction was read as the on/off switch for protection.
/// </para>
/// <para>
/// The declaration member is now <c>server.authenticationRequired</c>, read once at load into
/// <c>MountedManifest.RequiresAuthorization</c>. A scope may restrict a token; it may never
/// decide whether one is required. This guard is deliberately textual and slightly blunt, for
/// the reason the binding-seam guard states: a type-level check cannot see the difference
/// between enforcing a scope and deciding protection from one, and a reviewer noticing the
/// second reading is exactly what failed last time.
/// </para>
/// </remarks>
public sealed class MountProtectionGuardTests
{
    /// <summary>
    /// Files permitted to read <c>RequiredScopes</c> as a count or a list.
    /// </summary>
    /// <remarks>
    /// Each entry enforces or reports scopes; none of them decides whether a token is required.
    /// An exemption that starts doing so is the defect.
    /// </remarks>
    private static readonly string[] PermittedFiles =
    [
        // Enforces the scopes a token carries once protection is already established.
        "src/MCPiler.Engine.Host/Authorization/MountAuthorizationMiddleware.cs",

        // Carries the scopes into the tool listing's protocol-neutral surface value.
        "src/MCPiler.Engine/Mcp/SurfaceCatalogue.cs",

        // Reports the scopes in the startup report, after the protection state is stated.
        "src/MCPiler.Engine.Host/Cli/HostCommands.cs",

        // The model and the reader, which hold and populate the member.
        "src/MCPiler.Engine/Manifest/Model/ServerSection.cs",
        "src/MCPiler.Engine/Manifest/Loading/ServerSectionReader.cs",
        "src/MCPiler.Engine/Runtime/StartupRefusal.cs",
    ];

    /// <summary>
    /// The reading this guard forbids: a presence test over <c>RequiredScopes</c>.
    /// </summary>
    /// <remarks>
    /// A <c>.Count</c> comparison or a <c>Any()</c> over the scope list is the shape the defect
    /// took. Enumerating the list to enforce it is not matched, because that is what a scope is
    /// for.
    /// </remarks>
    private static readonly Regex PresenceTest = new(
        @"RequiredScopes\s*\.\s*(Count\s*(>|>=|!=|==)\s*0\b|Any\s*\()",
        RegexOptions.Multiline | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(5));

    [Fact]
    public void Protection_is_never_inferred_from_a_scope_list()
    {
        var offenders = new List<string>();

        foreach (var file in EngineRepository.ProductionSources())
        {
            var relative = EngineRepository.Relative(file);

            if (PermittedFiles.Contains(relative, StringComparer.Ordinal))
            {
                continue;
            }

            foreach (Match match in PresenceTest.Matches(File.ReadAllText(file)))
            {
                offenders.Add($"{relative}: {match.Value.Trim()}");
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Whether a mount requires a token is decided by server.authenticationRequired, read "
                + "into MountedManifest.RequiresAuthorization. A non-empty scope list is an "
                + "additional restriction, never the switch. Offending sites: "
                + string.Join("; ", offenders));
    }

    /// <summary>
    /// The declaration the guard protects must exist, or it would silently pass for the absence.
    /// </summary>
    [Fact]
    public void The_protection_member_is_where_the_guard_expects_it()
    {
        var model = File.ReadAllText(
            EngineRepository.Absolute("src/MCPiler.Engine/Manifest/Model/ServerSection.cs"));

        Assert.Contains("AuthenticationRequired", model, StringComparison.Ordinal);

        var mounted = File.ReadAllText(
            EngineRepository.Absolute("src/MCPiler.Engine/Runtime/StartupRefusal.cs"));

        Assert.Contains("RequiresAuthorization", mounted, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every exemption must name a file that exists, so a rename cannot silently widen the set.
    /// </summary>
    [Fact]
    public void Every_permitted_file_exists()
    {
        var missing = PermittedFiles
            .Where(entry => !EngineRepository.Exists(entry))
            .ToList();

        Assert.True(missing.Count == 0, $"Stale mount-protection exemption: {string.Join(", ", missing)}");
    }

    /// <summary>
    /// The guard must actually reach the file that once carried the inference.
    /// </summary>
    /// <remarks>
    /// A guard that scanned an empty set, or a set that had drifted off the seam, would report
    /// green for exactly the change it exists to prevent.
    /// </remarks>
    [Fact]
    public void The_guard_reaches_the_authorization_seam()
    {
        var reached = EngineRepository.ProductionSources()
            .Select(EngineRepository.Relative)
            .ToList();

        Assert.Contains("src/MCPiler.Engine/Runtime/Authorization/MountAuthorization.cs", reached);
        Assert.Contains("src/MCPiler.Engine/Runtime/StartupRefusal.cs", reached);
        Assert.Contains("src/MCPiler.Engine.Host/Authorization/MountAuthorizationMiddleware.cs", reached);
    }
}
