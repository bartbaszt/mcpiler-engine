namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Operator-controlled loading behavior.
/// </summary>
/// <remarks>
/// Nothing here can change what a manifest means. These options only decide how strict
/// loading is and how much work a hostile bundle may cause before it is refused.
/// </remarks>
public sealed record ManifestLoadOptions
{
    /// <summary>
    /// Default per-section payload limit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The format itself does not bound a section's size, but a loader must, because it is
    /// the first component that touches untrusted bytes. Without a bound, a 40-byte section
    /// index pointing at a multi-gigabyte payload is a memory-exhaustion primitive that costs
    /// the attacker nothing.
    /// </para>
    /// <para>
    /// The default is generous relative to observed data: a large real intermediate document
    /// measured tens of megabytes even before local references collapsed it, so 64 MiB
    /// refuses only absurd inputs. Operators serving very large catalogues raise it
    /// deliberately.
    /// </para>
    /// </remarks>
    public const long DefaultMaxSectionBytes = 64L * 1024 * 1024;

    /// <summary>Default root document limit.</summary>
    /// <remarks>
    /// The root is an index plus optionally inline sections. A hand-authored single-file
    /// manifest is tens of lines; an all-inline export of a large catalogue is still far
    /// under this.
    /// </remarks>
    public const long DefaultMaxRootBytes = 96L * 1024 * 1024;

    /// <summary>The loading behavior applied when an operator sets nothing.</summary>
    public static ManifestLoadOptions Default { get; } = new();

    /// <summary>
    /// Refuse a manifest that carries no completeness seal.
    /// </summary>
    /// <remarks>
    /// Opt-in hardening. It is off by default because a hand-authored manifest is a
    /// first-class input and requiring a seal would make the format unusable without tooling.
    /// A production deployment that only ever consumes Studio exports should turn it on.
    /// </remarks>
    public bool RequireSealed { get; init; }

    /// <summary>
    /// Permit a literal secret in the credentials section.
    /// </summary>
    /// <remarks>
    /// Off by default. An inline secret in a file that also describes routing and policy is
    /// the easiest way to leak a credential into version control, so it takes an explicit
    /// operator decision.
    /// </remarks>
    public bool AllowInlineSecrets { get; init; }

    /// <summary>
    /// Permit <c>fromProvider</c> credential references, which are resolvable only from a
    /// managed generation's in-memory secret set.
    /// </summary>
    /// <remarks>
    /// Off by default because file mode has no provider secret set: a <c>fromProvider</c>
    /// reference there would be a mount set that can never execute, so it is refused at load.
    /// Managed mode turns this on because its generation envelope is the only place the
    /// corresponding values can come from.
    /// </remarks>
    public bool AllowProviderReferences { get; init; }

    /// <summary>Maximum accepted root document size in bytes.</summary>
    public long MaxRootBytes { get; init; } = DefaultMaxRootBytes;

    /// <summary>Maximum accepted per-section payload size in bytes.</summary>
    public long MaxSectionBytes { get; init; } = DefaultMaxSectionBytes;
}
