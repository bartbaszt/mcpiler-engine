namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The <c>credentials</c> section: credential slot declarations holding value
/// <em>references</em>.
/// </summary>
/// <remarks>
/// Nothing in this model can hold a secret that came from Studio. A Studio export emits
/// metadata plus a reference; exporting a resolvable secret value would require an explicit,
/// audited opt-in that this format version does not define.
/// </remarks>
/// <param name="Credentials">The declared credential slots.</param>
public sealed record CredentialsSection(IReadOnlyList<ManifestCredential> Credentials = null!)
{
    /// <summary>The section format version this model represents.</summary>
    public const int FormatVersion = 1;

    /// <summary>The declared credentials, never null.</summary>
    public IReadOnlyList<ManifestCredential> Credentials { get; init; } = Credentials ?? [];

    /// <summary>An empty section, which is the default when none is declared.</summary>
    public static CredentialsSection Empty { get; } = new();
}

/// <summary>One credential slot.</summary>
/// <param name="Scheme">How the value is applied to the request.</param>
/// <param name="Slot">
/// The slot name. For <see cref="CredentialScheme.Basic"/> this is
/// <see cref="BasicUsernameSlot"/> or <see cref="BasicPasswordSlot"/>; for
/// <see cref="CredentialScheme.Bearer"/> it is the header name, normally
/// <see cref="AuthorizationHeader"/>; for <see cref="CredentialScheme.ApiKey"/> and
/// <see cref="CredentialScheme.Header"/> it is the header, query, or cookie name.
/// </param>
/// <param name="Value">Where the secret is read from at resolution time.</param>
/// <param name="Location">
/// Where an API key is placed. Meaningful only for <see cref="CredentialScheme.ApiKey"/>.
/// </param>
public sealed record ManifestCredential(
    CredentialScheme Scheme,
    string Slot,
    CredentialReference Value,
    CredentialLocation? Location = null)
{
    /// <summary>The basic-scheme user name slot.</summary>
    public const string BasicUsernameSlot = "username";

    /// <summary>The basic-scheme password slot.</summary>
    public const string BasicPasswordSlot = "password";

    /// <summary>The conventional bearer header name.</summary>
    public const string AuthorizationHeader = "Authorization";

    /// <summary>The cookie header name.</summary>
    public const string CookieHeader = "Cookie";

    /// <summary>The effective API key placement.</summary>
    public CredentialLocation EffectiveLocation => Location ?? CredentialLocation.Header;

    /// <summary>
    /// True when this credential contributes a request header whose value must be treated as
    /// sensitive across a redirect.
    /// </summary>
    /// <remarks>
    /// Redirect sensitivity is derived, never authored, mirroring the existing outbound HTTP
    /// factory behavior.
    /// </remarks>
    public bool IsRedirectSensitiveHeader => Scheme switch
    {
        CredentialScheme.Basic or CredentialScheme.Bearer => true,
        CredentialScheme.Header => true,
        CredentialScheme.ApiKey => EffectiveLocation is CredentialLocation.Header or CredentialLocation.Cookie,
        _ => false,
    };
}

/// <summary>
/// Where a credential's secret is read from. Exactly one variant is populated.
/// </summary>
/// <remarks>
/// A missing or unreadable reference is a distinct auth fault, never a network error, so an
/// operator can tell a misconfigured secret from an unreachable upstream.
/// </remarks>
public sealed record CredentialReference
{
    private CredentialReference()
    {
    }

    /// <summary>The environment variable name to read, when this is an env reference.</summary>
    public string? FromEnv { get; private init; }

    /// <summary>
    /// The absolute file path to read, when this is a file reference. A single trailing
    /// newline is trimmed so a file written by <c>echo</c> works as expected.
    /// </summary>
    public string? FromFile { get; private init; }

    /// <summary>
    /// A literal secret. Refused unless Engine is started with an explicit opt-in, and always
    /// reported as a warning by <c>validate</c>.
    /// </summary>
    public string? Inline { get; private init; }

    /// <summary>True when the value is a literal rather than a reference.</summary>
    public bool IsInline => Inline is not null;

    /// <summary>Creates an environment variable reference.</summary>
    public static CredentialReference Env(string variableName)
        => new() { FromEnv = Require(variableName, nameof(variableName)) };

    /// <summary>Creates a file reference.</summary>
    public static CredentialReference File(string path)
        => new() { FromFile = Require(path, nameof(path)) };

    /// <summary>Creates a literal value.</summary>
    public static CredentialReference Literal(string value)
        => new() { Inline = Require(value, nameof(value)) };

    /// <summary>
    /// Describes the reference without disclosing a secret, for diagnostics.
    /// </summary>
    /// <remarks>
    /// The inline case deliberately reports only its shape. Echoing a literal secret into a
    /// diagnostic is the failure mode this method exists to prevent.
    /// </remarks>
    public override string ToString() => this switch
    {
        { FromEnv: { } name } => $"fromEnv:{name}",
        { FromFile: { } path } => $"fromFile:{path}",
        { Inline: not null } => "inline:(redacted)",
        _ => "(unset)",
    };

    private static string Require(string value, string parameterName)
        => string.IsNullOrEmpty(value)
            ? throw new ArgumentException("A credential reference must be non-empty.", parameterName)
            : value;
}
