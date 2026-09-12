using System.Diagnostics.CodeAnalysis;

using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Configuration;

/// <summary>
/// The complete set of settings this deployable accepts, and the refusal of everything else.
/// </summary>
/// <remarks>
/// <para>
/// The list is short on purpose. A base URL, an allowed origin, a credential and any bound
/// a Manifest compiles are absent, because those belong to the reviewed artifact rather than
/// to whatever the process was started with. A deployment changes them by changing the
/// Manifest.
/// </para>
/// <para>
/// An unrecognized key is refused by name. Ignoring it is worse than rejecting it: the
/// operator believes the setting applied, the process behaves as if it were never written,
/// and the disagreement surfaces as behaviour rather than as a message at startup.
/// </para>
/// <para>
/// Bound names are not restated here. They come from the library, which already enumerates
/// every bound local configuration may narrow and already has a reflection guard proving the
/// enumeration is complete. Restating them would be a second list to keep in step.
/// </para>
/// </remarks>
/// <summary>Everything one command line resolved to, split by who reads it.</summary>
/// <remarks>
/// Two records rather than one, because the split is the point. <see cref="Runtime"/> is what
/// the library is told and is the whole of what can change behaviour; <see cref="Listener"/>
/// is how this process is reached and can change nothing a client is served.
/// </remarks>
/// <param name="Runtime">What the library is told.</param>
/// <param name="Listener">How the listener is told to reach this process.</param>
/// <param name="Authorization">The trusted issuer and how its tokens are validated, or none.</param>
public sealed record HostBinding(
    RuntimeOptions Runtime,
    HostListenOptions Listener,
    HostAuthorizationOptions? Authorization);

/// <summary>
/// The authorization configuration this deployable accepts, or the absence of one.
/// </summary>
/// <remarks>
/// <para>
/// An issuer without a validation mode is refused, and so is a validation mode without an
/// issuer: the two halves of "validate against the trusted issuer" are one decision, and
/// accepting half of it would tell an operator the boundary is configured when only the
/// other half is.
/// </para>
/// <para>
/// Nothing here authorizes a request on its own. The configuration names what to trust; the
/// per-request decisions — audience binding, scopes — are made against the addressed surface,
/// which is manifest state.
/// </para>
/// </remarks>
/// <param name="Issuer">The absolute URI of the authorization server this process trusts.</param>
/// <param name="Validation">How a presented token is validated against the issuer.</param>
/// <param name="IntrospectionEndpoint">Overrides RFC 8414 discovery of the RFC 7662 endpoint.</param>
/// <param name="JwksUri">Overrides the issuer metadata's <c>jwks_uri</c>.</param>
public sealed record HostAuthorizationOptions(
    string Issuer,
    HostTokenValidation Validation,
    string? IntrospectionEndpoint = null,
    string? JwksUri = null)
{
    /// <summary>
    /// The configuration for a process that trusts no issuer, which serves mounts that declare
    /// no surface scope and refuses mounts that do.
    /// </summary>
    public static HostAuthorizationOptions None { get; } =
        new(string.Empty, (HostTokenValidation)(-1));
}

/// <summary>How a presented token is validated against the trusted issuer.</summary>
public enum HostTokenValidation
{
    /// <summary>Remote RFC 7662 introspection; the response's <c>active</c> flag decides.</summary>
    Introspection = 0,

    /// <summary>Local signature and lifetime validation against the issuer's published keys.</summary>
    Jwks = 1,
}

public static class HostConfiguration
{
    /// <summary>Prefix for a bound narrowed on one mount: <c>mount:{prefix}:{Bound}</c>.</summary>
    public const string MountNarrowingPrefix = "mount:";

    /// <summary>Prefix for a bound narrowed across every mount: <c>floor:{Bound}</c>.</summary>
    public const string FloorPrefix = "floor:";

    /// <summary>Key naming the directory issued file handles keep their content in.</summary>
    public const string FileStoreRootKey = "file-store-root";

    /// <summary>Key naming the address a remote listener binds.</summary>
    public const string ListenKey = "listen";

    /// <summary>Key naming the transport, <c>http</c> or <c>stdio</c>.</summary>
    public const string TransportKey = "transport";

    /// <summary>Key refusing any Manifest that carries no completeness seal.</summary>
    public const string RequireSealedKey = "require-sealed";

    /// <summary>Key permitting a literal secret inside a Manifest.</summary>
    public const string AllowInlineSecretsKey = "allow-inline-secrets";

    /// <summary>Key naming a directory this process serves, which the file store must sit outside.</summary>
    public const string ServedContentRootKey = "served-content-root";

    /// <summary>Key naming the authorization server issuer this process trusts.</summary>
    /// <remarks>
    /// An absolute http or https URI. Required exactly when a mounted Manifest declares a surface
    /// scope; the pairing with <see cref="TokenValidationKey"/> is both-or-neither.
    /// </remarks>
    public const string IssuerKey = "issuer";

    /// <summary>Key selecting how a presented token is validated against the trusted issuer.</summary>
    /// <remarks>
    /// <c>introspection</c> (RFC 7662, endpoint discovered from RFC 8414 metadata unless
    /// <see cref="IntrospectionEndpointKey"/> overrides it) or <c>jwks</c> (local signature
    /// validation against the issuer's published keys unless <see cref="JwksUriKey"/> overrides
    /// it). Required when <see cref="IssuerKey"/> is set; both values narrow to the same
    /// byte-exact audience binding.
    /// </remarks>
    public const string TokenValidationKey = "token-validation";

    /// <summary>Key naming the RFC 7662 introspection endpoint, overriding RFC 8414 discovery.</summary>
    public const string IntrospectionEndpointKey = "introspection-endpoint";

    /// <summary>Key naming the issuer's JWKS URI, overriding the <c>jwks_uri</c> in its published metadata.</summary>
    public const string JwksUriKey = "jwks-uri";

    private static readonly string[] Simple =
    [
        FileStoreRootKey,
        ListenKey,
        TransportKey,
        RequireSealedKey,
        AllowInlineSecretsKey,
        ServedContentRootKey,
        IssuerKey,
        TokenValidationKey,
        IntrospectionEndpointKey,
        JwksUriKey,
    ];

    /// <summary>Every key this deployable accepts, excluding the two prefixed families.</summary>
    public static IReadOnlyList<string> AcceptedKeys => Simple;

    /// <summary>
    /// Binds settings and mounts into runtime options, or reports why it cannot.
    /// </summary>
    /// <param name="mounts">Prefix to Manifest path, in the order they were given.</param>
    /// <param name="settings">Everything else the operator set, in the order given.</param>
    /// <param name="binding">The bound configuration when this returns true.</param>
    /// <param name="refusals">One message per rejected setting when this returns false.</param>
    public static bool TryBind(
        IReadOnlyList<KeyValuePair<string, string>> mounts,
        IReadOnlyList<KeyValuePair<string, string>> settings,
        [NotNullWhen(true)] out HostBinding? binding,
        out IReadOnlyList<string> refusals)
    {
        ArgumentNullException.ThrowIfNull(mounts);
        ArgumentNullException.ThrowIfNull(settings);

        List<string> rejected = [];
        Dictionary<string, Dictionary<string, string>> narrowing = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string> floors = new(StringComparer.Ordinal);
        List<string> served = [];

        string? fileStoreRoot = null;
        string listen = HostListenOptions.DefaultListen;
        HostTransport transport = HostTransport.Http;
        bool requireSealed = false;
        bool allowInlineSecrets = false;
        string? issuer = null;
        HostTokenValidation? validation = null;
        string? introspectionEndpoint = null;
        string? jwksUri = null;

        foreach ((string key, string value) in settings)
        {
            if (key.StartsWith(MountNarrowingPrefix, StringComparison.Ordinal))
            {
                BindMountNarrowing(key, value, narrowing, rejected);
                continue;
            }

            if (key.StartsWith(FloorPrefix, StringComparison.Ordinal))
            {
                floors[key[FloorPrefix.Length..]] = value;
                continue;
            }

            switch (key)
            {
                case FileStoreRootKey:
                    fileStoreRoot = value;
                    break;
                case ServedContentRootKey:
                    served.Add(value);
                    break;
                case RequireSealedKey:
                    requireSealed = Flag(key, value, rejected);
                    break;
                case AllowInlineSecretsKey:
                    allowInlineSecrets = Flag(key, value, rejected);
                    break;
                case ListenKey:
                    listen = Address(key, value, rejected);
                    break;
                case TransportKey:
                    transport = Transport(key, value, rejected);
                    break;
                case IssuerKey:
                    issuer = UriSetting(key, value, rejected);
                    break;
                case TokenValidationKey:
                    validation = Validation(key, value, rejected);
                    break;
                case IntrospectionEndpointKey:
                    introspectionEndpoint = UriSetting(key, value, rejected);
                    break;
                case JwksUriKey:
                    jwksUri = UriSetting(key, value, rejected);
                    break;
                default:
                    rejected.Add($"'{key}' is not a setting this host accepts. It accepts {string.Join(", ", Simple)}, '{MountNarrowingPrefix}{{prefix}}:{{bound}}' and '{FloorPrefix}{{bound}}'.");
                    break;
            }
        }

        if (fileStoreRoot is null)
        {
            rejected.Add($"'{FileStoreRootKey}' is required. Issued file handles need somewhere to keep their content.");
        }

        HostAuthorizationOptions? authorization = BindAuthorization(
            issuer, validation, introspectionEndpoint, jwksUri, rejected);

        if (rejected.Count > 0)
        {
            binding = null;
            refusals = rejected;
            return false;
        }

        RuntimeOptions options = new(
            [.. mounts.Select(mount => new MountRequest(mount.Key, mount.Value)
            {
                Narrowing = narrowing.TryGetValue(mount.Key, out Dictionary<string, string>? own)
                    ? own
                    : new Dictionary<string, string>(StringComparer.Ordinal),
            })],
            fileStoreRoot!)
        {
            RequireSealed = requireSealed,
            AllowInlineSecrets = allowInlineSecrets,
            Floors = floors,
            ServedContentRoots = served,
        };

        binding = new HostBinding(options, new HostListenOptions(listen, transport), authorization);
        refusals = [];
        return true;
    }

    /// <summary>
    /// Binds the issuer and validation-mode pair, refusing the halves separately.
    /// </summary>
    /// <remarks>
    /// The pairing is both-or-neither, and so is each override: an introspection endpoint with
    /// JWKS validation names an address nothing would read, and a JWKS URI with introspection
    /// validation names keys nothing would fetch. A half-configured boundary is worse than an
    /// absent one, because the startup refusal for a scope-declaring mount will name a
    /// configured issuer that still validates nothing.
    /// </remarks>
    private static HostAuthorizationOptions? BindAuthorization(
        string? issuer,
        HostTokenValidation? validation,
        string? introspectionEndpoint,
        string? jwksUri,
        List<string> rejected)
    {
        if (issuer is null && validation is null)
        {
            if (introspectionEndpoint is not null || jwksUri is not null)
            {
                rejected.Add($"'{IssuerKey}' is required with '{TokenValidationKey}'. An endpoint or a key set with no issuer to trust validates nothing.");
            }

            return null;
        }

        if (issuer is null)
        {
            rejected.Add($"'{TokenValidationKey}' was given without '{IssuerKey}'. Name the issuer whose tokens the mode validates.");
            return null;
        }

        if (validation is not { } mode)
        {
            rejected.Add($"'{IssuerKey}' was given without '{TokenValidationKey}'. Choose 'introspection' or 'jwks'.");
            return null;
        }

        if (mode is HostTokenValidation.Introspection && jwksUri is not null)
        {
            rejected.Add($"'{JwksUriKey}' names keys nothing reads: '{TokenValidationKey}' is 'introspection'. Remove it, or select 'jwks'.");
        }

        if (mode is HostTokenValidation.Jwks && introspectionEndpoint is not null)
        {
            rejected.Add($"'{IntrospectionEndpointKey}' names an endpoint nothing calls: '{TokenValidationKey}' is 'jwks'. Remove it, or select 'introspection'.");
        }

        return new HostAuthorizationOptions(issuer, mode, introspectionEndpoint, jwksUri);
    }

    /// <summary>
    /// Reads an absolute http or https URI, the shape every address an authorization boundary
    /// fetches or compares has to have.
    /// </summary>
    private static string? UriSetting(string key, string value, List<string> rejected)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out Uri? address)
            && (string.Equals(address.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                || string.Equals(address.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            return value;
        }

        rejected.Add($"'{key}' was given '{value}', which is not an absolute http or https address.");
        return null;
    }

    private static HostTokenValidation? Validation(string key, string value, List<string> rejected)
    {
        if (string.Equals(value, "introspection", StringComparison.Ordinal))
        {
            return HostTokenValidation.Introspection;
        }

        if (string.Equals(value, "jwks", StringComparison.Ordinal))
        {
            return HostTokenValidation.Jwks;
        }

        rejected.Add($"'{key}' was given '{value}'. Choose 'introspection' or 'jwks'.");
        return null;
    }

    /// <summary>
    /// Reads a listen address, refusing anything a listener could not bind.
    /// </summary>
    /// <remarks>
    /// Validated here rather than left to the listener because a malformed address discovered
    /// at bind time is reported as a crash, and a crash and a refusal are the two outcomes an
    /// operator most needs to tell apart.
    /// </remarks>
    private static string Address(string key, string value, List<string> rejected)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out Uri? address)
            && (string.Equals(address.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                || string.Equals(address.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            return value;
        }

        rejected.Add($"'{key}' was given '{value}', which is not an absolute http or https address such as '{HostListenOptions.DefaultListen}'.");
        return HostListenOptions.DefaultListen;
    }

    private static HostTransport Transport(string key, string value, List<string> rejected)
    {
        if (string.Equals(value, HostListenOptions.HttpTransportName, StringComparison.Ordinal))
        {
            return HostTransport.Http;
        }

        rejected.Add($"'{key}' was given '{value}'. This build serves {string.Join(", ", HostListenOptions.AcceptedTransports)}.");
        return HostTransport.Http;
    }

    private static void BindMountNarrowing(
        string key,
        string value,
        Dictionary<string, Dictionary<string, string>> narrowing,
        List<string> rejected)
    {
        string remainder = key[MountNarrowingPrefix.Length..];
        int separator = remainder.LastIndexOf(':');

        if (separator <= 0 || separator == remainder.Length - 1)
        {
            rejected.Add($"'{key}' does not name a mount and a bound. The shape is '{MountNarrowingPrefix}{{prefix}}:{{bound}}'.");
            return;
        }

        string prefix = remainder[..separator];
        string bound = remainder[(separator + 1)..];

        if (!narrowing.TryGetValue(prefix, out Dictionary<string, string>? own))
        {
            own = new Dictionary<string, string>(StringComparer.Ordinal);
            narrowing[prefix] = own;
        }

        own[bound] = value;
    }

    private static bool Flag(string key, string value, List<string> rejected)
    {
        if (bool.TryParse(value, out bool parsed))
        {
            return parsed;
        }

        rejected.Add($"'{key}' was given '{value}', which is not true or false.");
        return false;
    }
}
