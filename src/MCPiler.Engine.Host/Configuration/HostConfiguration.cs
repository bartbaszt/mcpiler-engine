using System.Diagnostics.CodeAnalysis;
using System.Globalization;

using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Managed;
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
    HostAuthorizationOptions? Authorization,
    HostLifecycleOptions Lifecycle)
{
    /// <summary>Creates a binding with the product's lifecycle defaults.</summary>
    public HostBinding(
        RuntimeOptions runtime,
        HostListenOptions listener,
        HostAuthorizationOptions? authorization)
        : this(runtime, listener, authorization, HostLifecycleOptions.Default)
    {
    }

    /// <summary>
    /// Which authority decides what this process serves.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="HostDeploymentMode.File"/> so every caller that predates managed mode
    /// keeps its meaning: a process with local mounts is a file-mode process.
    /// </remarks>
    public HostDeploymentMode Mode { get; init; } = HostDeploymentMode.File;

    /// <summary>
    /// The managed synchronization settings, exactly when <see cref="Mode"/> is
    /// <see cref="HostDeploymentMode.Managed"/>.
    /// </summary>
    /// <remarks>
    /// One record rather than three loose settings because the three are one decision: an
    /// endpoint with no deployment identity would poll nothing in particular, and a deployment
    /// identity with no secret file would authenticate as nobody. Binding them together means a
    /// managed process cannot be half-configured by construction.
    /// </remarks>
    public ManagedSyncOptions? Managed { get; init; }

    /// <summary>
    /// The addresses of reverse proxies whose forwarded headers this process trusts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Empty means forwarded headers are ignored entirely, which is correct for a directly
    /// reached process and for one whose proxy rewrites the address rather than forwarding it.
    /// A non-empty list is what makes <c>X-Forwarded-Proto</c> and <c>X-Forwarded-For</c>
    /// effective, and only for the listed addresses: a client that could set the scheme itself
    /// could make the process believe it was reached over https and publish metadata naming a
    /// scheme and authority no client actually used.
    /// </para>
    /// <para>
    /// This is a listener fact, not a Manifest fact, so it lives beside the listen address
    /// rather than in <see cref="RuntimeOptions"/>: it changes how a request is observed and
    /// can change nothing a Manifest declares.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> TrustedProxies { get; init; } = [];

    /// <summary>
    /// The browser origins whose requests this process accepts on an MCP address.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Spec 11 requires the MCP endpoint to validate the <c>Origin</c> header when it is present
    /// and reject an unexpected origin. The endpoint is served here, so the decision lives here.
    /// Empty accepts no browser origin: the header is only sent by a browser, so a request that
    /// carries one is a browser request that no configured origin authorizes, and a non-browser
    /// client that sends no header is served normally.
    /// </para>
    /// <para>
    /// Like the listen address this is a deployment fact, not a Manifest fact: it says who may
    /// call the process, not what the process serves.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> AllowedOrigins { get; init; } = [];
}

/// <summary>How a process decides which Manifests it serves.</summary>
/// <remarks>
/// The two modes are exclusive because each names a single authority for the served mount set.
/// Accepting both would create a third, unwritten rule for which one wins, and the rule would
/// decide what a client is served.
/// </remarks>
public enum HostDeploymentMode
{
    /// <summary>Local Manifest files/bundles supplied to the deployment are authoritative.</summary>
    File = 0,

    /// <summary>One configured Platform deployment is authoritative; local mounts are refused.</summary>
    Managed = 1,
}

/// <summary>Host-only lifecycle settings that do not alter Manifest behavior.</summary>
/// <param name="DrainTimeout">How long shutdown lets admitted tool invocations finish.</param>
public sealed record HostLifecycleOptions(TimeSpan DrainTimeout)
{
    /// <summary>The default drain window, matching the default whole-exchange budget.</summary>
    public static readonly TimeSpan DefaultDrainTimeout = TimeSpan.FromSeconds(100);

    /// <summary>The lifecycle settings used when the operator supplies none.</summary>
    public static HostLifecycleOptions Default { get; } = new(DefaultDrainTimeout);
}

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
/// <param name="IntrospectionClientId">
/// The client identity this resource server authenticates with at the introspection endpoint.
/// </param>
/// <param name="IntrospectionClientSecretFile">
/// The file holding that client's secret. A path rather than a value, for the reason
/// <see cref="HostConfiguration.DeploymentSecretFileKey"/> states: a secret on a command line is
/// visible to every process listing on the host.
/// </param>
public sealed record HostAuthorizationOptions(
    string Issuer,
    HostTokenValidation Validation,
    string? IntrospectionEndpoint = null,
    string? JwksUri = null,
    string? IntrospectionClientId = null,
    string? IntrospectionClientSecretFile = null)
{
    /// <summary>
    /// The maximum positive introspection result age in seconds. Zero disables both result caches.
    /// The value is meaningful only in introspection mode.
    /// </summary>
    public int IntrospectionCacheTtlSeconds { get; init; } = 30;

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
    /// An absolute http or https URI. Required exactly when a mounted Manifest requires
    /// authorization — a mount is protected unless it declares <c>authenticationRequired: false</c>,
    /// whether or not any surface declares a scope; the pairing with <see cref="TokenValidationKey"/>
    /// is both-or-neither.
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

    /// <summary>Key bounding positive and negative introspection result caching in seconds.</summary>
    public const string IntrospectionCacheTtlSecondsKey = "introspection-cache-ttl-seconds";

    /// <summary>Key naming the issuer's JWKS URI, overriding the <c>jwks_uri</c> in its published metadata.</summary>
    public const string JwksUriKey = "jwks-uri";

    /// <summary>Key naming the client identity this resource server introspects as.</summary>
    /// <remarks>
    /// RFC 7662 requires the introspection endpoint to be protected, so a resource server that
    /// authenticates itself needs an identity of its own. It is deliberately distinct from every
    /// upstream credential and from the management bearer: the introspection client authenticates
    /// a service to its issuer, and reusing another credential for that would widen what one
    /// disclosure compromises.
    /// </remarks>
    public const string IntrospectionClientIdKey = "introspection-client-id";

    /// <summary>Key naming the file holding the introspection client's secret.</summary>
    /// <remarks>
    /// A file rather than a value, for the same reason the deployment secret is: a secret on a
    /// command line is visible to every process listing on the host, and an environment literal is
    /// visible in a container's inspectable configuration. The pairing with
    /// <see cref="IntrospectionClientIdKey"/> is both-or-neither.
    /// </remarks>
    public const string IntrospectionClientSecretFileKey = "introspection-client-secret-file";

    /// <summary>Accepted value of <see cref="TokenValidationKey"/>: remote RFC 7662 introspection.</summary>
    public const string IntrospectionModeName = "introspection";

    /// <summary>Accepted value of <see cref="TokenValidationKey"/>: local signature validation.</summary>
    public const string JwksModeName = "jwks";

    /// <summary>Host-only shutdown drain window, in positive whole seconds.</summary>
    public const string DrainTimeoutSecondsKey = "drain-timeout-seconds";

    /// <summary>Key naming the directory runtime-owned mutable authentication state is kept in.</summary>
    /// <remarks>
    /// A rotating refresh token must survive a restart, and its replacement is provider-
    /// authoritative the moment the provider issues it. Engine encrypts that one class of value
    /// here; it is not a credential database and holds nothing else. The pairing with
    /// <see cref="RuntimeStateKeyFileKey"/> is both-or-neither.
    /// </remarks>
    public const string RuntimeStateRootKey = "runtime-state-root";

    /// <summary>Key naming the file holding the Engine runtime-state key.</summary>
    /// <remarks>
    /// Exactly 32 raw bytes or their 64-character hexadecimal spelling. This is Engine's own key
    /// and is never the Platform master key.
    /// </remarks>
    public const string RuntimeStateKeyFileKey = "runtime-state-key-file";

    /// <summary>Key selecting the desired-state authority: <c>file</c> or <c>managed</c>.</summary>
    /// <remarks>
    /// Omitted means <c>file</c>, because a command line with local mounts is the shape every
    /// deployment had before managed mode existed. Naming <c>managed</c> together with any
    /// <c>--mount</c> is refused rather than resolved: the two are competing authorities, and
    /// whichever one a tie-break rule chose would decide what a client is served.
    /// </remarks>
    public const string ModeKey = "mode";

    /// <summary>The <c>file</c> spelling of <see cref="ModeKey"/>.</summary>
    public const string FileModeName = "file";

    /// <summary>The <c>managed</c> spelling of <see cref="ModeKey"/>.</summary>
    public const string ManagedModeName = "managed";

    /// <summary>Key naming the Platform management endpoint a managed process polls.</summary>
    /// <remarks>
    /// An absolute URI. HTTPS is required for every address except loopback, where the tests and
    /// local diagnostics run: the deployment secret crosses this connection, and a scheme that
    /// cannot protect it must be an explicit local choice rather than an operator typo.
    /// </remarks>
    public const string ManagementEndpointKey = "management-endpoint";

    /// <summary>Key naming the deployment identity this process is configured for.</summary>
    public const string DeploymentIdKey = "deployment-id";

    /// <summary>Key naming the file holding the deployment-scoped bearer secret.</summary>
    /// <remarks>
    /// A file rather than a value, for the same reason the master key is: a secret on a command
    /// line is visible to every process listing on the host.
    /// </remarks>
    public const string DeploymentSecretFileKey = "deployment-secret-file";

    /// <summary>
    /// Key naming a reverse-proxy address whose forwarded headers this process trusts.
    /// </summary>
    /// <remarks>
    /// Repeatable. An IP address, because that is what a forwarded request carries and what the
    /// hosting middleware compares; a host name would have to be resolved and a resolved name is
    /// not an identity. Absent means no forwarded header is trusted, which is the safe default:
    /// a process that honoured <c>X-Forwarded-Proto</c> from anyone could be told it was reached
    /// over https and would then publish protected-resource metadata naming a scheme and
    /// authority no client used.
    /// </remarks>
    public const string TrustedProxyKey = "trusted-proxy";

    /// <summary>
    /// Key naming an origin whose browser requests this process accepts on an MCP address.
    /// </summary>
    /// <remarks>
    /// Repeatable. Empty means no browser origin is accepted: a request that carries an
    /// <c>Origin</c> header is refused, while a non-browser client that sends none is served
    /// normally. That default is what spec 11 requires of the MCP endpoint - an unexpected origin
    /// is rejected - and a browser is the only client that sends the header at all, so an
    /// operator who wants browser access names the origins that may have it.
    /// </remarks>
    public const string AllowedOriginKey = "allowed-origin";

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
        IntrospectionCacheTtlSecondsKey,
        JwksUriKey,
        IntrospectionClientIdKey,
        IntrospectionClientSecretFileKey,
        DrainTimeoutSecondsKey,
        RuntimeStateRootKey,
        RuntimeStateKeyFileKey,
        ModeKey,
        ManagementEndpointKey,
        DeploymentIdKey,
        DeploymentSecretFileKey,
        TrustedProxyKey,
        AllowedOriginKey,
    ];

    /// <summary>Every key this deployable accepts, excluding the two prefixed families.</summary>
    public static IReadOnlyList<string> AcceptedKeys => Simple;

    /// <summary>
    /// Whether the settings ask for managed mode, before anything is bound.
    /// </summary>
    /// <remarks>
    /// The serving verb needs this before binding so a managed process is not told to supply a
    /// local mount. The mode spelling is read here rather than in the verb so the two places that
    /// know the accepted spellings are one place.
    /// </remarks>
    public static bool RequestsManagedMode(IReadOnlyList<KeyValuePair<string, string>> settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        foreach ((string key, string value) in settings)
        {
            if (string.Equals(key, ModeKey, StringComparison.Ordinal)
                && string.Equals(value, ManagedModeName, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

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
        int? introspectionCacheTtlSeconds = null;
        string? jwksUri = null;
        string? introspectionClientId = null;
        string? introspectionClientSecretFile = null;
        TimeSpan drainTimeout = HostLifecycleOptions.DefaultDrainTimeout;
        string? runtimeStateRoot = null;
        string? runtimeStateKeyFile = null;
        HostDeploymentMode mode = HostDeploymentMode.File;
        bool modeExplicit = false;
        string? managementEndpoint = null;
        string? deploymentId = null;
        string? deploymentSecretFile = null;
        List<string> trustedProxies = [];
        List<string> allowedOrigins = [];

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
                    issuer = AuthorizationUriSetting(key, value, rejected);
                    break;
                case TokenValidationKey:
                    validation = Validation(key, value, rejected);
                    break;
                case IntrospectionEndpointKey:
                    introspectionEndpoint = AuthorizationUriSetting(key, value, rejected);
                    break;
                case IntrospectionCacheTtlSecondsKey:
                    introspectionCacheTtlSeconds = NonNegativeWholeSeconds(key, value, rejected);
                    break;
                case JwksUriKey:
                    jwksUri = AuthorizationUriSetting(key, value, rejected);
                    break;
                case IntrospectionClientIdKey:
                    introspectionClientId = value;
                    break;
                case IntrospectionClientSecretFileKey:
                    introspectionClientSecretFile = value;
                    break;
                case DrainTimeoutSecondsKey:
                    drainTimeout = PositiveWholeSeconds(key, value, rejected);
                    break;
                case RuntimeStateRootKey:
                    runtimeStateRoot = value;
                    break;
                case RuntimeStateKeyFileKey:
                    runtimeStateKeyFile = value;
                    break;
                case ModeKey:
                    if (DeploymentMode(key, value, rejected) is { } parsed)
                    {
                        mode = parsed;
                        modeExplicit = true;
                    }

                    break;
                case ManagementEndpointKey:
                    managementEndpoint = UriSetting(key, value, rejected);
                    break;
                case DeploymentIdKey:
                    deploymentId = value;
                    break;
                case DeploymentSecretFileKey:
                    deploymentSecretFile = value;
                    break;
                case TrustedProxyKey:
                    if (ProxyAddress(key, value, rejected) is { } proxy)
                    {
                        trustedProxies.Add(proxy);
                    }

                    break;
                case AllowedOriginKey:
                    if (BrowserOrigin(key, value, rejected) is { } origin)
                    {
                        allowedOrigins.Add(origin);
                    }

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
            issuer,
            validation,
            introspectionEndpoint,
            introspectionCacheTtlSeconds,
            jwksUri,
            introspectionClientId,
            introspectionClientSecretFile,
            rejected);

        BindRuntimeState(runtimeStateRoot, runtimeStateKeyFile, rejected);

        BindDeploymentMode(mode, modeExplicit, mounts.Count, rejected);

        ManagedSyncOptions? managed = BindManaged(
            mode, managementEndpoint, deploymentId, deploymentSecretFile, rejected);

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
            RuntimeStateRoot = runtimeStateRoot,
            RuntimeStateKeyFile = runtimeStateKeyFile,
        };

        binding = new HostBinding(
            options,
            new HostListenOptions(listen, transport),
            authorization,
            new HostLifecycleOptions(drainTimeout))
        {
            Mode = mode,
            Managed = managed,
            TrustedProxies = trustedProxies,
            AllowedOrigins = allowedOrigins,
        };
        refusals = [];
        return true;
    }

    /// <summary>
    /// Reads a trusted reverse-proxy address, refusing anything that is not an IP literal.
    /// </summary>
    /// <remarks>
    /// An IP literal rather than a host name because the hosting middleware compares the
    /// forwarded request's peer address against the configured set: a name would have to be
    /// resolved, and a resolved name is not an identity a request can be attributed to.
    /// </remarks>
    private static string? ProxyAddress(string key, string value, List<string> rejected)
    {
        if (System.Net.IPAddress.TryParse(value, out _))
        {
            return value;
        }

        rejected.Add($"'{key}' was given '{value}'. Name an IP address such as '172.28.0.2'.");
        return null;
    }

    /// <summary>
    /// Reads a browser origin, refusing anything that is not a bare http(s) origin.
    /// </summary>
    /// <remarks>
    /// Only scheme, host and optional port are admitted, because that is exactly what a browser
    /// puts in the <c>Origin</c> header: a path, query or fragment could never match a real
    /// header value, so accepting one would look configured while refusing every browser. The
    /// canonical spelling is returned so comparison does not depend on how the operator wrote
    /// the trailing slash.
    /// </remarks>
    private static string? BrowserOrigin(string key, string value, List<string> rejected)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out Uri? parsed)
            && parsed.Scheme is "http" or "https"
            && !string.IsNullOrEmpty(parsed.Host)
            && parsed.AbsolutePath is "" or "/"
            && string.IsNullOrEmpty(parsed.Query)
            && string.IsNullOrEmpty(parsed.Fragment)
            && string.IsNullOrEmpty(parsed.UserInfo))
        {
            return parsed.GetLeftPart(UriPartial.Authority);
        }

        rejected.Add($"'{key}' was given '{value}'. Name an origin such as 'https://studio.example.test' with no path, query or fragment.");
        return null;
    }

    /// <summary>
    /// Binds the managed synchronization settings, refusing an incomplete or unsafe set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In managed mode all three settings are required: the endpoint says where to poll, the
    /// deployment identity says which deployment this process is, and the secret file says how it
    /// authenticates. Naming any subset would start a process that cannot synchronize and would
    /// discover that as a timeout rather than as a startup refusal.
    /// </para>
    /// <para>
    /// In file mode none of them is accepted. A management endpoint on a file-mode process names
    /// work nothing does, and accepting it would suggest a synchronization that is not running.
    /// </para>
    /// <para>
    /// A non-loopback <c>http://</c> endpoint is refused because the deployment secret is
    /// presented on every poll. Loopback is admitted so tests and local diagnostics can run
    /// without a certificate, but the plaintext exposure is bounded to the same machine.
    /// </para>
    /// </remarks>
    private static ManagedSyncOptions? BindManaged(
        HostDeploymentMode mode,
        string? endpoint,
        string? deploymentId,
        string? secretFile,
        List<string> rejected)
    {
        if (mode is HostDeploymentMode.File)
        {
            if (endpoint is not null || deploymentId is not null || secretFile is not null)
            {
                rejected.Add(
                    $"'{ManagementEndpointKey}', '{DeploymentIdKey}' and '{DeploymentSecretFileKey}' "
                    + $"configure managed synchronization, but '{ModeKey}' is '{FileModeName}'. "
                    + $"Select '{ManagedModeName}' to synchronize from a deployment.");
            }

            return null;
        }

        bool complete = true;

        if (endpoint is null)
        {
            rejected.Add($"'{ManagementEndpointKey}' is required when '{ModeKey}' is '{ManagedModeName}'. Name the Platform endpoint this process polls.");
            complete = false;
        }

        if (deploymentId is null)
        {
            rejected.Add($"'{DeploymentIdKey}' is required when '{ModeKey}' is '{ManagedModeName}'. Name the deployment this process synchronizes with.");
            complete = false;
        }

        if (secretFile is null)
        {
            rejected.Add($"'{DeploymentSecretFileKey}' is required when '{ModeKey}' is '{ManagedModeName}'. Name the file holding the deployment secret this process authenticates with.");
            complete = false;
        }

        if (!complete)
        {
            return null;
        }

        string? address = UriSetting(ManagementEndpointKey, endpoint!, rejected);

        if (address is null)
        {
            return null;
        }

        Uri parsed = new(address, UriKind.Absolute);

        if (!ManagedSyncOptions.IsLoopback(parsed)
            && !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            rejected.Add(
                $"'{ManagementEndpointKey}' was given '{endpoint}', which is not an https address and "
                + "does not name a loopback host. The deployment secret is presented on every poll, so "
                + "a remote endpoint must be https.");
            return null;
        }

        return new ManagedSyncOptions
        {
            Endpoint = parsed,
            DeploymentId = deploymentId!,
            SecretFile = secretFile!,
        };
    }

    /// <summary>
    /// Refuses a managed process that also names local mounts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The refusal is the point of having a mode at all. A managed process that silently merged a
    /// local mount would serve one mount set at startup and a different one after the first
    /// synchronization, and which one a client saw would depend on timing rather than on
    /// configuration.
    /// </para>
    /// <para>
    /// A file-mode process with no mounts is not refused here: the library already refuses an empty
    /// mount set with <c>host/no-mount</c>, and reporting the same absence twice would put two
    /// codes on one cause.
    /// </para>
    /// </remarks>
    private static void BindDeploymentMode(
        HostDeploymentMode mode,
        bool explicitMode,
        int mountCount,
        List<string> rejected)
    {
        if (mode is HostDeploymentMode.Managed && mountCount > 0)
        {
            rejected.Add(
                $"'{ModeKey}' is '{ManagedModeName}', which makes the Platform deployment the only "
                + $"authority for what this process serves, but {mountCount} '--mount' "
                + (mountCount == 1 ? "input was" : "inputs were")
                + " given. Remove them, or select "
                + $"'{FileModeName}' to serve the local Manifests.");
        }

        if (explicitMode && mode is HostDeploymentMode.File && mountCount == 0)
        {
            rejected.Add(
                $"'{ModeKey}' is '{FileModeName}', which serves the local Manifests, but none was "
                + "given. Name at least one '--mount <prefix>=<dir>'.");
        }
    }

    private static HostDeploymentMode? DeploymentMode(string key, string value, List<string> rejected)
    {
        if (string.Equals(value, FileModeName, StringComparison.Ordinal))
        {
            return HostDeploymentMode.File;
        }

        if (string.Equals(value, ManagedModeName, StringComparison.Ordinal))
        {
            return HostDeploymentMode.Managed;
        }

        rejected.Add($"'{key}' was given '{value}'. Choose '{FileModeName}' or '{ManagedModeName}'.");
        return null;
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
        int? introspectionCacheTtlSeconds,
        string? jwksUri,
        string? introspectionClientId,
        string? introspectionClientSecretFile,
        List<string> rejected)
    {
        if (issuer is null && validation is null)
        {
            if (introspectionEndpoint is not null || jwksUri is not null)
            {
                rejected.Add($"'{IssuerKey}' is required with '{TokenValidationKey}'. An endpoint or a key set with no issuer to trust validates nothing.");
            }

            if (introspectionClientId is not null || introspectionClientSecretFile is not null)
            {
                rejected.Add($"'{IssuerKey}' is required with '{IntrospectionClientIdKey}' and '{IntrospectionClientSecretFileKey}'. A client identity with no issuer authenticates to nobody.");
            }

            if (introspectionCacheTtlSeconds is not null)
            {
                rejected.Add($"'{IntrospectionCacheTtlSecondsKey}' requires '{TokenValidationKey}' to be '{IntrospectionModeName}'. It is unused when no issuer validation is configured.");
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

        if (mode is HostTokenValidation.Jwks && introspectionCacheTtlSeconds is not null)
        {
            rejected.Add($"'{IntrospectionCacheTtlSecondsKey}' names a cache nothing uses: '{TokenValidationKey}' is 'jwks'. Remove it, or select 'introspection'.");
        }

        BindIntrospectionClient(
            mode,
            introspectionClientId,
            introspectionClientSecretFile,
            rejected);

        HostAuthorizationOptions options = new(
            issuer,
            mode,
            introspectionEndpoint,
            jwksUri,
            introspectionClientId,
            introspectionClientSecretFile);

        return options with
        {
            IntrospectionCacheTtlSeconds = introspectionCacheTtlSeconds ?? options.IntrospectionCacheTtlSeconds,
        };
    }

    /// <summary>
    /// Binds the introspection client identity and its secret file, refusing either half alone or
    /// the pair under a mode that never calls the endpoint.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both-or-neither for the same reason the issuer pair is: an identity with no secret can
    /// authenticate as nobody, and a secret with no identity has no one to authenticate as. Either
    /// half alone would look configured and would fail at the first protected request.
    /// </para>
    /// <para>
    /// Under <c>jwks</c> the pair names a client nothing ever presents, which is the same class of
    /// mistake as an introspection endpoint under <c>jwks</c>: the operator believes a setting
    /// applied and the process behaves as if it were never written.
    /// </para>
    /// </remarks>
    private static void BindIntrospectionClient(
        HostTokenValidation mode,
        string? clientId,
        string? secretFile,
        List<string> rejected)
    {
        if (clientId is not null && secretFile is null)
        {
            rejected.Add($"'{IntrospectionClientIdKey}' was given without '{IntrospectionClientSecretFileKey}'. Name the file holding the secret this client authenticates with.");
            return;
        }

        if (secretFile is not null && clientId is null)
        {
            rejected.Add($"'{IntrospectionClientSecretFileKey}' was given without '{IntrospectionClientIdKey}'. Name the client the secret authenticates as.");
            return;
        }

        if (clientId is not null && mode is HostTokenValidation.Jwks)
        {
            rejected.Add($"'{IntrospectionClientIdKey}' and '{IntrospectionClientSecretFileKey}' name a client that presents itself at the introspection endpoint, but '{TokenValidationKey}' is 'jwks', which never calls it. Remove them, or select 'introspection'.");
        }
    }

    /// <summary>
    /// Binds the runtime-state root and key-file pair, refusing either half alone.
    /// </summary>
    /// <remarks>
    /// Both-or-neither for the same reason the authorization pair is: a root with no key cannot
    /// read what it writes, and a key with no root has nowhere to write. A half-configured pair
    /// would start a process that believes its rotating credential is durable when it is not.
    /// </remarks>
    private static void BindRuntimeState(
        string? root,
        string? keyFile,
        List<string> rejected)
    {
        if (root is not null && keyFile is null)
        {
            rejected.Add($"'{RuntimeStateRootKey}' was given without '{RuntimeStateKeyFileKey}'. Durable runtime state needs the key its records are encrypted with.");
        }

        if (keyFile is not null && root is null)
        {
            rejected.Add($"'{RuntimeStateKeyFileKey}' was given without '{RuntimeStateRootKey}'. Name the directory the key decrypts.");
        }
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

    /// <summary>
    /// Binds an authorization trust endpoint and applies the HTTPS-unless-loopback policy before
    /// the endpoint can be used by discovery or bearer validation.
    /// </summary>
    private static string? AuthorizationUriSetting(string key, string value, List<string> rejected)
    {
        string? address = UriSetting(key, value, rejected);
        if (address is null)
        {
            return null;
        }

        Uri parsed = new(address, UriKind.Absolute);
        if (!AuthorizationEndpointPolicy.IsAllowed(parsed))
        {
            rejected.Add(
                $"'{key}' was given '{value}', which is remote plain http. Authorization trust endpoints "
                + "must use https unless they resolve to loopback.");
            return null;
        }

        return address;
    }

    private static HostTokenValidation? Validation(string key, string value, List<string> rejected)
    {
        if (string.Equals(value, IntrospectionModeName, StringComparison.Ordinal))
        {
            return HostTokenValidation.Introspection;
        }

        if (string.Equals(value, JwksModeName, StringComparison.Ordinal))
        {
            return HostTokenValidation.Jwks;
        }

        rejected.Add($"'{key}' was given '{value}'. Choose '{IntrospectionModeName}' or '{JwksModeName}'.");
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

        if (string.Equals(value, HostListenOptions.StdioTransportName, StringComparison.Ordinal))
        {
            return HostTransport.Stdio;
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

    private static TimeSpan PositiveWholeSeconds(string key, string value, List<string> rejected)
    {
        if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int seconds)
            && seconds > 0)
        {
            return TimeSpan.FromSeconds(seconds);
        }

        rejected.Add($"'{key}' was given '{value}', which is not a positive whole number of seconds.");
        return HostLifecycleOptions.DefaultDrainTimeout;
    }

    private static int? NonNegativeWholeSeconds(string key, string value, List<string> rejected)
    {
        if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int seconds)
            && seconds >= 0)
        {
            return seconds;
        }

        rejected.Add($"'{key}' was given '{value}', which is not a non-negative whole number of seconds.");
        return null;
    }
}
