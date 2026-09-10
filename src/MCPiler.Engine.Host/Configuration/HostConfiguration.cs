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
/// <param name="Listener">What the listener is told.</param>
public sealed record HostBinding(RuntimeOptions Runtime, HostListenOptions Listener);

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

    private static readonly string[] Simple =
    [
        FileStoreRootKey,
        ListenKey,
        TransportKey,
        RequireSealedKey,
        AllowInlineSecretsKey,
        ServedContentRootKey,
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
                default:
                    rejected.Add($"'{key}' is not a setting this host accepts. It accepts {string.Join(", ", Simple)}, '{MountNarrowingPrefix}{{prefix}}:{{bound}}' and '{FloorPrefix}{{bound}}'.");
                    break;
            }
        }

        if (fileStoreRoot is null)
        {
            rejected.Add($"'{FileStoreRootKey}' is required. Issued file handles need somewhere to keep their content.");
        }

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

        binding = new HostBinding(options, new HostListenOptions(listen, transport));
        refusals = [];
        return true;
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
