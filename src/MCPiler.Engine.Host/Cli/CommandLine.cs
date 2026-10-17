namespace MCPiler.Engine.Host.Cli;

/// <summary>What the operator asked the process to do.</summary>
public enum HostVerb
{
    /// <summary>Bring every mount up and answer the protocol.</summary>
    Serve,

    /// <summary>Bring every mount up, report what would be served, listen for nothing.</summary>
    Inspect,

    /// <summary>Report every handle the file store holds.</summary>
    FilesList,

    /// <summary>Report one handle by identifier.</summary>
    FilesShow,

    /// <summary>Reclaim expired handles and orphan content, reporting what went.</summary>
    FilesSweep,

    /// <summary>Report the build identity and the Manifest format range it accepts.</summary>
    Version,

    /// <summary>Report the machine-readable compatibility descriptor.</summary>
    Compatibility,

    /// <summary>
    /// Move a permanently integrity-failed confirmation journal aside, without deleting it, so the Engine can
    /// start a fresh journal and managed reconciliation is no longer stalled (R15.12).
    /// </summary>
    ConfirmedRevisionsReset,

    /// <summary>
    /// Interactively bootstrap or reauthorize one file-mode upstream OAuth profile over a loopback
    /// callback (ST-1, ST-2).
    /// </summary>
    AuthAuthorize,

    /// <summary>Report the local authorization state of every profile, or of one (OPS-1).</summary>
    AuthStatus,

    /// <summary>Clear the runtime-owned refresh authorization of one file-mode profile (OPS-2).</summary>
    AuthClear,

    /// <summary>Report bounded, sanitized recent authorization outcomes (OPS-3).</summary>
    AuthEvents,

    /// <summary>
    /// Establish a fresh fail-closed authority baseline for a profile whose durable record cannot
    /// be authenticated, after an explicit acknowledgement (OPS-2g).
    /// </summary>
    AuthAuthorityReset,

    /// <summary>
    /// Probe the configured issuer's metadata and JWKS or introspection endpoint over the network
    /// (IDP-2). Explicit, operator-only, bounded, and separate from <see cref="Inspect"/>.
    /// </summary>
    IssuerReadiness,
}

/// <summary>One parsed command line.</summary>
/// <param name="Verb">The verb, or null when the arguments named none this process knows.</param>
/// <param name="Mounts">Prefix to Manifest directory, in the order given.</param>
/// <param name="Settings">Everything else, in the key shape <see cref="Configuration.HostConfiguration"/> accepts.</param>
/// <param name="Operand">The positional argument a verb takes, such as a handle identifier.</param>
/// <param name="Refusals">Why the arguments could not be read. Empty when they could.</param>
public sealed record CommandLineResult(
    HostVerb? Verb,
    IReadOnlyList<KeyValuePair<string, string>> Mounts,
    IReadOnlyList<KeyValuePair<string, string>> Settings,
    string? Operand,
    IReadOnlyList<string> Refusals)
{
    /// <summary>
    /// The positional arguments a multi-target verb takes, in order, such as a mount prefix and a
    /// profile id. Empty for verbs that take none.
    /// </summary>
    public IReadOnlyList<string> Targets { get; init; } = [];

    /// <summary>
    /// The explicitly configured loopback callback URI for <c>auth authorize</c>, or null when the
    /// verb was given none. It is a per-invocation operator input, not a process setting, so it
    /// never enters <see cref="Settings"/>.
    /// </summary>
    public string? OAuthRedirectUri { get; init; }

    /// <summary>
    /// The base address of a serving Engine's authorization operator channel, or null when this
    /// invocation is not relaying. It is a per-invocation operator input rather than a process
    /// setting, because two invocations of the same binary may talk to different deployments.
    /// </summary>
    public string? OAuthOperatorEndpoint { get; init; }

    /// <summary>
    /// Whether <c>auth authority-reset</c> was given the acknowledgement its irrecoverable effect
    /// requires. Absent means the reset reports what it would affect and refuses.
    /// </summary>
    public bool AcknowledgeReset { get; init; }

    /// <summary>Whether the arguments named a verb this process implements.</summary>
    public bool Recognized => Verb is not null;

    /// <summary>Whether the arguments were readable.</summary>
    public bool Valid => Recognized && Refusals.Count == 0;
}

/// <summary>
/// Turns arguments into a verb and settings, and decides nothing else.
/// </summary>
/// <remarks>
/// <para>
/// This translates syntax. It holds no list of which settings exist, because
/// <see cref="Configuration.HostConfiguration"/> already holds exactly one such list and
/// refuses an unrecognized key by name. A second list here would be a second answer to
/// "is this a real setting", and the two would part company the first time one was extended.
/// </para>
/// <para>
/// The verb set is different: verbs are this process's own vocabulary, so they are named
/// here and an unknown one is refused here.
/// </para>
/// </remarks>
public static class CommandLine
{
    /// <summary>The option introducing a mount, as <c>prefix=directory</c>.</summary>
    public const string MountOption = "--mount";

    /// <summary>The option narrowing one bound on one mount, as <c>prefix:bound=value</c>.</summary>
    public const string MountLimitOption = "--mount-limit";

    /// <summary>The option narrowing one bound across every mount, as <c>bound=value</c>.</summary>
    public const string FloorOption = "--floor";

    /// <summary>The repeatable file-mode external-resource binding option.</summary>
    public const string ExternalResourceOption = "--external-resource";

    /// <summary>
    /// The explicitly configured loopback callback URI <c>auth authorize</c> registers with the
    /// upstream provider. Not a process setting: it is one invocation's callback registration.
    /// </summary>
    public const string OAuthRedirectOption = "--oauth-redirect-uri";

    /// <summary>
    /// The base address of a serving Engine's authorization operator channel, which turns
    /// <c>auth authorize</c> into a relay: the serving process owns the attempt and the commit, and
    /// this process only carries the callback back. Not a process setting; it names the deployment
    /// this one invocation talks to.
    /// </summary>
    public const string OAuthOperatorEndpointOption = "--oauth-operator-endpoint";

    /// <summary>
    /// The acknowledgement <c>auth authority-reset</c> demands before it retires unreadable
    /// authority. A switch, so its mere presence is the operator's explicit statement.
    /// </summary>
    public const string AcknowledgeResetOption = "--acknowledge-irrecoverable";

    /// <summary>The option reporting identity and exiting.</summary>
    public const string VersionOption = "--version";

    /// <summary>The option reporting the machine-readable compatibility descriptor and exiting.</summary>
    public const string CompatibilityOption = "--compatibility";

    /// <summary>What the process prints when it cannot read its own arguments.</summary>
    public const string Usage = """
        mcpiler-engine <verb> [options]

        Verbs
          serve                    Mount every Manifest and answer the protocol.
          inspect                  Mount every Manifest, print what would be served, listen for nothing.
          issuer readiness         Probe the configured issuer over the network: metadata, exact
                                   issuer identity, then JWKS or introspection reachability.
          files list               Print every handle the file store holds.
          files show <id>          Print one handle.
          files sweep              Reclaim expired handles and orphan content.
          auth authorize <mount> <profile>
                                   Authorize one file-mode OAuth profile over a loopback callback.
          auth status [<mount> <profile>]
                                   Report local authorization state, sources and next action.
          auth clear <mount> <profile>
                                   Clear one runtime-owned refresh authorization slot.
          auth events              Report bounded sanitized recent authorization outcomes.
          auth authority-reset <mount> <profile> --acknowledge-irrecoverable
                                   Replace unreadable local authority with a fail-closed baseline.
          confirmed-revisions reset
                                   Move a permanently integrity-failed confirmation journal aside.
          version                  Print the build identity and supported Manifest format range.
          compatibility            Print the machine-readable compatibility descriptor.

        Options
          --mount <prefix>=<dir>   A Manifest bundle directory answering on <prefix>. Repeatable.
          --mount-limit <p>:<b>=<v>  Narrow bound <b> on mount <p>.
          --floor <bound>=<value>  Narrow a bound across every mount.
          --external-resource <surface-route>=<absolute-resource-uri>
                                  Bind one exact file-mode surface route to one external HTTPS resource. Repeatable.
          --oauth-redirect-uri <uri>
                                  The exact loopback callback URI an auth command registers with the provider.
          --oauth-operator-endpoint <url>
                                  Authorize through a serving Engine's operator channel instead of locally.
          --acknowledge-irrecoverable
                                  Acknowledge that 'auth authority-reset' cannot recover the previous credential.
          --allow-loopback-authorization <bool>
                                  Let 'auth authorize' and the 'auth clear' revocation attempt reach a
                                  loopback authorization server. Refused addresses stay refused.
          --<setting> <value>      Any setting the host accepts; an unknown one is named and refused.
          --<switch>               A switch, equivalent to --<switch> true.

        Standalone authorization
          Stop any serving Engine first: authorization and clear take the runtime-state-root lease
          exclusively. Then run, for example:

            mcpiler-engine auth authorize /api my-profile \
              --mount /api=/srv/api --file-store-root /var/lib/mcpiler/files \
              --runtime-state-root /var/lib/mcpiler/state \
              --runtime-state-key-file /etc/mcpiler/state.key \
              --oauth-redirect-uri http://127.0.0.1:57431/oauth/callback

          The provider must register exactly that callback URI. The command opens a short-lived
          listener on that loopback address only, prints the authorization URL, and completes when
          the provider redirects the browser back. In a container or over SSH, forward the callback
          port to the machine running the command (for example ssh -L 57431:127.0.0.1:57431 host).
          There is no device-code flow and no host-exposed callback endpoint.

          Inspect and manage what is authorized, from the same deployment settings:

            mcpiler-engine auth status
            mcpiler-engine auth status /api my-profile
            mcpiler-engine auth clear /api my-profile
            mcpiler-engine auth events

          'auth clear' commits an authenticated cleared floor before it returns, so a restart cannot
          resurrect the previous runtime record or an earlier Manifest-declared credential. A
          declared provider revocation is attempted afterwards at the profile's own endpoint only,
          and its result is reported separately from the local clear. 'auth events' reports the
          bounded, sanitized outcomes this process has recorded; it is in-memory only and states so
          when it has none. In managed mode only status is available and lifecycle actions belong to
          Platform Connect/Reauthorize/Disconnect.

          If a durable record cannot be authenticated with the configured key, ordinary clear and
          authorize refuse. Recovery is a separate, explicitly acknowledged act:

            mcpiler-engine auth authority-reset /api my-profile --acknowledge-irrecoverable

          It names the affected slots and replaces unreadable authority with a fresh fail-closed
          baseline, so the previous credential is irrecoverable and a new 'auth authorize' is
          required.

          An authorization server on the same machine is reachable only with an explicit allowance:

            --allow-loopback-authorization true

          The shipped address table refuses loopback along with private, link-local and every other
          reserved range, because an upstream can steer a request into infrastructure the operator
          did not choose. An authorization server on the operator's own machine needs loopback, so
          this setting widens that one judgement, and only for 'auth authorize' and the revocation
          attempt that follows 'auth clear'. It changes nothing a served request reaches: tool
          execution never reads it. Link-local, instance-metadata, private and reserved addresses
          stay refused with the allowance set.

        Issuer readiness
          'inspect' proves what would be served; it never becomes a networked trust check. The
          explicit, operator-only probe answers a different question - can the configured issuer
          be reached and trusted right now:

            mcpiler-engine issuer readiness \
              --file-store-root /var/lib/mcpiler/files \
              --issuer https://idp.example.com/realms/main \
              --token-validation jwks

          It reads the same deployment settings as 'serve'. It contacts only the configured
          issuer's metadata URL (RFC 8414 first; the issuer-derived OIDC URL only with
          --oidc-discovery-fallback true after exactly HTTP 404/410) and then the effective
          JWKS URI or introspection endpoint. With '--jwks-uri' or
          '--introspection-endpoint' the metadata step is skipped, exactly as the serving
          validators skip it. The introspection check authenticates as the configured
          '--introspection-client-id' and sends one invented, non-secret probe value: it never
          manufactures a caller token, never accepts one as an argument and never prints one.

          Output is one plain-text report with a stable outcome token: 'issuer readiness: ready',
          or 'issuer readiness: not ready [issuer/<category>]' plus a sanitized non-secret
          detail. Categories: unconfigured, unsupported-mode, credential-unusable,
          invalid-metadata, issuer-unavailable, origin-refused, endpoint-unreachable,
          endpoint-unauthorized, endpoint-unusable. Exit codes: ready -> 0; a currently
          unreachable issuer or endpoint -> 1 (retry); every other not-ready outcome -> 78 (fix
          the named configuration). Readiness opens no listener, takes no store-root lease and
          changes no authorization policy.

          A ready result proves metadata, exact issuer identity, endpoint reachability and, for
          introspection, resource-server client authentication only. Issued-token audience,
          scope and revocation behavior require a real provider-issued token accepted by the
          protected MCP resource, and readiness never claims them.

        Serving operator channel
          A running Engine can expose the same read-only status and the same single-slot clear over
          an authenticated, non-MCP channel. It is opt-in and entirely absent unless a dedicated
          secret file is named:

            --oauth-operator-secret-file /etc/mcpiler/operator.secret

          The channel is GET /.engine/oauth/capability, GET /.engine/oauth/status,
          GET /.engine/oauth/events, POST /.engine/oauth/clear and, in file mode, the relay routes
          POST /.engine/oauth/authorize, POST /.engine/oauth/authorize/complete and
          POST /.engine/oauth/authorize/abort. It is authenticated with
          'Authorization: Bearer <secret>' and the 'X-MCPiler-Contract-Generation' header. The
          read-only routes read no request body, the relay routes read one small JSON body, and every
          route requires HTTPS unless the request originates on loopback. It is bounded in
          concurrency, waiting callers, request rate and unfinished authorizations. Its secret is
          deliberately a different file from the response-cache operator secret: it can clear a live
          credential, which that one cannot. In managed mode only the read-only routes are mapped. The
          channel is not an MCP tool and authorizes no ordinary tool call.

          While an Engine is serving, authorize through it rather than stopping it:

            mcpiler-engine auth authorize /api my-profile \
              --oauth-redirect-uri http://127.0.0.1:57431/oauth/callback \
              --oauth-operator-endpoint https://127.0.0.1:8443 \
              --oauth-operator-secret-file /etc/mcpiler/operator.secret

          The serving process builds the attempt and keeps the PKCE verifier and the state; this
          command binds the loopback callback, prints the authorization URL, and forwards only the
          callback's state value back. It takes no store lease and writes nothing. The commit is a
          compare-and-commit on the serving process, so its next tool call already uses the new
          credential.
        """;

    /// <summary>Reads <paramref name="args"/> into a verb, mounts and settings.</summary>
    public static CommandLineResult Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        List<string> refusals = [];
        List<KeyValuePair<string, string>> mounts = [];
        List<KeyValuePair<string, string>> settings = [];
        List<string> targets = [];
        string? oauthRedirectUri = null;
        bool oauthRedirectSeen = false;
        string? oauthOperatorEndpoint = null;
        bool oauthOperatorSeen = false;
        bool acknowledgeReset = false;

        var positional = args.TakeWhile(static argument => !argument.StartsWith("--", StringComparison.Ordinal)).ToList();
        var options = args.Skip(positional.Count).ToList();

        HostVerb? verb = ReadVerb(positional, options, out string? operand, targets, refusals);

        for (int index = 0; index < options.Count; index++)
        {
            string option = options[index];

            if (!option.StartsWith("--", StringComparison.Ordinal))
            {
                refusals.Add($"'{option}' is not an option and follows one. Options start with '--'.");
                continue;
            }

            string name = option[2..];
            string? inline = null;

            int equals = name.IndexOf('=', StringComparison.Ordinal);
            if (equals >= 0)
            {
                inline = name[(equals + 1)..];
                name = name[..equals];
            }

            if (name.Length == 0)
            {
                refusals.Add("'--' names no option.");
                continue;
            }

            // A following token that is itself an option means this one is a switch. Guessing
            // the other way would silently swallow the next option as a value.
            string value = inline
                ?? (index + 1 < options.Count && !options[index + 1].StartsWith("--", StringComparison.Ordinal)
                    ? options[++index]
                    : "true");

            switch ("--" + name)
            {
                case MountOption:
                    Split(value, '=', MountOption, "<prefix>=<directory>", mounts, refusals);
                    break;
                case MountLimitOption:
                    SplitPrefixed(value, Configuration.HostConfiguration.MountNarrowingPrefix, MountLimitOption, "<prefix>:<bound>=<value>", settings, refusals);
                    break;
                case FloorOption:
                    SplitPrefixed(value, Configuration.HostConfiguration.FloorPrefix, FloorOption, "<bound>=<value>", settings, refusals);
                    break;
                case ExternalResourceOption:
                    SplitPrefixed(
                        value,
                        Configuration.HostConfiguration.ExternalResourcePrefix,
                        ExternalResourceOption,
                        "<surface-route>=<absolute-resource-uri>",
                        settings,
                        refusals);
                    break;
                case VersionOption:
                    verb ??= HostVerb.Version;
                    break;
                case CompatibilityOption:
                    verb = HostVerb.Compatibility;
                    break;
                case OAuthRedirectOption:
                    if (oauthRedirectSeen)
                    {
                        refusals.Add($"'{OAuthRedirectOption}' was given more than once.");
                        break;
                    }

                    oauthRedirectUri = value;
                    oauthRedirectSeen = true;
                    break;
                case OAuthOperatorEndpointOption:
                    if (oauthOperatorSeen)
                    {
                        refusals.Add($"'{OAuthOperatorEndpointOption}' was given more than once.");
                        break;
                    }

                    oauthOperatorEndpoint = value;
                    oauthOperatorSeen = true;
                    break;
                case AcknowledgeResetOption:
                    if (!bool.TryParse(value, out acknowledgeReset))
                    {
                        refusals.Add($"'{AcknowledgeResetOption}' was given '{value}', which is not true or false.");
                    }

                    break;
                default:
                    settings.Add(new KeyValuePair<string, string>(name, value));
                    break;
            }
        }

        return new CommandLineResult(verb, mounts, settings, operand, refusals)
        {
            Targets = targets,
            OAuthRedirectUri = oauthRedirectUri,
            OAuthOperatorEndpoint = oauthOperatorEndpoint,
            AcknowledgeReset = acknowledgeReset,
        };
    }

    private static HostVerb? ReadVerb(
        IReadOnlyList<string> positional,
        IReadOnlyList<string> options,
        out string? operand,
        List<string> targets,
        List<string> refusals)
    {
        operand = null;

        if (positional.Count == 0)
        {
            // '--version' alone is a legitimate whole command line, so an absent verb is only
            // a refusal once nothing else names one.
            if (!options.Contains(VersionOption, StringComparer.Ordinal)
                && !options.Contains(CompatibilityOption, StringComparer.Ordinal))
            {
                refusals.Add("No verb was given.");
            }

            return null;
        }

        switch (positional[0])
        {
            case "serve":
                Extra(positional, 1, refusals);
                return HostVerb.Serve;
            case "inspect":
                Extra(positional, 1, refusals);
                return HostVerb.Inspect;
            case "version":
                Extra(positional, 1, refusals);
                return HostVerb.Version;
            case "compatibility":
                Extra(positional, 1, refusals);
                return HostVerb.Compatibility;
            case "files":
                return ReadFilesVerb(positional, out operand, refusals);
            case "auth":
                return ReadAuthVerb(positional, targets, refusals);
            case "issuer":
                return ReadIssuerVerb(positional, refusals);
            case "confirmed-revisions":
                return ReadConfirmedRevisionsVerb(positional, refusals);
            default:
                refusals.Add($"'{positional[0]}' is not a verb this host knows.");
                return null;
        }
    }

    private static HostVerb? ReadFilesVerb(IReadOnlyList<string> positional, out string? operand, List<string> refusals)
    {
        operand = null;

        if (positional.Count < 2)
        {
            refusals.Add("'files' needs one of: list, show <id>, sweep.");
            return null;
        }

        switch (positional[1])
        {
            case "list":
                Extra(positional, 2, refusals);
                return HostVerb.FilesList;
            case "sweep":
                Extra(positional, 2, refusals);
                return HostVerb.FilesSweep;
            case "show":
                if (positional.Count < 3)
                {
                    refusals.Add("'files show' needs a handle identifier.");
                    return null;
                }

                operand = positional[2];
                Extra(positional, 3, refusals);
                return HostVerb.FilesShow;
            default:
                refusals.Add($"'{positional[1]}' is not one of: list, show, sweep.");
                return null;
        }
    }

    private static HostVerb? ReadAuthVerb(IReadOnlyList<string> positional, List<string> targets, List<string> refusals)
    {
        if (positional.Count < 2)
        {
            refusals.Add("'auth' needs one of: authorize, status, clear, events, authority-reset.");
            return null;
        }

        switch (positional[1])
        {
            case "authorize":
                if (positional.Count < 4)
                {
                    refusals.Add("'auth authorize' needs a mount prefix and a profile id.");
                    return null;
                }

                targets.Add(positional[2]);
                targets.Add(positional[3]);
                Extra(positional, 4, refusals);
                return HostVerb.AuthAuthorize;
            case "status":
                if (positional.Count == 2)
                {
                    return HostVerb.AuthStatus;
                }

                if (positional.Count == 4)
                {
                    targets.Add(positional[2]);
                    targets.Add(positional[3]);
                    Extra(positional, 4, refusals);
                    return HostVerb.AuthStatus;
                }

                refusals.Add("'auth status' takes either no target (every profile) or both a mount prefix and a profile id.");
                return null;
            case "clear":
                if (positional.Count < 4)
                {
                    refusals.Add("'auth clear' needs a mount prefix and a profile id.");
                    return null;
                }

                targets.Add(positional[2]);
                targets.Add(positional[3]);
                Extra(positional, 4, refusals);
                return HostVerb.AuthClear;
            case "events":
                Extra(positional, 2, refusals);
                return HostVerb.AuthEvents;
            case "authority-reset":
                if (positional.Count < 4)
                {
                    refusals.Add("'auth authority-reset' needs a mount prefix and a profile id.");
                    return null;
                }

                targets.Add(positional[2]);
                targets.Add(positional[3]);
                Extra(positional, 4, refusals);
                return HostVerb.AuthAuthorityReset;
            default:
                refusals.Add($"'{positional[1]}' is not one of: authorize, status, clear, events, authority-reset.");
                return null;
        }
    }

    /// <summary>
    /// Reads the <c>issuer</c> family. Today one subcommand, <c>readiness</c>, and it takes no
    /// positional target: the issuer comes from the same bound settings every other verb reads.
    /// </summary>
    private static HostVerb? ReadIssuerVerb(IReadOnlyList<string> positional, List<string> refusals)
    {
        if (positional.Count < 2)
        {
            refusals.Add("'issuer' needs one of: readiness.");
            return null;
        }

        switch (positional[1])
        {
            case "readiness":
                Extra(positional, 2, refusals);
                return HostVerb.IssuerReadiness;
            default:
                refusals.Add($"'{positional[1]}' is not one of: readiness.");
                return null;
        }
    }

    private static HostVerb? ReadConfirmedRevisionsVerb(IReadOnlyList<string> positional, List<string> refusals)
    {
        if (positional.Count < 2)
        {
            refusals.Add("'confirmed-revisions' needs its 'reset' subcommand.");
            return null;
        }

        if (positional[1] != "reset")
        {
            refusals.Add($"'{positional[1]}' is not one of: reset.");
            return null;
        }

        Extra(positional, 2, refusals);
        return HostVerb.ConfirmedRevisionsReset;
    }

    private static void Extra(IReadOnlyList<string> positional, int consumed, List<string> refusals)
    {
        if (positional.Count > consumed)
        {
            refusals.Add($"'{positional[consumed]}' was not expected here.");
        }
    }

    private static void Split(
        string value,
        char separator,
        string option,
        string shape,
        List<KeyValuePair<string, string>> into,
        List<string> refusals)
    {
        int at = value.IndexOf(separator, StringComparison.Ordinal);

        if (at <= 0 || at == value.Length - 1)
        {
            refusals.Add($"'{option} {value}' is not '{option} {shape}'.");
            return;
        }

        into.Add(new KeyValuePair<string, string>(value[..at], value[(at + 1)..]));
    }

    private static void SplitPrefixed(
        string value,
        string keyPrefix,
        string option,
        string shape,
        List<KeyValuePair<string, string>> into,
        List<string> refusals)
    {
        int at = value.IndexOf('=', StringComparison.Ordinal);

        if (at <= 0 || at == value.Length - 1)
        {
            refusals.Add($"'{option} {value}' is not '{option} {shape}'.");
            return;
        }

        into.Add(new KeyValuePair<string, string>(keyPrefix + value[..at], value[(at + 1)..]));
    }
}
