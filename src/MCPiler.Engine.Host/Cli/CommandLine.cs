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

    /// <summary>The option reporting identity and exiting.</summary>
    public const string VersionOption = "--version";

    /// <summary>What the process prints when it cannot read its own arguments.</summary>
    public const string Usage = """
        mcpiler-engine <verb> [options]

        Verbs
          serve                    Mount every Manifest and answer the protocol.
          inspect                  Mount every Manifest, print what would be served, listen for nothing.
          files list               Print every handle the file store holds.
          files show <id>          Print one handle.
          files sweep              Reclaim expired handles and orphan content.
          version                  Print the build identity and supported Manifest format range.

        Options
          --mount <prefix>=<dir>   A Manifest bundle directory answering on <prefix>. Repeatable.
          --mount-limit <p>:<b>=<v>  Narrow bound <b> on mount <p>.
          --floor <bound>=<value>  Narrow a bound across every mount.
          --<setting> <value>      Any setting the host accepts; an unknown one is named and refused.
          --<switch>               A switch, equivalent to --<switch> true.
        """;

    /// <summary>Reads <paramref name="args"/> into a verb, mounts and settings.</summary>
    public static CommandLineResult Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        List<string> refusals = [];
        List<KeyValuePair<string, string>> mounts = [];
        List<KeyValuePair<string, string>> settings = [];

        var positional = args.TakeWhile(static argument => !argument.StartsWith("--", StringComparison.Ordinal)).ToList();
        var options = args.Skip(positional.Count).ToList();

        HostVerb? verb = ReadVerb(positional, options, out string? operand, refusals);

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
                case VersionOption:
                    verb ??= HostVerb.Version;
                    break;
                default:
                    settings.Add(new KeyValuePair<string, string>(name, value));
                    break;
            }
        }

        return new CommandLineResult(verb, mounts, settings, operand, refusals);
    }

    private static HostVerb? ReadVerb(
        IReadOnlyList<string> positional,
        IReadOnlyList<string> options,
        out string? operand,
        List<string> refusals)
    {
        operand = null;

        if (positional.Count == 0)
        {
            // '--version' alone is a legitimate whole command line, so an absent verb is only
            // a refusal once nothing else names one.
            if (!options.Contains(VersionOption, StringComparer.Ordinal))
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
            case "files":
                return ReadFilesVerb(positional, out operand, refusals);
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
