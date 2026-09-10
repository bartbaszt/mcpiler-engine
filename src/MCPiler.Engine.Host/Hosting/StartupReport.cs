using System.Globalization;
using System.Text;

using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>The exit codes this deployable uses.</summary>
/// <remarks>
/// A configuration refusal exits distinctly from a crash because the two call for different
/// responses, and an orchestrator restarting a process whose configuration is wrong will
/// restart it forever. The value follows the conventional <c>EX_CONFIG</c>, which is what a
/// deployment engineer looking it up will find.
/// </remarks>
public static class ExitCodes
{
    /// <summary>The command did what it was asked.</summary>
    public const int Success = 0;

    /// <summary>Something about the configuration or a Manifest means the process will not serve.</summary>
    public const int Configuration = 78;

    /// <summary>An error the host does not attribute to configuration.</summary>
    public const int Failure = 1;
}

/// <summary>
/// Turns a startup outcome into what an operator reads.
/// </summary>
/// <remarks>
/// <para>
/// Rendering is all this does. Which refusals exist, and whether any of them stops the
/// process, is decided in the library; a deployable that could soften a refusal into a
/// warning would be deciding the safety property from the outside.
/// </para>
/// <para>
/// Every refusal is printed, not just the first. An operator who fixes one setting and
/// restarts only to meet the next one learns the shape of their configuration one round trip
/// at a time, and each round trip is a deployment.
/// </para>
/// </remarks>
public static class StartupReport
{
    /// <summary>Renders every refusal and warning, in the order the runtime reported them.</summary>
    public static string Render(RuntimeStartResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        StringBuilder text = new();

        foreach (StartupRefusal warning in result.Warnings)
        {
            text.AppendLine(Line("warning", warning));
        }

        if (result.Started)
        {
            foreach (MountedManifest mount in result.Mounts)
            {
                text.AppendLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"mounted {mount.Prefix} -> {mount.ServerName} ({mount.Path})"));
            }

            return text.ToString();
        }

        foreach (StartupRefusal refusal in result.Refusals)
        {
            text.AppendLine(Line("refused", refusal));
        }

        text.AppendLine("The process will not start. Nothing is served: a partially mounted process "
            + "answers some requests and refuses others in a way that reads as an upstream fault.");

        return text.ToString();
    }

    /// <summary>The exit code the outcome calls for.</summary>
    public static int ExitCode(RuntimeStartResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return result.Started ? ExitCodes.Success : ExitCodes.Configuration;
    }

    private static string Line(string severity, StartupRefusal refusal)
    {
        StringBuilder line = new(severity);

        if (refusal.Mount.Length > 0)
        {
            line.Append(' ').Append(refusal.Mount);
        }

        line.Append(' ').Append('[').Append(refusal.Code).Append(']').Append(' ').Append(refusal.Message);

        if (refusal.Manifest is { } manifest)
        {
            line.Append(" manifest=").Append(manifest);
        }

        if (refusal.Setting is { } setting)
        {
            line.Append(" setting=").Append(setting);
        }

        if (refusal.Compiled is { } compiled)
        {
            line.Append(" compiled=").Append(compiled);
        }

        if (refusal.Attempted is { } attempted)
        {
            line.Append(" configured=").Append(attempted);
        }

        return line.ToString();
    }
}
