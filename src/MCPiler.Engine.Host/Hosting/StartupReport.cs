using System.Globalization;
using System.Text;

using MCPiler.Engine.Host.Configuration;
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

    /// <summary>The arguments did not name something this host can do.</summary>
    /// <remarks>
    /// Distinct from <see cref="Configuration"/>, which means the command was understood and
    /// the deployment is wrong. The conventional <c>EX_USAGE</c>. A script that mistypes a
    /// verb and one whose Manifest widens a limit need different responses, and one code for
    /// both would make an automated caller unable to tell them apart.
    /// </remarks>
    public const int Usage = 64;
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
    /// <param name="authorization">The bound authorization policy, when serving is configured to validate tokens.</param>
    public static string Render(
        RuntimeStartResult result,
        HostAuthorizationOptions? authorization = null)
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

                // The mount's authorization state belongs beside its identity, in the mount's own
                // vocabulary. Reporting a scope list said nothing about the common case — a
                // protected mount that declares no specific scope — so an operator reading only
                // that line would conclude the mount was open when it was not.
                text.AppendLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"{mount.Prefix} {(mount.RequiresAuthorization() ? "requires authorization" : "served without authorization")}"));
            }

            // The durability of runtime-owned mutable authentication state is the one fact about
            // it an operator needs at startup: a deployment that keeps a rotating refresh token in
            // memory loses it on restart and must reauthorize, which is supported rather than
            // broken, and is invisible until the first restart unless it is stated here.
            text.AppendLine(result.DurableRuntimeState
                ? "runtime state: durable (rotated authentication state survives a restart)"
                : "runtime state: memory-only (a rotated refresh token is lost on restart)");

            AppendAuthorizationPolicy(text, authorization);

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

    /// <summary>Renders one refusal the host produced before a runtime existed.</summary>
    /// <remarks>
    /// Managed startup can refuse before any Manifest is loaded: a Platform that never delivered
    /// an initial generation has no library-side refusal to report, only a synchronization one.
    /// Rendering it through the same line shape keeps an operator's reading of a refusal the same
    /// whichever side produced it.
    /// </remarks>
    public static string RenderRefusal(StartupRefusal refusal)
    {
        ArgumentNullException.ThrowIfNull(refusal);

        StringBuilder text = new();
        text.AppendLine(Line("refused", refusal));
        text.AppendLine("The process will not start. Nothing is served: a partially mounted process "
            + "answers some requests and refuses others in a way that reads as an upstream fault.");
        return text.ToString();
    }

    /// <summary>
    /// Renders one refusal a serving run would produce, for a verb that inspects instead of
    /// serving.
    /// </summary>
    /// <remarks>
    /// The wording is conditional on purpose. Nothing was refused here — the inspection
    /// succeeded and the mount is described — and an operator reading a plain <c>refused</c>
    /// line would conclude the command had failed. Stating that a serving run *would* refuse
    /// is the answer the inspection exists to give, and it carries the same refusal object
    /// the serving path throws, so the two readings cannot disagree.
    /// </remarks>
    public static string RenderUnstartable(StartupRefusal refusal)
    {
        ArgumentNullException.ThrowIfNull(refusal);

        StringBuilder text = new();
        text.AppendLine(Line("would be refused", refusal));
        text.AppendLine("Serving this configuration would not start. The mount is described below "
            + "because inspection succeeded; configure the named setting before running 'serve'.");
        return text.ToString();
    }

    /// <summary>Renders the managed synchronization facts an operator needs at startup.</summary>
    /// <remarks>
    /// The initial generation id is the answer to "what is this process serving", which is not
    /// recoverable from the address it listens on. It is stated once at startup rather than on
    /// every activation, because the progress stream is read by a person watching a boot.
    /// </remarks>
    public static string RenderManaged(
        string endpoint,
        string generationId,
        bool durableRuntimeState,
        HostAuthorizationOptions? authorization = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(endpoint);
        ArgumentException.ThrowIfNullOrEmpty(generationId);

        StringBuilder text = new();

        text.AppendLine(string.Create(
            CultureInfo.InvariantCulture,
            $"managed from {endpoint} -> generation {generationId}"));

        text.AppendLine(durableRuntimeState
            ? "runtime state: durable (rotated authentication state survives a restart)"
            : "runtime state: memory-only (a rotated refresh token is lost on restart)");

        AppendAuthorizationPolicy(text, authorization);

        return text.ToString();
    }

    /// <summary>
    /// Renders the one operator-visible consequence of the configured introspection policy.
    /// </summary>
    /// <remarks>
    /// The line is deliberately sourced from the already-bound authorization options. There is no
    /// second report-only parse of the command line, so the bound the operator reads is the bound
    /// the validator actually receives. JWKS validation and an absent issuer have no introspection
    /// cache policy to report.
    /// </remarks>
    public static string RenderAuthorizationPolicy(HostAuthorizationOptions? authorization)
    {
        if (authorization is not { Validation: HostTokenValidation.Introspection })
        {
            return string.Empty;
        }

        return authorization.IntrospectionCacheTtlSeconds > 0
            ? string.Create(
                CultureInfo.InvariantCulture,
                $"introspection revalidation bound: {authorization.IntrospectionCacheTtlSeconds} seconds")
            : "introspection revalidation bound: caching disabled (fresh issuer validation per request)";
    }

    private static void AppendAuthorizationPolicy(
        StringBuilder text,
        HostAuthorizationOptions? authorization)
    {
        string policy = RenderAuthorizationPolicy(authorization);

        if (policy.Length > 0)
        {
            text.AppendLine(policy);
        }
    }

    private static string Line(string severity, StartupRefusal refusal)
    {
        StringBuilder line = new(severity);

        if (refusal.Mount.Length > 0)
        {
            line.Append(' ').Append(refusal.Mount);
        }

        line.Append(' ').Append('[').Append(refusal.Code);

        if (refusal.ProgramCode is { } program)
        {
            line.Append(' ').Append(program);
        }

        line.Append(']').Append(' ').Append(refusal.Message);

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
