using System.Globalization;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Manifest.Validation;

/// <summary>
/// The unit a bound is expressed in. Used only to render a diagnostic an operator can act on.
/// </summary>
public enum LimitUnit
{
    /// <summary>A plain count.</summary>
    Count,

    /// <summary>A byte count.</summary>
    Bytes,

    /// <summary>A duration held as ticks.</summary>
    Duration,

    /// <summary>A boolean hardening switch held as permissiveness.</summary>
    Flag,
}

/// <summary>
/// One compiled bound that local configuration may narrow but never widen.
/// </summary>
/// <remarks>
/// Every bound is normalized to a single <em>permissiveness</em> number where a lower value is
/// always the stricter setting. That removes the per-bound "is smaller stricter?" question
/// from the comparison, which is exactly the kind of per-case reasoning that lets one bound
/// quietly get the comparison backwards.
/// </remarks>
/// <param name="Name">The configuration name an operator sets.</param>
/// <param name="DeclaringType">The policy record the bound belongs to.</param>
/// <param name="Member">The member name on that record.</param>
/// <param name="Unit">How to render the value.</param>
public sealed record ProtectedLimit(string Name, Type DeclaringType, string Member, LimitUnit Unit);

/// <summary>
/// Applies operator narrowing to a compiled policy, refusing any attempt to widen it.
/// </summary>
public static class PolicyNarrowing
{
    private sealed record Rule(
        ProtectedLimit Limit,
        Func<PolicySection, long> Compiled,
        Func<PolicyOverrides, long?> Requested,
        Func<PolicySection, long, PolicySection> With);

    private static readonly Rule[] Rules =
    [
        new(
            new("UpstreamConnectTimeout", typeof(ExecutionLimits), nameof(ExecutionLimits.UpstreamConnectTimeout), LimitUnit.Duration),
            static policy => policy.EffectiveLimits.UpstreamConnectTimeout.Ticks,
            static overrides => overrides.UpstreamConnectTimeout?.Ticks,
            static (policy, value) => policy with
            {
                Limits = policy.EffectiveLimits with { UpstreamConnectTimeout = TimeSpan.FromTicks(value) },
            }),
        new(
            new("UpstreamRequestTimeout", typeof(ExecutionLimits), nameof(ExecutionLimits.UpstreamRequestTimeout), LimitUnit.Duration),
            static policy => policy.EffectiveLimits.UpstreamRequestTimeout.Ticks,
            static overrides => overrides.UpstreamRequestTimeout?.Ticks,
            static (policy, value) => policy with
            {
                Limits = policy.EffectiveLimits with { UpstreamRequestTimeout = TimeSpan.FromTicks(value) },
            }),
        new(
            new("UpstreamResponseSizeLimitBytes", typeof(ExecutionLimits), nameof(ExecutionLimits.UpstreamResponseSizeLimitBytes), LimitUnit.Bytes),
            static policy => policy.EffectiveLimits.UpstreamResponseSizeLimitBytes,
            static overrides => overrides.UpstreamResponseSizeLimitBytes,
            static (policy, value) => policy with
            {
                Limits = policy.EffectiveLimits with { UpstreamResponseSizeLimitBytes = value },
            }),
        new(
            new("RedirectHopLimit", typeof(ExecutionLimits), nameof(ExecutionLimits.RedirectHopLimit), LimitUnit.Count),
            static policy => policy.EffectiveLimits.RedirectHopLimit,
            static overrides => overrides.RedirectHopLimit,
            static (policy, value) => policy with
            {
                Limits = policy.EffectiveLimits with { RedirectHopLimit = (int)value },
            }),
        new(
            new("Concurrency", typeof(ExecutionLimits), nameof(ExecutionLimits.Concurrency), LimitUnit.Count),
            static policy => policy.EffectiveLimits.Concurrency,
            static overrides => overrides.Concurrency,
            static (policy, value) => policy with
            {
                Limits = policy.EffectiveLimits with { Concurrency = (int)value },
            }),
        new(
            new("McpRequestSizeLimitBytes", typeof(ExecutionLimits), nameof(ExecutionLimits.McpRequestSizeLimitBytes), LimitUnit.Bytes),
            static policy => policy.EffectiveLimits.McpRequestSizeLimitBytes,
            static overrides => overrides.McpRequestSizeLimitBytes,
            static (policy, value) => policy with
            {
                Limits = policy.EffectiveLimits with { McpRequestSizeLimitBytes = value },
            }),
        new(
            new("TransformMaxSteps", typeof(TransformCeiling), nameof(TransformCeiling.MaxSteps), LimitUnit.Count),
            static policy => policy.EffectiveTransformCeiling.MaxSteps,
            static overrides => overrides.TransformMaxSteps,
            static (policy, value) => policy with
            {
                TransformCeiling = policy.EffectiveTransformCeiling with { MaxSteps = (int)value },
            }),
        new(
            new("TransformMaxDepth", typeof(TransformCeiling), nameof(TransformCeiling.MaxDepth), LimitUnit.Count),
            static policy => policy.EffectiveTransformCeiling.MaxDepth,
            static overrides => overrides.TransformMaxDepth,
            static (policy, value) => policy with
            {
                TransformCeiling = policy.EffectiveTransformCeiling with { MaxDepth = (int)value },
            }),
        new(
            new("TransformMaxNodes", typeof(TransformCeiling), nameof(TransformCeiling.MaxNodes), LimitUnit.Count),
            static policy => policy.EffectiveTransformCeiling.MaxNodes,
            static overrides => overrides.TransformMaxNodes,
            static (policy, value) => policy with
            {
                TransformCeiling = policy.EffectiveTransformCeiling with { MaxNodes = (int)value },
            }),
        new(
            new("TransformMaxOutputBytes", typeof(TransformCeiling), nameof(TransformCeiling.MaxOutputBytes), LimitUnit.Bytes),
            static policy => policy.EffectiveTransformCeiling.MaxOutputBytes,
            static overrides => overrides.TransformMaxOutputBytes,
            static (policy, value) => policy with
            {
                TransformCeiling = policy.EffectiveTransformCeiling with { MaxOutputBytes = value },
            }),
        new(
            new("TransformMaxArrayFanout", typeof(TransformCeiling), nameof(TransformCeiling.MaxArrayFanout), LimitUnit.Count),
            static policy => policy.EffectiveTransformCeiling.MaxArrayFanout,
            static overrides => overrides.TransformMaxArrayFanout,
            static (policy, value) => policy with
            {
                TransformCeiling = policy.EffectiveTransformCeiling with { MaxArrayFanout = (int)value },
            }),
        new(
            new("CompoundMaxTotalResponseBytes", typeof(CompoundBounds), nameof(CompoundBounds.MaxTotalResponseBytes), LimitUnit.Bytes),
            static policy => policy.EffectiveCompound.MaxTotalResponseBytes,
            static overrides => overrides.CompoundMaxTotalResponseBytes,
            static (policy, value) => policy with
            {
                Compound = policy.EffectiveCompound with { MaxTotalResponseBytes = value },
            }),
        new(
            new("CompoundWorkflowTimeout", typeof(CompoundBounds), nameof(CompoundBounds.WorkflowTimeout), LimitUnit.Duration),
            static policy => policy.EffectiveCompound.WorkflowTimeout.Ticks,
            static overrides => overrides.CompoundWorkflowTimeout?.Ticks,
            static (policy, value) => policy with
            {
                Compound = policy.EffectiveCompound with { WorkflowTimeout = TimeSpan.FromTicks(value) },
            }),
        new(
            new("SchemaMaxDepth", typeof(SchemaBounds), nameof(SchemaBounds.MaxDepth), LimitUnit.Count),
            static policy => policy.EffectiveSchemaBounds.MaxDepth,
            static overrides => overrides.SchemaMaxDepth,
            static (policy, value) => policy with
            {
                SchemaBounds = policy.EffectiveSchemaBounds with { MaxDepth = (int)value },
            }),
        new(
            new("SchemaMaxNodes", typeof(SchemaBounds), nameof(SchemaBounds.MaxNodes), LimitUnit.Count),
            static policy => policy.EffectiveSchemaBounds.MaxNodes,
            static overrides => overrides.SchemaMaxNodes,
            static (policy, value) => policy with
            {
                SchemaBounds = policy.EffectiveSchemaBounds with { MaxNodes = (int)value },
            }),
        new(
            new("SchemaMaxPropertiesPerLevel", typeof(SchemaBounds), nameof(SchemaBounds.MaxPropertiesPerLevel), LimitUnit.Count),
            static policy => policy.EffectiveSchemaBounds.MaxPropertiesPerLevel,
            static overrides => overrides.SchemaMaxPropertiesPerLevel,
            static (policy, value) => policy with
            {
                SchemaBounds = policy.EffectiveSchemaBounds with { MaxPropertiesPerLevel = (int)value },
            }),
        new(
            new("FileHandleLifetime", typeof(FilePolicy), nameof(FilePolicy.HandleLifetime), LimitUnit.Duration),
            static policy => policy.EffectiveFiles.HandleLifetime.Ticks,
            static overrides => overrides.FileHandleLifetime?.Ticks,
            static (policy, value) => policy with
            {
                Files = policy.EffectiveFiles with { HandleLifetime = TimeSpan.FromTicks(value) },
            }),
        new(
            new("FileUploadSizeLimitBytes", typeof(FilePolicy), nameof(FilePolicy.UploadSizeLimitBytes), LimitUnit.Bytes),
            static policy => policy.EffectiveFiles.UploadSizeLimitBytes,
            static overrides => overrides.FileUploadSizeLimitBytes,
            static (policy, value) => policy with
            {
                Files = policy.EffectiveFiles with { UploadSizeLimitBytes = value },
            }),
        new(
            new("FileRejectMagicMismatch", typeof(FilePolicy), nameof(FilePolicy.RejectMagicMismatch), LimitUnit.Flag),
            static policy => Permissiveness(policy.EffectiveFiles.RejectMagicMismatch),
            static overrides => overrides.FileRejectMagicMismatch is { } reject ? Permissiveness(reject) : null,
            static (policy, value) => policy with
            {
                Files = policy.EffectiveFiles with { RejectMagicMismatch = value == 0 },
            }),
    ];

    /// <summary>
    /// Every compiled bound local configuration is allowed to narrow.
    /// </summary>
    /// <remarks>
    /// This list is the specification, not documentation of it: <see cref="Apply"/> iterates
    /// exactly these rules. An architecture test walks the policy records by reflection and
    /// asserts each numeric or boolean member appears here, so adding a bound without
    /// protecting it fails the build rather than shipping an unguarded widening path.
    /// </remarks>
    public static IReadOnlyList<ProtectedLimit> ProtectedLimits { get; } =
        [.. Rules.Select(static rule => rule.Limit)];

    /// <summary>
    /// The protected bounds indexed by the name an operator writes, compared ordinally.
    /// </summary>
    /// <remarks>
    /// A host configures narrowing by name because the alternative is a second list of the
    /// same nineteen bounds in whatever type the configuration surface uses, and a second
    /// list drifts. The reflection guard behind <see cref="ProtectedLimits"/> then protects
    /// the configuration surface too, for free.
    /// </remarks>
    public static IReadOnlyDictionary<string, ProtectedLimit> ByName { get; } =
        Rules.ToDictionary(static rule => rule.Limit.Name, static rule => rule.Limit, StringComparer.Ordinal);

    /// <summary>
    /// The value <paramref name="policy"/> compiled for <paramref name="limitName"/>, expressed
    /// in the same permissiveness units <see cref="ApplyNamed"/> compares.
    /// </summary>
    /// <remarks>
    /// Exposed so a caller can compute a floor as the minimum of a process-wide setting and
    /// what a manifest already compiled. Clamping before the comparison is what makes a floor
    /// structurally incapable of widening, rather than merely intended not to.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="limitName"/> is not a protected bound.</exception>
    public static long Compiled(PolicySection policy, string limitName)
    {
        ArgumentNullException.ThrowIfNull(policy);

        Rule rule = Array.Find(Rules, candidate => string.Equals(candidate.Limit.Name, limitName, StringComparison.Ordinal))
            ?? throw new ArgumentOutOfRangeException(nameof(limitName), limitName, "Not a protected bound.");

        return rule.Compiled(policy);
    }

    /// <summary>
    /// Returns <paramref name="compiled"/> narrowed by bounds named in <paramref name="requested"/>,
    /// reporting every attempt to widen one.
    /// </summary>
    /// <remarks>
    /// Behaves exactly as <see cref="Apply"/>; only the way a caller names a bound differs. An
    /// unrecognized name is a caller error rather than a diagnostic, because a configuration
    /// surface is expected to have refused it by name already.
    /// </remarks>
    public static PolicySection ApplyNamed(
        PolicySection compiled,
        IReadOnlyDictionary<string, long> requested,
        ICollection<ManifestDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(compiled);
        ArgumentNullException.ThrowIfNull(requested);
        ArgumentNullException.ThrowIfNull(diagnostics);

        PolicySection narrowed = compiled;

        foreach (Rule rule in Rules)
        {
            if (!requested.TryGetValue(rule.Limit.Name, out long value))
            {
                continue;
            }

            long compiledValue = rule.Compiled(compiled);

            if (value > compiledValue)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.LimitWidened,
                    $"Local configuration sets '{rule.Limit.Name}' to {Render(value, rule.Limit.Unit)}, " +
                    $"which is more permissive than the compiled {Render(compiledValue, rule.Limit.Unit)}. " +
                    "Local configuration may only narrow a compiled bound.",
                    section: ManifestSectionName.Policy));
                continue;
            }

            narrowed = rule.With(narrowed, value);
        }

        return narrowed;
    }

    /// <summary>
    /// Returns <paramref name="compiled"/> narrowed by <paramref name="overrides"/>, reporting
    /// every attempt to widen a bound or the perimeter.
    /// </summary>
    /// <remarks>
    /// On any widening attempt the compiled value is kept and an error is reported. The
    /// returned policy is therefore never more permissive than the manifest compiled, whether
    /// or not the caller inspects the diagnostics.
    /// </remarks>
    public static PolicySection Apply(
        PolicySection compiled,
        PolicyOverrides? overrides,
        ICollection<ManifestDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(compiled);
        ArgumentNullException.ThrowIfNull(diagnostics);

        if (overrides is null)
        {
            return compiled;
        }

        PolicySection narrowed = compiled;

        foreach (Rule rule in Rules)
        {
            if (rule.Requested(overrides) is not { } requested)
            {
                continue;
            }

            long compiledValue = rule.Compiled(compiled);

            if (requested > compiledValue)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.LimitWidened,
                    $"Local configuration sets '{rule.Limit.Name}' to {Render(requested, rule.Limit.Unit)}, " +
                    $"which is more permissive than the compiled {Render(compiledValue, rule.Limit.Unit)}. " +
                    "Local configuration may only narrow a compiled bound.",
                    section: ManifestSectionName.Policy));
                continue;
            }

            narrowed = rule.With(narrowed, requested);
        }

        return ApplyOrigins(compiled, narrowed, overrides, diagnostics);
    }

    private static PolicySection ApplyOrigins(
        PolicySection compiled,
        PolicySection narrowed,
        PolicyOverrides overrides,
        ICollection<ManifestDiagnostic> diagnostics)
    {
        if (overrides.AllowedOrigins is not { } requested)
        {
            return narrowed;
        }

        HashSet<string> permitted = new(compiled.AllowedOrigins, StringComparer.OrdinalIgnoreCase);
        List<string> accepted = [];
        bool widened = false;

        foreach (string origin in requested)
        {
            if (!permitted.Contains(origin))
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.LimitWidened,
                    $"Local configuration adds origin '{DiagnosticText.Echo(origin)}' to the perimeter, " +
                    $"which the manifest does not compile. The compiled perimeter is " +
                    $"{DiagnosticText.List(compiled.AllowedOrigins)}. Local configuration may only remove an origin.",
                    section: ManifestSectionName.Policy));
                widened = true;
                continue;
            }

            accepted.Add(origin);
        }

        if (widened)
        {
            return narrowed;
        }

        if (accepted.Count == 0)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.OriginInvalid,
                "Local configuration removes every allowed origin, which leaves no destination reachable. " +
                "Omit the override to keep the compiled perimeter.",
                section: ManifestSectionName.Policy));

            return narrowed;
        }

        return narrowed with { AllowedOrigins = accepted };
    }

    private static long Permissiveness(bool hardened) => hardened ? 0 : 1;

    private static string Render(long value, LimitUnit unit) => unit switch
    {
        LimitUnit.Duration => TimeSpan.FromTicks(value).ToString("c", CultureInfo.InvariantCulture),
        LimitUnit.Bytes => value.ToString(CultureInfo.InvariantCulture) + " bytes",
        LimitUnit.Flag => value == 0 ? "enabled" : "disabled",
        _ => value.ToString(CultureInfo.InvariantCulture),
    };
}
