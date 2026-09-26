using System.Reflection;

using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Validation;

public sealed class PolicyNarrowingTests
{
    private readonly List<ManifestDiagnostic> _diagnostics = [];

    private static PolicySection Compiled(params string[] origins)
        => new(
            BaseUrl: new Uri("https://api.example.com/v1"),
            AllowedOrigins: origins.Length == 0 ? null! : origins);

    private IReadOnlyList<string> ErrorCodes
        => [.. _diagnostics.Where(static d => d.IsError).Select(static d => d.Code)];

    // ---- the rule table is the specification -------------------------------------------

    /// <summary>
    /// Every numeric or boolean bound on every policy record must appear in the protected set.
    /// </summary>
    /// <remarks>
    /// This is the guard that matters. Adding a bound to the policy model without adding it to
    /// the narrowing table would leave a value an operator can raise without refusal, and no
    /// hand-written test would notice because the new bound would simply have no test.
    /// </remarks>
    [Fact]
    public void Every_policy_bound_is_protected_against_widening()
    {
        Type[] boundRecords =
        [
            typeof(ExecutionLimits),
            typeof(TransformCeiling),
            typeof(JmesPathCeiling),
            typeof(CompoundBounds),
            typeof(SchemaBounds),
            typeof(FilePolicy),
        ];

        var protectedMembers = ProtectedMembers();
        List<string> unprotected = [];

        foreach (Type record in boundRecords)
        {
            foreach (PropertyInfo property in record.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                if (!IsBound(property.PropertyType))
                {
                    continue;
                }

                if (!protectedMembers.Contains((record, property.Name)))
                {
                    unprotected.Add($"{record.Name}.{property.Name}");
                }
            }
        }

        Assert.Empty(unprotected);
    }

    [Fact]
    public void No_protected_limit_names_a_member_that_does_not_exist()
    {
        List<string> dangling = [];

        foreach (ProtectedLimit limit in PolicyNarrowing.ProtectedLimits)
        {
            if (limit.DeclaringType.GetProperty(limit.Member) is null)
            {
                dangling.Add($"{limit.DeclaringType.Name}.{limit.Member}");
            }
        }

        Assert.Empty(dangling);
    }

    [Fact]
    public void Protected_limit_names_are_unique()
    {
        var names = PolicyNarrowing.ProtectedLimits.Select(static limit => limit.Name).ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
    }

    private static HashSet<(Type, string)> ProtectedMembers()
        => [.. PolicyNarrowing.ProtectedLimits.Select(static limit => (limit.DeclaringType, limit.Member))];

    private static bool IsBound(Type type)
        => type == typeof(int) || type == typeof(long) || type == typeof(TimeSpan) || type == typeof(bool);

    // ---- narrowing is accepted ----------------------------------------------------------

    [Fact]
    public void A_smaller_numeric_bound_is_accepted()
    {
        PolicySection narrowed = PolicyNarrowing.Apply(
            Compiled(),
            new PolicyOverrides { UpstreamResponseSizeLimitBytes = 1024 },
            _diagnostics);

        Assert.Empty(_diagnostics);
        Assert.Equal(1024, narrowed.EffectiveLimits.UpstreamResponseSizeLimitBytes);
    }

    [Fact]
    public void A_shorter_duration_is_accepted()
    {
        PolicySection narrowed = PolicyNarrowing.Apply(
            Compiled(),
            new PolicyOverrides { UpstreamRequestTimeout = TimeSpan.FromSeconds(5) },
            _diagnostics);

        Assert.Empty(_diagnostics);
        Assert.Equal(TimeSpan.FromSeconds(5), narrowed.EffectiveLimits.UpstreamRequestTimeout);
    }

    /// <summary>
    /// A JMESPath ceiling narrows like every other bound, in all seven dimensions.
    /// </summary>
    /// <remarks>
    /// The projection's own limits are declared by a Manifest and bounded by this ceiling, so
    /// the ceiling is the operator's only lever over a projection an author already published.
    /// Each dimension is exercised because they are compared independently: a rule that was
    /// written for the wrong member would still accept a narrower value somewhere.
    /// </remarks>
    [Fact]
    public void A_narrower_jmespath_ceiling_is_accepted_in_every_dimension()
    {
        PolicySection compiled = Compiled();

        PolicySection narrowed = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides
            {
                JmesPathMaxExpressionBytes = 1024,
                JmesPathMaxInputNodes = 1000,
                JmesPathMaxInputDepth = 16,
                JmesPathMaxResultNodes = 1000,
                JmesPathMaxResultDepth = 16,
                JmesPathMaxOutputBytes = 4096,
                JmesPathMaxEvaluationMilliseconds = TimeSpan.FromSeconds(5),
            },
            _diagnostics);

        Assert.Empty(_diagnostics);

        JmesPathCeiling effective = narrowed.EffectiveJmesPathCeiling;

        Assert.Equal(1024, effective.MaxExpressionBytes);
        Assert.Equal(1000, effective.MaxInputNodes);
        Assert.Equal(16, effective.MaxInputDepth);
        Assert.Equal(1000, effective.MaxResultNodes);
        Assert.Equal(16, effective.MaxResultDepth);
        Assert.Equal(4096, effective.MaxOutputBytes);
        Assert.Equal(5000, effective.MaxEvaluationMilliseconds);
    }

    [Fact]
    public void A_wider_jmespath_ceiling_is_refused_and_the_compiled_value_survives()
    {
        PolicySection compiled = Compiled();
        int compiledLimit = compiled.EffectiveJmesPathCeiling.MaxInputNodes > int.MaxValue
            ? int.MaxValue
            : (int)compiled.EffectiveJmesPathCeiling.MaxInputNodes;

        PolicySection result = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides { JmesPathMaxInputNodes = compiled.EffectiveJmesPathCeiling.MaxInputNodes + 1 },
            _diagnostics);

        Assert.Equal([ManifestDiagnosticCodes.LimitWidened], ErrorCodes);
        Assert.Equal(compiled.EffectiveJmesPathCeiling.MaxInputNodes, result.EffectiveJmesPathCeiling.MaxInputNodes);
        Assert.True(compiledLimit > 0);
    }

    [Fact]
    public void An_equal_value_is_accepted_and_changes_nothing()
    {
        PolicySection compiled = Compiled();

        PolicySection narrowed = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides { RedirectHopLimit = compiled.EffectiveLimits.RedirectHopLimit },
            _diagnostics);

        Assert.Empty(_diagnostics);
        Assert.Equal(compiled.EffectiveLimits.RedirectHopLimit, narrowed.EffectiveLimits.RedirectHopLimit);
    }

    [Fact]
    public void Several_bounds_narrow_independently_in_one_pass()
    {
        PolicySection narrowed = PolicyNarrowing.Apply(
            Compiled(),
            new PolicyOverrides
            {
                RedirectHopLimit = 0,
                Concurrency = 1,
                SchemaMaxDepth = 4,
                CompoundWorkflowTimeout = TimeSpan.FromSeconds(1),
                FileUploadSizeLimitBytes = 1,
            },
            _diagnostics);

        Assert.Empty(_diagnostics);
        Assert.Equal(0, narrowed.EffectiveLimits.RedirectHopLimit);
        Assert.Equal(1, narrowed.EffectiveLimits.Concurrency);
        Assert.Equal(4, narrowed.EffectiveSchemaBounds.MaxDepth);
        Assert.Equal(TimeSpan.FromSeconds(1), narrowed.EffectiveCompound.WorkflowTimeout);
        Assert.Equal(1, narrowed.EffectiveFiles.UploadSizeLimitBytes);
    }

    [Fact]
    public void Narrowing_one_bound_leaves_its_siblings_untouched()
    {
        PolicySection compiled = Compiled();

        PolicySection narrowed = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides { SchemaMaxNodes = 8 },
            _diagnostics);

        Assert.Equal(8, narrowed.EffectiveSchemaBounds.MaxNodes);
        Assert.Equal(compiled.EffectiveSchemaBounds.MaxDepth, narrowed.EffectiveSchemaBounds.MaxDepth);
        Assert.Equal(
            compiled.EffectiveSchemaBounds.MaxPropertiesPerLevel,
            narrowed.EffectiveSchemaBounds.MaxPropertiesPerLevel);
    }

    [Fact]
    public void No_overrides_returns_the_compiled_policy_unchanged()
    {
        PolicySection compiled = Compiled();

        Assert.Same(compiled, PolicyNarrowing.Apply(compiled, overrides: null, _diagnostics));
        Assert.Equal(compiled, PolicyNarrowing.Apply(compiled, PolicyOverrides.None, _diagnostics));
        Assert.Empty(_diagnostics);
    }

    // ---- widening is refused, never clamped --------------------------------------------

    [Fact]
    public void A_larger_numeric_bound_is_refused_and_the_compiled_value_survives()
    {
        PolicySection compiled = Compiled();
        long compiledLimit = compiled.EffectiveLimits.UpstreamResponseSizeLimitBytes;

        PolicySection result = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides { UpstreamResponseSizeLimitBytes = compiledLimit + 1 },
            _diagnostics);

        Assert.Equal([ManifestDiagnosticCodes.LimitWidened], ErrorCodes);
        Assert.Equal(compiledLimit, result.EffectiveLimits.UpstreamResponseSizeLimitBytes);
    }

    /// <summary>
    /// A widening attempt must not be silently clamped even though clamping would be safe.
    /// </summary>
    /// <remarks>
    /// Clamping keeps the deployment secure but leaves the operator believing a budget that is
    /// not in force, which is the state that produces a wrong incident diagnosis later.
    /// </remarks>
    [Fact]
    public void A_widening_attempt_reports_both_the_requested_and_the_compiled_value()
    {
        _ = PolicyNarrowing.Apply(
            Compiled(),
            new PolicyOverrides { RedirectHopLimit = 99 },
            _diagnostics);

        ManifestDiagnostic diagnostic = Assert.Single(_diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.LimitWidened, diagnostic.Code);
        Assert.Contains("RedirectHopLimit", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("99", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("5", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_longer_duration_is_refused()
    {
        PolicySection result = PolicyNarrowing.Apply(
            Compiled(),
            new PolicyOverrides { CompoundWorkflowTimeout = TimeSpan.FromHours(1) },
            _diagnostics);

        Assert.Equal([ManifestDiagnosticCodes.LimitWidened], ErrorCodes);
        Assert.Equal(TimeSpan.FromSeconds(120), result.EffectiveCompound.WorkflowTimeout);
    }

    /// <summary>
    /// Turning off magic-byte rejection is a widening even though it is a boolean.
    /// </summary>
    /// <remarks>
    /// The comparison normalizes every bound to a permissiveness number precisely so a
    /// boolean hardening switch cannot get the direction backwards.
    /// </remarks>
    [Fact]
    public void Disabling_a_hardening_flag_is_refused()
    {
        PolicySection result = PolicyNarrowing.Apply(
            Compiled(),
            new PolicyOverrides { FileRejectMagicMismatch = false },
            _diagnostics);

        Assert.Equal([ManifestDiagnosticCodes.LimitWidened], ErrorCodes);
        Assert.True(result.EffectiveFiles.RejectMagicMismatch);
    }

    [Fact]
    public void Enabling_a_hardening_flag_the_manifest_disabled_is_accepted()
    {
        PolicySection compiled = new(
            BaseUrl: new Uri("https://api.example.com"),
            Files: FilePolicy.Default with { RejectMagicMismatch = false });

        PolicySection result = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides { FileRejectMagicMismatch = true },
            _diagnostics);

        Assert.Empty(_diagnostics);
        Assert.True(result.EffectiveFiles.RejectMagicMismatch);
    }

    [Fact]
    public void A_widening_attempt_does_not_block_a_valid_narrowing_of_another_bound()
    {
        PolicySection result = PolicyNarrowing.Apply(
            Compiled(),
            new PolicyOverrides { RedirectHopLimit = 99, Concurrency = 2 },
            _diagnostics);

        Assert.Equal([ManifestDiagnosticCodes.LimitWidened], ErrorCodes);
        Assert.Equal(5, result.EffectiveLimits.RedirectHopLimit);
        Assert.Equal(2, result.EffectiveLimits.Concurrency);
    }

    // ---- the perimeter ------------------------------------------------------------------

    [Fact]
    public void Removing_an_origin_is_accepted()
    {
        PolicySection result = PolicyNarrowing.Apply(
            Compiled("https://api.example.com", "https://eu.example.com"),
            new PolicyOverrides { AllowedOrigins = ["https://api.example.com"] },
            _diagnostics);

        Assert.Empty(_diagnostics);
        Assert.Equal(["https://api.example.com"], result.AllowedOrigins);
    }

    [Fact]
    public void Adding_an_origin_is_refused_and_the_compiled_perimeter_survives()
    {
        PolicySection compiled = Compiled("https://api.example.com");

        PolicySection result = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides { AllowedOrigins = ["https://api.example.com", "https://attacker.example"] },
            _diagnostics);

        Assert.Equal([ManifestDiagnosticCodes.LimitWidened], ErrorCodes);
        Assert.Equal(compiled.AllowedOrigins, result.AllowedOrigins);
    }

    /// <summary>
    /// A rejected perimeter override must not partially apply.
    /// </summary>
    /// <remarks>
    /// Accepting the recognized entries and dropping the unrecognized one would silently
    /// deploy a perimeter the operator never wrote, and the operator's stated intent was
    /// refused, so keeping the compiled perimeter is the only honest outcome.
    /// </remarks>
    [Fact]
    public void A_refused_perimeter_override_applies_nothing_at_all()
    {
        PolicySection compiled = Compiled("https://a.example.com", "https://b.example.com");

        PolicySection result = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides { AllowedOrigins = ["https://a.example.com", "https://c.example.com"] },
            _diagnostics);

        Assert.Equal([ManifestDiagnosticCodes.LimitWidened], ErrorCodes);
        Assert.Equal(2, result.AllowedOrigins.Count);
    }

    [Fact]
    public void An_empty_perimeter_override_is_refused_rather_than_leaving_nothing_reachable()
    {
        PolicySection compiled = Compiled("https://api.example.com");

        PolicySection result = PolicyNarrowing.Apply(
            compiled,
            new PolicyOverrides { AllowedOrigins = [] },
            _diagnostics);

        Assert.Equal([ManifestDiagnosticCodes.OriginInvalid], ErrorCodes);
        Assert.Equal(compiled.AllowedOrigins, result.AllowedOrigins);
    }

    [Fact]
    public void Origin_matching_ignores_case_because_a_host_is_case_insensitive()
    {
        PolicySection result = PolicyNarrowing.Apply(
            Compiled("https://api.example.com"),
            new PolicyOverrides { AllowedOrigins = ["https://API.example.com"] },
            _diagnostics);

        Assert.Empty(_diagnostics);
        Assert.Single(result.AllowedOrigins);
    }

    [Fact]
    public void An_added_origin_is_echoed_truncated()
    {
        string hostile = "https://" + new string('a', 200) + ".example";

        _ = PolicyNarrowing.Apply(
            Compiled("https://api.example.com"),
            new PolicyOverrides { AllowedOrigins = [hostile] },
            _diagnostics);

        ManifestDiagnostic diagnostic = Assert.Single(_diagnostics);

        Assert.DoesNotContain(hostile, diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains(DiagnosticText.TruncationMarker, diagnostic.Message, StringComparison.Ordinal);
    }
}
