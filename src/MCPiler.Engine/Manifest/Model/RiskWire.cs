namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The wire vocabulary for a bounded risk classification, and the deterministic fallback
/// used when a manifest declares no risk for an operation.
/// </summary>
/// <remarks>
/// <para>
/// A risk value is a comma-joined set of camel-case class names in ordinal order, or
/// <c>none</c> when no class applies. The joined form is what discovery results render and
/// what an aggregate risk report reads, so the ordering has to be a property of the format
/// rather than of whichever collection produced it.
/// </para>
/// <para>
/// Engine never runs risk detection over a contract. Authoring-side detection, operator
/// overrides, and who set them are Studio state; only the resolved value crosses the
/// boundary. The fallback here is narrower on purpose: it reads the HTTP method and nothing
/// else, so a hand-authored manifest that declares no risk still gets a sane, explainable
/// value instead of silently claiming that nothing is risky.
/// </para>
/// </remarks>
public static class RiskWire
{
    /// <summary>The value meaning "no risk classes apply".</summary>
    public const string None = AgentOperationEntry.NoRisk;

    /// <summary>The operation does not modify upstream state.</summary>
    public const string ReadOnly = "readOnly";

    /// <summary>The operation modifies upstream state.</summary>
    public const string Mutating = "mutating";

    /// <summary>The operation may irreversibly remove or overwrite state.</summary>
    public const string Destructive = "destructive";

    /// <summary>Repeating the call with the same arguments has the same effect.</summary>
    public const string Idempotent = "idempotent";

    /// <summary>The operation reaches a system outside the caller's control.</summary>
    public const string OpenWorld = "openWorld";

    /// <summary>The operation should be confirmed before it is repeated automatically.</summary>
    public const string RequiresConfirmation = "requiresConfirmation";

    /// <summary>The operation handles sensitive data.</summary>
    public const string Sensitive = "sensitive";

    /// <summary>The classes an operation may be tagged with.</summary>
    public static IReadOnlySet<string> Classes { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        ReadOnly,
        Mutating,
        Destructive,
        Idempotent,
        OpenWorld,
        RequiresConfirmation,
        Sensitive,
    };

    /// <summary>Renders a set of classes in the canonical wire form.</summary>
    /// <param name="classes">The classes to render. Unknown names are kept, not dropped.</param>
    public static string Write(IEnumerable<string> classes)
    {
        ArgumentNullException.ThrowIfNull(classes);

        var ordered = classes
            .Where(static value => !string.IsNullOrEmpty(value))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal)
            .ToList();

        return ordered.Count == 0 ? None : string.Join(',', ordered);
    }

    /// <summary>Splits a wire value into its classes.</summary>
    /// <param name="risk">The wire value. Null, empty, or <c>none</c> yields no classes.</param>
    public static IReadOnlyList<string> Read(string? risk)
    {
        if (string.IsNullOrWhiteSpace(risk) || string.Equals(risk, None, StringComparison.Ordinal))
        {
            return [];
        }

        return risk.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// Derives a risk value from an HTTP method alone.
    /// </summary>
    /// <remarks>
    /// Every operation reaches an external system, so <c>openWorld</c> always applies. The
    /// rest follows method semantics: a body-bearing method mutates, <c>DELETE</c> and
    /// <c>PATCH</c> may destroy, <c>PUT</c> and <c>DELETE</c> are idempotent, and anything
    /// that mutates without being provably safe asks for confirmation. An unrecognised or
    /// absent method yields <c>openWorld</c> only — it claims neither safety nor danger.
    /// </remarks>
    /// <param name="method">The HTTP method, in any casing.</param>
    public static string FromMethod(string? method)
    {
        var normalized = method?.Trim().ToUpperInvariant();
        var classes = new List<string> { OpenWorld };

        var mutating = normalized is "POST" or "PUT" or "PATCH" or "DELETE";
        var destructive = normalized is "DELETE" or "PATCH";

        if (mutating)
        {
            classes.Add(Mutating);
        }
        else if (normalized is "GET" or "HEAD" or "OPTIONS")
        {
            classes.Add(ReadOnly);
        }

        if (destructive)
        {
            classes.Add(Destructive);
            classes.Add(Mutating);
            classes.Add(RequiresConfirmation);
        }
        else if (normalized is "POST" or "PUT" or "PATCH")
        {
            classes.Add(RequiresConfirmation);
        }

        if (normalized is "PUT" or "DELETE")
        {
            classes.Add(Idempotent);
        }

        return Write(classes);
    }

    /// <summary>
    /// Returns the declared risk when present, otherwise the value derived from the method.
    /// </summary>
    /// <param name="declared">The risk declared on the operation, if any.</param>
    /// <param name="method">The HTTP method of the bound operation, if it can be resolved.</param>
    public static string Resolve(string? declared, string? method)
        => declared ?? FromMethod(method);

    /// <summary>Extracts the method from an execution key of the form <c>METHOD path</c>.</summary>
    /// <param name="operationKey">The execution key.</param>
    public static string? MethodOfKey(string? operationKey)
    {
        if (string.IsNullOrEmpty(operationKey))
        {
            return null;
        }

        var space = operationKey.IndexOf(' ', StringComparison.Ordinal);
        return space > 0 ? operationKey[..space] : null;
    }
}
