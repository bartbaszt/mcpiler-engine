namespace MCPiler.Engine.Runtime.Projection;

/// <summary>What one load-time expression check concluded.</summary>
public enum ProjectionExpressionValidityStatus
{
    /// <summary>The expression is valid profile 1, or fails only in a data-dependent family.</summary>
    Valid,

    /// <summary>The expression is invalid: a compile-phase failure family.</summary>
    Invalid,

    /// <summary>The check could not be performed in confined isolation.</summary>
    Unavailable,
}

/// <summary>
/// What one load-time expression check concluded, with the failure when it did not pass.
/// </summary>
/// <param name="Status">The conclusion.</param>
/// <param name="Failure">The classified failure, or <c>null</c> when the expression is valid.</param>
public sealed record ProjectionExpressionValidity(
    ProjectionExpressionValidityStatus Status,
    JmesPathFailure? Failure)
{
    /// <summary>The expression is valid profile 1.</summary>
    public static ProjectionExpressionValidity Valid { get; } = new(ProjectionExpressionValidityStatus.Valid, Failure: null);

    /// <summary>The expression is invalid.</summary>
    public static ProjectionExpressionValidity Invalid(JmesPathFailure failure)
        => new(ProjectionExpressionValidityStatus.Invalid, failure);

    /// <summary>The check could not run in confinement.</summary>
    public static ProjectionExpressionValidity Unavailable(JmesPathFailure failure)
        => new(ProjectionExpressionValidityStatus.Unavailable, failure);
}

/// <summary>
/// The only way a load-time expression check may reach an evaluator.
/// </summary>
/// <remarks>
/// <para>
/// Validating an expression means compiling it, and compiling it in the serving process is the
/// one thing the profile forbids. So the library asks, and whichever host is loading answers —
/// in the shipped host, by running the expression against a placeholder inside the same
/// short-lived, OS-confined worker every evaluation uses. A host without that machinery reports
/// <see cref="ProjectionExpressionValidityStatus.Unavailable"/>, and the library refuses the
/// manifest rather than interpreting the expression itself.
/// </para>
/// <para>
/// The call is synchronous because manifest loading is: a Manifest is read, validated and
/// mounted before a listener exists, and giving the load path an async surface would ripple
/// through every caller to say nothing about the manifest. An implementation performs its
/// bounded wait internally and returns a classified result; it never blocks indefinitely and
/// never falls back in process.
/// </para>
/// </remarks>
public interface IProjectionExpressionValidator
{
    /// <summary>Classifies one profile-1 expression without evaluating it in this process.</summary>
    /// <param name="expression">The authored expression.</param>
    /// <param name="limits">The projection's declared limits.</param>
    ProjectionExpressionValidity Validate(string expression, JmesPathLimits limits);
}
