namespace MCPiler.Engine.Authentication;

/// <summary>
/// Raised when a manifest names an authentication strategy, configuration or signer kind this
/// Engine build cannot execute.
/// </summary>
/// <remarks>
/// Distinct from <see cref="Execution.CredentialUnavailableException"/>: that one means a
/// credential the Engine knows how to use could not be obtained, while this one means the Engine
/// does not know how to use the thing at all. Conflating them would tell an operator to check a
/// secret when the actual remedy is a different deployment of Engine.
/// </remarks>
public sealed class UnsupportedAuthenticationStrategyException : Exception
{
    /// <summary>Creates a refusal naming what is unsupported.</summary>
    /// <param name="message">What is unsupported and, when known, what is supported instead.</param>
    /// <param name="inner">The underlying cause, when the failure wraps one.</param>
    public UnsupportedAuthenticationStrategyException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

/// <summary>
/// Raised when a resolved authentication plan cannot be applied for the reason the plan itself
/// states: an origin outside the plan's scope, a missing slot, or material that does not match
/// the strategy's own contract.
/// </summary>
/// <remarks>
/// Carries the same non-disclosure property as the credential family: the message names the
/// profile and the failure, never a value.
/// </remarks>
public sealed class AuthenticationPlanException : Exception
{
    /// <summary>Creates a refusal naming the profile whose plan cannot be applied.</summary>
    /// <param name="profileId">The manifest-local profile id.</param>
    /// <param name="message">What about the plan cannot be applied, without any value.</param>
    /// <param name="inner">The underlying cause, when the failure wraps one.</param>
    public AuthenticationPlanException(string profileId, string message, Exception? inner = null)
        : base($"Authentication profile '{profileId}': {message}", inner)
    {
        ProfileId = profileId;
    }

    /// <summary>The profile whose plan could not be applied.</summary>
    public string ProfileId { get; }
}
