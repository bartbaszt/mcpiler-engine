using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution;

/// <summary>One declared credential together with the value its reference resolved to.</summary>
/// <remarks>
/// The declaration travels with the value because applying a credential needs the scheme, the
/// slot and the location, and re-looking those up by id at the point of application would be a
/// second chance to look up the wrong one.
/// </remarks>
/// <param name="Declaration">The credential as the manifest declared it.</param>
/// <param name="Value">The resolved material.</param>
public sealed record ResolvedCredential(ManifestCredential Declaration, string Value)
{
    /// <summary>The declared credential id.</summary>
    public string Id => Declaration.Id;

    /// <summary>
    /// The reference as text: its kind and its name, never its value.
    /// </summary>
    /// <remarks>
    /// This is what a diagnostic is allowed to say. It exists on the resolved credential as
    /// well as on the unresolved one so that a failure occurring after resolution has the same
    /// safe description available and no reason to reach for the value.
    /// </remarks>
    public string ReferenceDescription => Declaration.Value.ToString();
}

/// <summary>
/// Turns the credential references an executing binding names into resolved values.
/// </summary>
/// <remarks>
/// <para>
/// Reading an environment variable and reading a file are host access, which is why this is a
/// port rather than a method. What is NOT delegated is which credentials get resolved: the
/// caller passes the executing binding's reference list, and an implementation resolves those
/// and nothing else.
/// </para>
/// <para>
/// That restriction is the whole point of the interface taking a reference list rather than a
/// section. A resolver handed the whole credentials section would read every declared secret in
/// order to execute an operation that uses one of them, so a manifest declaring five
/// credentials could not be executed at all unless all five happened to be present.
/// </para>
/// </remarks>
public interface IManifestSecretResolver
{
    /// <summary>
    /// Resolves exactly the credentials <paramref name="credentialRefs"/> names, in the order
    /// they were declared.
    /// </summary>
    /// <exception cref="CredentialUnavailableException">
    /// A named credential is not declared, its reference cannot be read, or it resolves to
    /// nothing. The exception names the reference kind and the reference name and never any
    /// part of a value.
    /// </exception>
    ValueTask<IReadOnlyList<ResolvedCredential>> ResolveAsync(
        CredentialsSection credentials,
        IReadOnlyList<string> credentialRefs,
        CancellationToken cancellationToken);
}
