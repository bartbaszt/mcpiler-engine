namespace MCPiler.Engine.Runtime;

/// <summary>
/// How one surface introduces itself to a client that connects to it.
/// </summary>
/// <remarks>
/// <para>
/// A deployable serves several Manifests at once, so the identity a client is handed has to
/// come from the Manifest it addressed. Presenting the executable's own name and version
/// instead would tell every client the same thing no matter which server it reached, which is
/// the one question this field exists to answer.
/// </para>
/// <para>
/// Built here rather than by a transport, and complete, so mapping it onto a protocol type is
/// a field copy with nothing left to decide. A transport that had to choose what to say when
/// a Manifest declares no version would be choosing product behaviour.
/// </para>
/// </remarks>
/// <param name="Name">The server name the Manifest declares. Always present.</param>
/// <param name="Version">
/// The version the Manifest declares, or the empty string when it declares none. Empty says
/// "not stated"; substituting the engine's own version would state something untrue about the
/// server, and inventing a placeholder would state something untrue about the Manifest.
/// </param>
/// <param name="Title">
/// The surface's authored display name, or <c>null</c> when the Manifest authored none. A
/// surface without a name has only a slug, and a slug is already in the address the client
/// used, so repeating it as a title says nothing.
/// </param>
/// <param name="Description">The server description the Manifest declares, if any.</param>
public sealed record ServerIdentity(string Name, string Version, string? Title, string? Description)
{
    /// <summary>
    /// The identity of a surface that was constructed rather than mounted.
    /// </summary>
    /// <remarks>
    /// Named nothing rather than named something plausible. A surface built by hand
    /// advertises nothing and reaches nothing; identifying as nothing keeps it consistent.
    /// </remarks>
    internal static ServerIdentity Undeclared { get; } = new(string.Empty, string.Empty, null, null);
}
