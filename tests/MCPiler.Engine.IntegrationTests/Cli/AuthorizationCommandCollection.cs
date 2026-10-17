using Xunit;

namespace MCPiler.Engine.IntegrationTests.Cli;

/// <summary>
/// Serializes the test classes that drive the process-wide authorization-attempt registry.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="MCPiler.Engine.Runtime.StandaloneAuthorization"/> tracks live attempts per
/// <c>(mount, profile)</c> for the whole process, and <c>auth status</c> reports <c>authorizing</c>
/// while one is live. That is the correct behaviour for the in-host operator channel, where one
/// process owns both verbs, and it is also what a CLI invocation sees when another invocation in
/// the same process is waiting for a callback.
/// </para>
/// <para>
/// A test suite runs many invocations in one process, so two classes that use the same mount and
/// profile id for the same purpose are not independent: a class that holds an attempt open while
/// awaiting a callback changes what another class's status assertion observes, even though neither
/// class touches a shared field. The flake it produced was remote from its cause - a status test
/// reporting <c>authorizing</c> instead of <c>configured</c> or <c>faulted</c>, and an exit code that
/// was <c>Success</c> where the test expected <c>Failure</c>.
/// </para>
/// <para>
/// Membership therefore follows the identity, not the file: a class joins this collection when it
/// starts an attempt that outlives its own verb, or reads a status that another class's live
/// attempt can change. Collections still run in parallel with everything else.
/// </para>
/// </remarks>
[CollectionDefinition(Name)]
public sealed class AuthorizationCommandCollection
{
    /// <summary>The collection name shared by the classes that must not run concurrently.</summary>
    public const string Name = "authorization-commands";
}
