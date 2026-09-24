using System.Text.Json.Nodes;

using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The closed output-projection union a format-4 <c>transformedHttp</c> binding may carry.
/// </summary>
/// <remarks>
/// <para>
/// Absence is passthrough, and that is the only way to say it: there is no <c>none</c> member,
/// because a third kind that means "do nothing" would give the format two spellings for what
/// an omitted member already says.
/// </para>
/// <para>
/// Exactly one variant is carried, and neither can contain the other. A program that ran and
/// then an expression over its output is a composition the profile does not define, and the
/// representation does not offer a place to write it: the binding has one projection, and the
/// projection has one kind.
/// </para>
/// </remarks>
public abstract record ManifestOutputProjection
{
    /// <summary>The wire discriminator this variant is written with.</summary>
    public abstract string Kind { get; }

    /// <summary>The wire names of the kinds a format-4 document may select.</summary>
    public static IReadOnlyList<string> KindNames { get; } = [TransformProgramVariant.KindName, JmesPathVariant.KindName];

    /// <summary>The output transformation program, carried verbatim for its own validator.</summary>
    /// <param name="Program">
    /// The program grammar is a separate versioned contract with its own validator and its own
    /// diagnostic codes, so it is held as JSON rather than mapped here.
    /// </param>
    public sealed record TransformProgramVariant(JsonObject Program) : ManifestOutputProjection
    {
        /// <summary>The wire discriminator value.</summary>
        public const string KindName = "transformProgram";

        /// <inheritdoc />
        public override string Kind => KindName;
    }

    /// <summary>
    /// A profile-1 JMESPath projection carrying its own explicitly declared limits.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The limits are mapped into <see cref="JmesPathLimits"/> here rather than carried as
    /// JSON, because unlike a transformation program this is not a nested grammar with its own
    /// validator: the seven numbers are the whole of the contract, and a shape that is not
    /// seven positive numbers is not a projection. A reader that carried them verbatim would
    /// leave every consumer to re-decide what a valid limit object is.
    /// </para>
    /// <para>
    /// Mapping is not acceptance. Whether the declared values fit the policy ceiling is a
    /// cross-section question and belongs to the validator, which can answer it once.
    /// </para>
    /// </remarks>
    /// <param name="LanguageVersion">The declared profile version.</param>
    /// <param name="Expression">The declared expression.</param>
    /// <param name="Limits">The declared limits.</param>
    public sealed record JmesPathVariant(
        int LanguageVersion,
        string Expression,
        JmesPathLimits Limits) : ManifestOutputProjection
    {
        /// <summary>The wire discriminator value.</summary>
        public const string KindName = "jmespath";

        /// <inheritdoc />
        public override string Kind => KindName;
    }
}
