using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution;

/// <summary>How credential references are allowed to be resolved.</summary>
/// <param name="AllowInlineCredentials">
/// Whether a credential whose value is written into the manifest may be used.
/// </param>
/// <remarks>
/// Inline material is refused by default and the refusal has to be lifted deliberately. A
/// manifest is a document that gets copied, diffed, attached to an issue and committed; a
/// secret inside one has already been disclosed by the time it is executed. The flag exists
/// because a local experiment against a throwaway endpoint is a real use, not because inline
/// material is an acceptable production shape.
/// </remarks>
public sealed record SecretResolutionOptions(bool AllowInlineCredentials = false)
{
    /// <summary>The shipped settings: inline material refused.</summary>
    public static SecretResolutionOptions Default { get; } = new();
}

/// <summary>
/// Turns the credential references an executing binding names into values.
/// </summary>
/// <remarks>
/// <para>
/// Every decision is here and every read is elsewhere. What a reference means, which
/// declarations are in scope, whether inline material is admissible, whether an empty value
/// counts, how much of a file was an artifact of writing it, and what a failure is allowed to
/// say are all product semantics; the environment and the filesystem are reached through
/// <see cref="ISecretSource"/>, which knows none of it.
/// </para>
/// <para>
/// Every failure is reported with the reference's kind and name and nothing else. Not a
/// truncated value, not a length, not the first characters, not the file's contents on the
/// theory that the read failed anyway: a diagnostic that leaked a fragment of a secret in order
/// to explain why it could not be read would have disclosed the thing the reference exists to
/// keep out of the document.
/// </para>
/// <para>
/// The failure cases are distinguished from each other because they call for different
/// corrections. A variable that is not set is a deployment that forgot it; a variable set to an
/// empty string is a deployment that thinks it supplied it; a missing file is a path mistake;
/// an unreadable file is a permission mistake. One message covering all four would leave an
/// operator guessing which.
/// </para>
/// </remarks>
public sealed class ManifestSecretResolver : IManifestSecretResolver
{
    private readonly SecretResolutionOptions _options;
    private readonly ISecretSource _source;
    private readonly GenerationSecretSource? _providers;

    /// <summary>Creates a resolver refusing inline material and reading the real host.</summary>
    public ManifestSecretResolver()
        : this(SecretResolutionOptions.Default, new HostSecretSource())
    {
    }

    /// <summary>Creates a resolver under <paramref name="options"/> reading the real host.</summary>
    public ManifestSecretResolver(SecretResolutionOptions options)
        : this(options, new HostSecretSource())
    {
    }

    /// <summary>Creates a resolver under <paramref name="options"/> reading <paramref name="source"/>.</summary>
    public ManifestSecretResolver(SecretResolutionOptions options, ISecretSource source)
        : this(options, source, providers: null)
    {
    }

    /// <summary>
    /// Creates a resolver that also reads <paramref name="providers"/>.
    /// </summary>
    /// <param name="options">Which references are admissible.</param>
    /// <param name="source">Where environment and file references are read.</param>
    /// <param name="providers">
    /// The active generation's in-memory provider values, or null for a process that runs no
    /// generation. A <c>fromProvider</c> reference in a manifest this resolver reads without a
    /// source is a deployment fault: standalone loading refuses such a manifest, so reaching
    /// this state means the two halves of the mode decision disagree.
    /// </param>
    public ManifestSecretResolver(
        SecretResolutionOptions options,
        ISecretSource source,
        GenerationSecretSource? providers)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(source);

        _options = options;
        _source = source;
        _providers = providers;
    }

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<ResolvedCredential>> ResolveAsync(
        CredentialsSection credentials,
        IReadOnlyList<string> credentialRefs,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(credentialRefs);

        if (credentialRefs.Count == 0)
        {
            return [];
        }

        // The same id named twice is one credential. Deduplicating before resolving means a
        // duplicate costs one read rather than two, and — for a file reference — cannot produce
        // two different values from one declaration.
        var wanted = new HashSet<string>(credentialRefs, StringComparer.Ordinal);

        var resolved = new List<ResolvedCredential>(wanted.Count);

        // Declaration order, so the result is stable regardless of how the binding listed them.
        foreach (var declaration in credentials.Credentials)
        {
            if (!wanted.Remove(declaration.Id))
            {
                // Declared and not referenced. Never read: an unreferenced reference whose
                // variable is unset is not this execution's problem, and reading it would make
                // it one.
                continue;
            }

            resolved.Add(new ResolvedCredential(
                declaration,
                await ReadAsync(declaration, cancellationToken).ConfigureAwait(false)));
        }

        if (wanted.Count > 0)
        {
            var missing = wanted.OrderBy(static id => id, StringComparer.Ordinal).First();
            throw new CredentialUnavailableException(
                missing,
                "the executing binding references it, but the manifest declares no credential with that id.");
        }

        return resolved;
    }

    private async ValueTask<string> ReadAsync(ManifestCredential declaration, CancellationToken cancellationToken)
    {
        var reference = declaration.Value;
        var described = reference.ToString();

        if (reference.IsInline)
        {
            if (!_options.AllowInlineCredentials)
            {
                throw new CredentialUnavailableException(
                    declaration.Id,
                    $"{described} is inline material, which is refused unless inline credentials are explicitly allowed.");
            }

            return NonEmpty(declaration, reference.Inline!, described);
        }

        if (reference.FromEnv is { } variable)
        {
            var value = _source.ReadEnvironmentVariable(variable);

            if (value is null)
            {
                throw new CredentialUnavailableException(
                    declaration.Id,
                    $"{described} names an environment variable that is not set.");
            }

            // Returned verbatim. A credential is an opaque string, and trimming it would
            // silently send something other than what the deployment supplied — which fails
            // upstream with an authentication error that points nowhere near the cause.
            return NonEmpty(declaration, value, described);
        }

        if (reference.FromFile is { } path)
        {
            var read = await _source.ReadFileAsync(path, cancellationToken).ConfigureAwait(false);

            var contents = read.Status switch
            {
                SecretFileStatus.Read => read.Contents!,

                // Distinguished from a missing file: the path exists and points at the wrong
                // kind of thing, which is a different mistake with a different correction.
                SecretFileStatus.NotAFile => throw new CredentialUnavailableException(
                    declaration.Id,
                    $"{described} names a directory rather than a file."),
                SecretFileStatus.NotFound => throw new CredentialUnavailableException(
                    declaration.Id,
                    $"{described} names a file that does not exist."),
                _ => throw new CredentialUnavailableException(
                    declaration.Id,
                    $"{described} names a file that could not be read."),
            };

            return NonEmpty(declaration, TrimSingleTrailingNewline(contents), described);
        }

        if (reference.FromProvider is { } key)
        {
            if (_providers is null)
            {
                // A managed reference in a process with no managed generation. Standalone loading
                // refuses such a manifest, so this is a mode disagreement rather than a
                // deployment mistake: resolving it from anywhere else would defeat the reason
                // provider values are delivered separately.
                throw new CredentialUnavailableException(
                    declaration.Id,
                    $"{described} names a managed provider value, and this process has no active managed generation.");
            }

            if (!_providers.TryResolve(key, out var value))
            {
                // The key is echoed because a key is configuration, not a secret, and an operator
                // whose generation delivered a different key needs to see which one was asked
                // for. The delivered keys are not echoed: that would describe another
                // generation's secret set to whoever controls this manifest.
                throw new CredentialUnavailableException(
                    declaration.Id,
                    $"{described} names a provider value the active generation did not deliver.");
            }

            return NonEmpty(declaration, value, described);
        }

        throw new CredentialUnavailableException(
            declaration.Id,
            $"{described} names no resolvable source.");
    }

    /// <summary>
    /// Removes exactly one trailing line ending, and no other whitespace.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every text editor and most secret-mounting mechanisms terminate the last line, so a
    /// token written to a file usually arrives with a newline that was never part of it. One is
    /// removed because that one is an artifact of how files are written.
    /// </para>
    /// <para>
    /// Nothing else is. A second newline, a leading space, or a trailing tab is content as far
    /// as this code can tell, and a credential that legitimately ends in whitespace would
    /// otherwise be silently mangled into one that fails upstream for no visible reason.
    /// </para>
    /// </remarks>
    private static string TrimSingleTrailingNewline(string contents)
    {
        if (contents.EndsWith("\r\n", StringComparison.Ordinal))
        {
            return contents[..^2];
        }

        if (contents.EndsWith('\n') || contents.EndsWith('\r'))
        {
            return contents[..^1];
        }

        return contents;
    }

    private static string NonEmpty(ManifestCredential declaration, string value, string described)
    {
        if (value.Length == 0)
        {
            // An empty credential would be applied as a well-formed header carrying nothing,
            // and the upstream would answer with an authentication error naming neither the
            // reference nor the deployment mistake behind it.
            throw new CredentialUnavailableException(
                declaration.Id,
                $"{described} resolved to an empty value.");
        }

        return value;
    }
}
