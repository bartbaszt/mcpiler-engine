using System.Text;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution;

/// <summary>
/// Places resolved credential material into a compiled request.
/// </summary>
/// <remarks>
/// <para>
/// This reaches nothing. It takes a compiled request and values that have already been
/// resolved, and returns the request that should be sent. That makes the whole of "where does
/// this credential go" assertable without an environment, a file or a socket, which is the
/// part most worth asserting: a credential written into the wrong place either fails visibly
/// upstream or, worse, succeeds while being logged by a proxy that had no business seeing it.
/// </para>
/// <para>
/// Two credentials contending for one destination are refused rather than resolved by order.
/// The validator already rejects that shape for a binding it can see, so reaching this refusal
/// means something got past it; picking a winner here would make which secret reached the
/// upstream depend on how the reference list happened to be sorted.
/// </para>
/// </remarks>
public static class CredentialApplier
{
    /// <summary>
    /// Returns <paramref name="request"/> with <paramref name="credentials"/> applied and every
    /// credential-bearing header marked sensitive for redirects.
    /// </summary>
    /// <exception cref="CredentialUnavailableException">
    /// A basic pair is incomplete, a slot is not one this scheme defines, or two credentials
    /// target one destination.
    /// </exception>
    public static UpstreamRequest Apply(CompiledRequest request, IReadOnlyList<ResolvedCredential> credentials)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(credentials);

        var headers = new Dictionary<string, string[]>(request.Headers, StringComparer.OrdinalIgnoreCase);
        var sensitive = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var writtenBy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var cookies = new List<string>();
        var query = new List<KeyValuePair<string, string>>();

        string? basicUser = null;
        string? basicPassword = null;
        string? basicId = null;

        foreach (var credential in credentials)
        {
            var declaration = credential.Declaration;

            switch (declaration.Scheme)
            {
                case CredentialScheme.Basic:
                    basicId ??= declaration.Id;

                    if (string.Equals(declaration.Slot, ManifestCredential.BasicUsernameSlot, StringComparison.Ordinal))
                    {
                        basicUser = credential.Value;
                    }
                    else if (string.Equals(declaration.Slot, ManifestCredential.BasicPasswordSlot, StringComparison.Ordinal))
                    {
                        basicPassword = credential.Value;
                    }
                    else
                    {
                        throw new CredentialUnavailableException(
                            declaration.Id,
                            $"a basic credential names slot '{declaration.Slot}', which is neither " +
                            $"'{ManifestCredential.BasicUsernameSlot}' nor '{ManifestCredential.BasicPasswordSlot}'.");
                    }

                    break;

                case CredentialScheme.Bearer:
                    // The slot is the header name, which is Authorization in every shape the
                    // format has a reason to produce. The value is prefixed here rather than
                    // stored prefixed, so what a deployment supplies is the token and not a
                    // token plus a scheme word it has to remember to include.
                    Write(HeaderName(declaration), $"Bearer {credential.Value}", declaration);
                    break;

                case CredentialScheme.Header:
                    Write(declaration.Slot, credential.Value, declaration);
                    break;

                case CredentialScheme.ApiKey:
                    switch (declaration.EffectiveLocation)
                    {
                        case CredentialLocation.Query:
                            query.Add(new KeyValuePair<string, string>(declaration.Slot, credential.Value));
                            break;

                        case CredentialLocation.Cookie:
                            Reserve($"cookie:{declaration.Slot}", declaration.Id);
                            cookies.Add($"{declaration.Slot}={credential.Value}");
                            break;

                        default:
                            Write(declaration.Slot, credential.Value, declaration);
                            break;
                    }

                    break;

                default:
                    // Not a fall-through. A scheme nobody taught this method about would
                    // otherwise be silently dropped, and the request would go out
                    // unauthenticated while every declaration looked satisfied.
                    throw new CredentialUnavailableException(
                        declaration.Id,
                        $"credential scheme '{declaration.Scheme}' has no application rule.");
            }

            if (declaration.IsRedirectSensitiveHeader)
            {
                sensitive.Add(SensitiveHeaderName(declaration));
            }
        }

        ApplyBasic(basicId, basicUser, basicPassword);

        if (cookies.Count > 0)
        {
            // Merged rather than replacing: the compiled request may already carry cookies from
            // declared parameters, and a credential cookie is an addition to them.
            var existing = headers.TryGetValue(ManifestCredential.CookieHeader, out var current) ? current : [];
            headers[ManifestCredential.CookieHeader] = [string.Join("; ", existing.Concat(cookies))];
        }

        return new UpstreamRequest
        {
            Method = request.Method,
            Uri = AppendQuery(request.ExactUrl, query),
            Headers = headers,
            Body = request.Body,
            BodyMediaType = request.BodyMediaType,
            SensitiveHeaders = sensitive.ToArray(),
        };

        void Write(string name, string value, ManifestCredential declaration)
        {
            Reserve($"header:{name}", declaration.Id);
            headers[name] = [value];
        }

        void Reserve(string destination, string credentialId)
        {
            if (writtenBy.TryGetValue(destination, out var first))
            {
                throw new CredentialUnavailableException(
                    credentialId,
                    $"it targets '{destination}', which credential '{first}' already wrote. Which " +
                    "value reached the upstream service would depend on reference order.");
            }

            writtenBy[destination] = credentialId;
        }

        void ApplyBasic(string? id, string? user, string? password)
        {
            if (user is null && password is null)
            {
                return;
            }

            if (user is null || password is null)
            {
                // Half a pair produces a well-formed header carrying an empty user or an empty
                // password: a silently wrong credential rather than a refusal.
                throw new CredentialUnavailableException(
                    id!,
                    "a basic credential pair is incomplete; both the username and the password half must be referenced.");
            }

            Reserve($"header:{ManifestCredential.AuthorizationHeader}", id!);

            headers[ManifestCredential.AuthorizationHeader] =
                [$"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}"))}"];

            sensitive.Add(ManifestCredential.AuthorizationHeader);
        }
    }

    /// <summary>The header a credential writes, or the empty string when it writes none.</summary>
    private static string HeaderName(ManifestCredential declaration)
        => declaration.Slot.Length == 0 ? ManifestCredential.AuthorizationHeader : declaration.Slot;

    /// <summary>
    /// The header name to mark sensitive for a credential that writes one.
    /// </summary>
    /// <remarks>
    /// A basic credential's slot is a half-name, not a header, so it maps to the header the
    /// pair produces. A cookie-located key maps to the cookie header rather than to the cookie
    /// name, because stripping happens per header.
    /// </remarks>
    private static string SensitiveHeaderName(ManifestCredential declaration) => declaration.Scheme switch
    {
        CredentialScheme.Basic => ManifestCredential.AuthorizationHeader,
        CredentialScheme.ApiKey when declaration.EffectiveLocation == CredentialLocation.Cookie
            => ManifestCredential.CookieHeader,
        _ => HeaderName(declaration),
    };

    /// <summary>
    /// Appends credential query parameters to the compiled URL.
    /// </summary>
    /// <remarks>
    /// The compiled exact URL is extended as text rather than rebuilt through a URI builder,
    /// because the compiler already decided the precise encoding of everything before the
    /// addition and a rebuild is an opportunity to re-encode it differently.
    /// </remarks>
    private static Uri AppendQuery(string exactUrl, IReadOnlyList<KeyValuePair<string, string>> query)
    {
        if (query.Count == 0)
        {
            return new Uri(exactUrl, UriKind.Absolute);
        }

        var separator = exactUrl.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        var appended = string.Join(
            '&',
            query.Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));

        return new Uri(exactUrl + separator + appended, UriKind.Absolute);
    }
}
