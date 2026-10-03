using System;

namespace MCPiler.Engine.Runtime.Managed;

/// <summary>
/// Which part of the external-resource contract a candidate value violates.
/// </summary>
/// <remarks>
/// The numeric order is the evaluation order. A value can break more than one rule, so the order
/// is part of the contract rather than an implementation detail: Platform and Engine must name the
/// same rule for the same value, or an operator comparing the two refusals is comparing two
/// different claims about one value. The authoritative sequence is published in the shared
/// external-resource contract corpus and is replayed by both repositories.
/// </remarks>
public enum ExternalResourceViolation
{
    /// <summary>The value satisfies the contract.</summary>
    None = 0,

    /// <summary>The value is absent, empty, or whitespace only.</summary>
    Blank,

    /// <summary>The value is longer than <see cref="ExternalResourceContract.MaxLength"/> characters.</summary>
    TooLong,

    /// <summary>The value does not write a valid absolute URI.</summary>
    NotAbsolute,

    /// <summary>The URI scheme is not exactly <c>https</c>.</summary>
    WrongScheme,

    /// <summary>The URI carries a query.</summary>
    HasQuery,

    /// <summary>The URI carries a fragment.</summary>
    HasFragment,

    /// <summary>A userinfo component was written into the URI authority.</summary>
    HasUserInfo,
}

/// <summary>
/// The one place that decides whether an external MCP resource identity is acceptable.
/// </summary>
/// <remarks>
/// <para>
/// An external resource is an OAuth protected-resource identifier that selects one surface. It is
/// opaque identity rather than a URL to dereference, so nothing here normalizes, rewrites, or
/// canonicalises it: the accepted value is compared byte-exactly everywhere downstream. What this
/// contract does is refuse values that cannot serve as an identity at all, or that would carry
/// something other than an identity.
/// </para>
/// <para>
/// This type exists so that exactly one predicate governs the contract. When the rule lived in each
/// call site, the two copies could drift and a value one refused the other accepted, which is a
/// defect neither side's own tests can see. Platform carries its own copy of the same contract and
/// the two are proven to agree by replaying one authored corpus rather than by two independent
/// chains of assertions.
/// </para>
/// <para>
/// Seven rules, evaluated in this order: non-blank, length, absolute, scheme, query, fragment,
/// userinfo.
/// </para>
/// </remarks>
public static class ExternalResourceContract
{
    /// <summary>
    /// The inclusive maximum length, in characters, of an external resource.
    /// </summary>
    /// <remarks>
    /// The bound has to exist somewhere both sides agree on. Storage column declarations do not
    /// provide it: SQLite stores TEXT unlengthened and applies no truncation, so a row longer than
    /// the declared maximum is accepted by the provider and read back intact. Without this bound the
    /// producing side can commit an authoritative value the consuming side refuses, having already
    /// published it.
    /// </remarks>
    public const int MaxLength = 2048;

    /// <summary>
    /// Evaluates <paramref name="resource"/> and reports the first rule it violates, or
    /// <see cref="ExternalResourceViolation.None"/> when it satisfies the contract.
    /// </summary>
    /// <param name="resource">The candidate external resource identity.</param>
    /// <returns>The violated rule, or <see cref="ExternalResourceViolation.None"/>.</returns>
    public static ExternalResourceViolation Evaluate(string? resource)
    {
        if (string.IsNullOrWhiteSpace(resource))
        {
            return ExternalResourceViolation.Blank;
        }

        if (resource.Length > MaxLength)
        {
            return ExternalResourceViolation.TooLong;
        }

        if (!HasWrittenHttpScheme(resource, Uri.UriSchemeHttps, out bool writesHttpsScheme))
        {
            return ExternalResourceViolation.NotAbsolute;
        }

        if (!writesHttpsScheme)
        {
            return ExternalResourceViolation.WrongScheme;
        }

        int queryStart = resource.IndexOf('?');
        int fragmentStart = resource.IndexOf('#');

        if (queryStart >= 0 && (fragmentStart < 0 || queryStart < fragmentStart))
        {
            return ExternalResourceViolation.HasQuery;
        }

        if (fragmentStart >= 0)
        {
            return ExternalResourceViolation.HasFragment;
        }

        return WritesUserInfo(resource)
            ? ExternalResourceViolation.HasUserInfo
            : ExternalResourceViolation.None;
    }

    /// <summary>
    /// Reports whether <paramref name="resource"/> satisfies the contract.
    /// </summary>
    /// <param name="resource">The candidate external resource identity.</param>
    /// <returns><see langword="true"/> when the value satisfies every rule.</returns>
    public static bool IsValid(string? resource) => Evaluate(resource) is ExternalResourceViolation.None;

    /// <summary>
    /// The shared rule name for a violation, as published in the contract corpus.
    /// </summary>
    /// <param name="violation">The violated rule.</param>
    /// <returns>The stable corpus rule name, or <see langword="null"/> for no violation.</returns>
    /// <remarks>
    /// Refusal prose is deliberately not shared. Two implementations may phrase one refusal
    /// differently without disagreeing about it; the rule name is the machine-readable fact they
    /// must share.
    /// </remarks>
    public static string? RuleName(ExternalResourceViolation violation) => violation switch
    {
        ExternalResourceViolation.None => null,
        ExternalResourceViolation.Blank => "non-blank",
        ExternalResourceViolation.TooLong => "max-length",
        ExternalResourceViolation.NotAbsolute => "absolute-uri",
        ExternalResourceViolation.WrongScheme => "scheme-https",
        ExternalResourceViolation.HasQuery => "no-query",
        ExternalResourceViolation.HasFragment => "no-fragment",
        ExternalResourceViolation.HasUserInfo => "no-userinfo",
        _ => throw new ArgumentOutOfRangeException(nameof(violation), violation, "Unknown external-resource contract rule."),
    };

    /// <summary>
    /// The shared statement of what a rule requires, used to phrase a refusal about the rule rather
    /// than about the offending value.
    /// </summary>
    /// <param name="violation">The violated rule.</param>
    /// <returns>A short description of what the rule requires.</returns>
    public static string RuleRequirement(ExternalResourceViolation violation) => violation switch
    {
        ExternalResourceViolation.Blank => "an external resource must not be blank",
        ExternalResourceViolation.TooLong => $"an external resource must be at most {MaxLength} characters",
        ExternalResourceViolation.NotAbsolute => "an external resource must be an absolute URI",
        ExternalResourceViolation.WrongScheme => "an external resource must use the https scheme",
        ExternalResourceViolation.HasQuery => "an external resource must not carry a query",
        ExternalResourceViolation.HasFragment => "an external resource must not carry a fragment",
        ExternalResourceViolation.HasUserInfo => "an external resource must not carry userinfo in its authority, because it is non-secret deployment state",
        _ => "an external resource must satisfy the external-resource contract",
    };

    /// <summary>
    /// Reports whether <paramref name="resource"/> writes an absolute URI whose scheme is
    /// <paramref name="expectedScheme"/>, comparing the scheme case-insensitively.
    /// </summary>
    /// <param name="resource">The candidate value.</param>
    /// <param name="expectedScheme">The scheme the value must write.</param>
    /// <param name="writesExpectedScheme">
    /// <see langword="true"/> when the scheme is exactly <paramref name="expectedScheme"/>; meaningful
    /// only when the method returns <see langword="true"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when an absolute URI with a valid scheme is written; <see langword="false"/>
    /// when no valid scheme is written at all, which the caller reports as
    /// <see cref="ExternalResourceViolation.NotAbsolute"/>.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This deliberately does not use <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>. That
    /// parser is host-dependent for a rooted or scheme-relative value: on Windows
    /// <c>/v1/mcp/x</c> fails to parse and <c>//host/x</c> parses as a UNC <c>file</c> URI, while on
    /// Linux <c>/v1/mcp/x</c> parses as <c>file:///v1/mcp/x</c>. The same corpus row therefore
    /// reported <c>absolute-uri</c> on one host and <c>scheme-https</c> on another, and Platform
    /// names the rule for the operator, so a host-dependent rule would make the two implementations
    /// disagree by operating system. The contract is instead decided from the raw value: a scheme is
    /// written when a valid scheme name, followed by <c>:</c>, prefixes the value, and it is absolute
    /// only when that scheme is followed by <c>//</c> and a non-empty authority.
    /// </para>
    /// <para>
    /// Every value an OAuth resource can legitimately carry uses the authority form, so the accepted
    /// set is unchanged for real inputs: an <c>https</c> absolute URI still passes, and a relative or
    /// scheme-relative reference is still refused (as <c>absolute-uri</c>). What changes is that the
    /// rule naming no longer depends on the operating system.
    /// </para>
    /// </remarks>
    private static bool HasWrittenHttpScheme(
        string resource,
        string expectedScheme,
        out bool writesExpectedScheme)
    {
        writesExpectedScheme = false;

        int colon = resource.IndexOf(':');
        if (colon <= 0)
        {
            return false;
        }

        ReadOnlySpan<char> scheme = resource.AsSpan(0, colon);
        if (!IsValidScheme(scheme))
        {
            return false;
        }

        int authorityStart = colon + 1;
        if (authorityStart + 1 >= resource.Length
            || resource[authorityStart] != '/'
            || resource[authorityStart + 1] != '/')
        {
            return false;
        }

        int authorityFrom = authorityStart + 2;
        int authorityEnd = resource.Length;
        for (int index = authorityFrom; index < resource.Length; index++)
        {
            if (resource[index] is '/' or '?' or '#')
            {
                authorityEnd = index;
                break;
            }
        }

        if (authorityEnd == authorityFrom)
        {
            return false;
        }

        writesExpectedScheme = scheme.Equals(expectedScheme, StringComparison.OrdinalIgnoreCase);
        return true;
    }

    /// <summary>
    /// Reports whether <paramref name="scheme"/> is an RFC 3986 scheme: <c>ALPHA *( ALPHA / DIGIT /
    /// "+" / "-" / "." )</c>.
    /// </summary>
    private static bool IsValidScheme(ReadOnlySpan<char> scheme)
    {
        if (scheme.IsEmpty || !char.IsAsciiLetter(scheme[0]))
        {
            return false;
        }

        for (int index = 1; index < scheme.Length; index++)
        {
            char c = scheme[index];
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('+' or '-' or '.'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Reports whether a userinfo component was written into the URI authority.
    /// </summary>
    /// <param name="resource">A value already known to parse as an absolute URI.</param>
    /// <returns><see langword="true"/> when an <c>@</c> separates a userinfo from the host.</returns>
    /// <remarks>
    /// The obvious test, an emptiness check on <see cref="Uri.UserInfo"/>, is not sufficient and is
    /// not used. <see cref="Uri"/> reports the userinfo of <c>https://@host/</c> as the empty
    /// string, so that test accepts a value that carries a written userinfo delimiter; the storage
    /// layer, which can only look for the delimiter, refuses it. Two layers disagreeing about one
    /// value is precisely the defect this contract exists to remove, so the authority itself is
    /// examined instead. A host cannot contain <c>@</c>, so an <c>@</c> between the scheme separator
    /// and the first path, query, or fragment delimiter is a userinfo delimiter and nothing else.
    /// <para>
    /// This is the one rule that reads the raw string, because the parsed form exposes no property
    /// that distinguishes an explicitly empty userinfo from none. Every other rule is decided from a
    /// parsed URI property.
    /// </para>
    /// </remarks>
    private static bool WritesUserInfo(string resource)
    {
        int schemeSeparator = resource.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator < 0)
        {
            return false;
        }

        int authorityStart = schemeSeparator + 3;
        int authorityLength = resource.Length - authorityStart;
        for (int index = authorityStart; index < resource.Length; index++)
        {
            if (resource[index] is '/' or '?' or '#')
            {
                authorityLength = index - authorityStart;
                break;
            }
        }

        return resource.AsSpan(authorityStart, authorityLength).IndexOf('@') >= 0;
    }
}