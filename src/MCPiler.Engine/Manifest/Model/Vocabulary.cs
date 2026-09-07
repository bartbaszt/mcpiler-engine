namespace MCPiler.Engine.Manifest.Model;

/// <summary>How an operation may be reached on one surface.</summary>
/// <remarks>
/// This is the single runtime exposure authority. Today invocation passes two independent
/// gates that can disagree; the manifest collapses them into membership of one list.
/// </remarks>
public enum OperationExposure
{
    /// <summary>Advertised in <c>tools/list</c> and directly invocable.</summary>
    Direct,

    /// <summary>Not advertised. Reachable and invocable only through Navigator invoke.</summary>
    Navigator,

    /// <summary>Present for diagnostics. Never invocable and never discoverable.</summary>
    Hidden,
}

/// <summary>Where an HTTP parameter is transmitted.</summary>
/// <remarks>
/// The IR also has a <c>querystring</c> location, but the request compiler refuses it, so
/// admitting it here would create an authorable construct that can never execute. It is
/// therefore excluded from format 0.x.
/// </remarks>
public enum ParameterLocation
{
    /// <summary>A query-string parameter.</summary>
    Query,

    /// <summary>A request header.</summary>
    Header,

    /// <summary>A path template segment.</summary>
    Path,

    /// <summary>A cookie.</summary>
    Cookie,
}

/// <summary>OpenAPI parameter serialization style.</summary>
public enum ParameterStyle
{
    /// <summary>RFC 6570 matrix expansion.</summary>
    Matrix,

    /// <summary>RFC 6570 label expansion.</summary>
    Label,

    /// <summary>Form-style expansion. The query default.</summary>
    Form,

    /// <summary>Simple expansion. The path and header default.</summary>
    Simple,

    /// <summary>Space-delimited array expansion.</summary>
    SpaceDelimited,

    /// <summary>Pipe-delimited array expansion.</summary>
    PipeDelimited,

    /// <summary>Deep-object expansion.</summary>
    DeepObject,

    /// <summary>Cookie-style expansion.</summary>
    Cookie,
}

/// <summary>How an agent operation is backed.</summary>
public enum AgentOperationKind
{
    /// <summary>Derived from an upstream contract operation.</summary>
    SourceBacked,

    /// <summary>Authored directly against an HTTP endpoint.</summary>
    CustomHttp,

    /// <summary>A multi-step workflow over other operations.</summary>
    Compound,
}

/// <summary>Whether an output schema is advertised to the client.</summary>
public enum OutputSchemaAdvertisement
{
    /// <summary>Advertise when the surface supports output schemas and one exists.</summary>
    Auto,

    /// <summary>Always advertise.</summary>
    Yes,

    /// <summary>Never advertise.</summary>
    No,
}

/// <summary>The credential application scheme.</summary>
/// <remarks>
/// Closed to the values the credential applier actually switches on. Platform doc comments
/// also mention <c>none</c>, but no branch matches it, so it would be a silent no-op rather
/// than "no authentication"; it is deliberately not part of the vocabulary.
/// </remarks>
public enum CredentialScheme
{
    /// <summary>HTTP Basic. Slots are <c>username</c> and <c>password</c>.</summary>
    Basic,

    /// <summary>Bearer token. The slot is the header name, normally <c>Authorization</c>.</summary>
    Bearer,

    /// <summary>An API key placed in a header, the query string, or a cookie.</summary>
    ApiKey,

    /// <summary>A verbatim header whose name is the slot.</summary>
    Header,
}

/// <summary>Where an API key is placed. Applies to <see cref="CredentialScheme.ApiKey"/>.</summary>
public enum CredentialLocation
{
    /// <summary>A request header. The default.</summary>
    Header,

    /// <summary>A query-string parameter.</summary>
    Query,

    /// <summary>A cookie.</summary>
    Cookie,
}

/// <summary>How a compound workflow reacts to a failing step.</summary>
public enum CompoundFailurePolicy
{
    /// <summary>Abort the workflow at the first failing step. The only policy in v1.</summary>
    FailFast,
}

/// <summary>
/// Wire-name mapping for every closed vocabulary in the manifest format.
/// </summary>
/// <remarks>
/// <para>
/// Parsing goes through this type so no reader invents its own spelling and no two readers
/// can disagree. Every <c>TryRead</c> is strict: an unrecognized token returns
/// <see langword="false"/> and the caller raises a diagnostic. Nothing falls back to a
/// default, because a misread enum silently changes behavior instead of failing.
/// </para>
/// <para>
/// Reads are case-insensitive so a hand-authored <c>spacedelimited</c> is accepted, matching
/// how the existing request compiler compares style names. Writes always emit the canonical
/// camelCase spelling.
/// </para>
/// </remarks>
public static class Vocabulary
{
    private static readonly (OperationExposure Value, string Wire)[] Exposures =
    [
        (OperationExposure.Direct, "direct"),
        (OperationExposure.Navigator, "navigator"),
        (OperationExposure.Hidden, "hidden"),
    ];

    private static readonly (ParameterLocation Value, string Wire)[] ParameterLocations =
    [
        (ParameterLocation.Query, "query"),
        (ParameterLocation.Header, "header"),
        (ParameterLocation.Path, "path"),
        (ParameterLocation.Cookie, "cookie"),
    ];

    private static readonly (ParameterStyle Value, string Wire)[] ParameterStyles =
    [
        (ParameterStyle.Matrix, "matrix"),
        (ParameterStyle.Label, "label"),
        (ParameterStyle.Form, "form"),
        (ParameterStyle.Simple, "simple"),
        (ParameterStyle.SpaceDelimited, "spaceDelimited"),
        (ParameterStyle.PipeDelimited, "pipeDelimited"),
        (ParameterStyle.DeepObject, "deepObject"),
        (ParameterStyle.Cookie, "cookie"),
    ];

    private static readonly (AgentOperationKind Value, string Wire)[] OperationKinds =
    [
        (AgentOperationKind.SourceBacked, "source-backed"),
        (AgentOperationKind.CustomHttp, "custom-http"),
        (AgentOperationKind.Compound, "compound"),
    ];

    private static readonly (OutputSchemaAdvertisement Value, string Wire)[] Advertisements =
    [
        (OutputSchemaAdvertisement.Auto, "auto"),
        (OutputSchemaAdvertisement.Yes, "yes"),
        (OutputSchemaAdvertisement.No, "no"),
    ];

    private static readonly (CredentialScheme Value, string Wire)[] CredentialSchemes =
    [
        (CredentialScheme.Basic, "basic"),
        (CredentialScheme.Bearer, "bearer"),
        (CredentialScheme.ApiKey, "apiKey"),
        (CredentialScheme.Header, "header"),
    ];

    private static readonly (CredentialLocation Value, string Wire)[] CredentialLocations =
    [
        (CredentialLocation.Header, "header"),
        (CredentialLocation.Query, "query"),
        (CredentialLocation.Cookie, "cookie"),
    ];

    private static readonly (CompoundFailurePolicy Value, string Wire)[] FailurePolicies =
    [
        (CompoundFailurePolicy.FailFast, "failFast"),
    ];

    /// <summary>Every accepted <see cref="OperationExposure"/> spelling, for diagnostics.</summary>
    public static IReadOnlyList<string> ExposureNames { get; } = Names(Exposures);

    /// <summary>Every accepted <see cref="ParameterLocation"/> spelling, for diagnostics.</summary>
    public static IReadOnlyList<string> ParameterLocationNames { get; } = Names(ParameterLocations);

    /// <summary>Every accepted <see cref="ParameterStyle"/> spelling, for diagnostics.</summary>
    public static IReadOnlyList<string> ParameterStyleNames { get; } = Names(ParameterStyles);

    /// <summary>Every accepted <see cref="AgentOperationKind"/> spelling, for diagnostics.</summary>
    public static IReadOnlyList<string> OperationKindNames { get; } = Names(OperationKinds);

    /// <summary>Every accepted <see cref="OutputSchemaAdvertisement"/> spelling, for diagnostics.</summary>
    public static IReadOnlyList<string> AdvertisementNames { get; } = Names(Advertisements);

    /// <summary>Every accepted <see cref="CredentialScheme"/> spelling, for diagnostics.</summary>
    public static IReadOnlyList<string> CredentialSchemeNames { get; } = Names(CredentialSchemes);

    /// <summary>Every accepted <see cref="CredentialLocation"/> spelling, for diagnostics.</summary>
    public static IReadOnlyList<string> CredentialLocationNames { get; } = Names(CredentialLocations);

    /// <summary>Every accepted <see cref="CompoundFailurePolicy"/> spelling, for diagnostics.</summary>
    public static IReadOnlyList<string> FailurePolicyNames { get; } = Names(FailurePolicies);

    /// <summary>Reads an <see cref="OperationExposure"/>.</summary>
    public static bool TryReadExposure(string? wire, out OperationExposure value)
        => TryRead(Exposures, wire, out value);

    /// <summary>Writes an <see cref="OperationExposure"/>.</summary>
    public static string Write(OperationExposure value) => Write(Exposures, value);

    /// <summary>Reads a <see cref="ParameterLocation"/>.</summary>
    public static bool TryReadParameterLocation(string? wire, out ParameterLocation value)
        => TryRead(ParameterLocations, wire, out value);

    /// <summary>Writes a <see cref="ParameterLocation"/>.</summary>
    public static string Write(ParameterLocation value) => Write(ParameterLocations, value);

    /// <summary>Reads a <see cref="ParameterStyle"/>.</summary>
    public static bool TryReadParameterStyle(string? wire, out ParameterStyle value)
        => TryRead(ParameterStyles, wire, out value);

    /// <summary>Writes a <see cref="ParameterStyle"/>.</summary>
    public static string Write(ParameterStyle value) => Write(ParameterStyles, value);

    /// <summary>Reads an <see cref="AgentOperationKind"/>.</summary>
    public static bool TryReadOperationKind(string? wire, out AgentOperationKind value)
        => TryRead(OperationKinds, wire, out value);

    /// <summary>Writes an <see cref="AgentOperationKind"/>.</summary>
    public static string Write(AgentOperationKind value) => Write(OperationKinds, value);

    /// <summary>Reads an <see cref="OutputSchemaAdvertisement"/>.</summary>
    public static bool TryReadAdvertisement(string? wire, out OutputSchemaAdvertisement value)
        => TryRead(Advertisements, wire, out value);

    /// <summary>Writes an <see cref="OutputSchemaAdvertisement"/>.</summary>
    public static string Write(OutputSchemaAdvertisement value) => Write(Advertisements, value);

    /// <summary>Reads a <see cref="CredentialScheme"/>.</summary>
    public static bool TryReadCredentialScheme(string? wire, out CredentialScheme value)
        => TryRead(CredentialSchemes, wire, out value);

    /// <summary>Writes a <see cref="CredentialScheme"/>.</summary>
    public static string Write(CredentialScheme value) => Write(CredentialSchemes, value);

    /// <summary>Reads a <see cref="CredentialLocation"/>.</summary>
    public static bool TryReadCredentialLocation(string? wire, out CredentialLocation value)
        => TryRead(CredentialLocations, wire, out value);

    /// <summary>Writes a <see cref="CredentialLocation"/>.</summary>
    public static string Write(CredentialLocation value) => Write(CredentialLocations, value);

    /// <summary>Reads a <see cref="CompoundFailurePolicy"/>.</summary>
    public static bool TryReadFailurePolicy(string? wire, out CompoundFailurePolicy value)
        => TryRead(FailurePolicies, wire, out value);

    /// <summary>Writes a <see cref="CompoundFailurePolicy"/>.</summary>
    public static string Write(CompoundFailurePolicy value) => Write(FailurePolicies, value);

    /// <summary>
    /// The parameter style applied when a parameter declares none.
    /// </summary>
    public static ParameterStyle DefaultStyle(ParameterLocation location) => location switch
    {
        ParameterLocation.Path => ParameterStyle.Simple,
        ParameterLocation.Query => ParameterStyle.Form,
        ParameterLocation.Header => ParameterStyle.Simple,
        ParameterLocation.Cookie => ParameterStyle.Form,
        _ => ParameterStyle.Simple,
    };

    /// <summary>
    /// The explode flag applied when a parameter declares none.
    /// </summary>
    public static bool DefaultExplode(ParameterLocation location, ParameterStyle style) => location switch
    {
        ParameterLocation.Query => style == ParameterStyle.Form,
        _ => false,
    };

    private static bool TryRead<T>((T Value, string Wire)[] table, string? wire, out T value)
        where T : struct, Enum
    {
        if (wire is not null)
        {
            foreach (var (candidate, name) in table)
            {
                if (string.Equals(name, wire, StringComparison.OrdinalIgnoreCase))
                {
                    value = candidate;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static string Write<T>((T Value, string Wire)[] table, T value)
        where T : struct, Enum
    {
        foreach (var (candidate, name) in table)
        {
            if (EqualityComparer<T>.Default.Equals(candidate, value))
            {
                return name;
            }
        }

        throw new ArgumentOutOfRangeException(
            nameof(value),
            value,
            $"No wire name is defined for {typeof(T).Name}.{value}.");
    }

    private static IReadOnlyList<string> Names<T>((T Value, string Wire)[] table)
        where T : struct, Enum
        => [.. table.Select(static entry => entry.Wire)];
}
