using System.Globalization;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.Exchange;

/// <summary>Where one exchange value mapping reads its value from.</summary>
public enum ExchangeValueSourceKind
{
    /// <summary>A non-secret input carried by the profile configuration.</summary>
    Input,

    /// <summary>A named secret slot consumed by the strategy.</summary>
    Secret,

    /// <summary>A literal value carried by the configuration.</summary>
    Static,
}

/// <summary>One exchange value mapping.</summary>
/// <param name="Kind">Where the value comes from.</param>
/// <param name="Slot">The input or secret slot name, for the two slot kinds.</param>
/// <param name="StaticValue">The literal value, for the literal kind.</param>
public sealed record ExchangeValueSource(
    ExchangeValueSourceKind Kind,
    string? Slot = null,
    string? StaticValue = null);

/// <summary>How a response selector reads its value.</summary>
public enum ExchangeSelectorKind
{
    /// <summary>An RFC 6901 JSON Pointer into a JSON response body.</summary>
    JsonPointer,

    /// <summary>A response header.</summary>
    Header,

    /// <summary>A response cookie.</summary>
    Cookie,
}

/// <summary>One response selector.</summary>
/// <param name="Kind">How the value is selected.</param>
/// <param name="Selector">The pointer, header name or cookie name.</param>
public sealed record ExchangeSelector(ExchangeSelectorKind Kind, string Selector);

/// <summary>How an exchange expiry value is interpreted.</summary>
public enum ExchangeExpiryKind
{
    /// <summary>Seconds from now.</summary>
    RelativeSeconds,

    /// <summary>Seconds since the Unix epoch.</summary>
    UnixSeconds,

    /// <summary>An absolute instant.</summary>
    AbsoluteUtc,
}

/// <summary>One expiry mapping.</summary>
/// <param name="Kind">How the selected value is interpreted.</param>
/// <param name="Selector">Where the value is read from.</param>
public sealed record ExchangeExpiryDefinition(ExchangeExpiryKind Kind, ExchangeSelector Selector);

/// <summary>A response-derived destination together with the origins it may use.</summary>
/// <param name="Selector">Where the destination is read from.</param>
/// <param name="AllowedOrigins">The reviewed origins the destination must fall inside.</param>
public sealed record ExchangeDestinationDefinition(
    ExchangeSelector Selector,
    IReadOnlyList<string> AllowedOrigins);

/// <summary>
/// How acquired session material is injected into the operation request.
/// </summary>
/// <param name="Location">One of <c>bearer</c>, <c>header</c>, <c>cookie</c>, <c>query</c>.</param>
/// <param name="Name">The wire name, for the three named locations.</param>
/// <param name="Prefix">A literal prefix applied to the value, for the named locations.</param>
public sealed record SessionInjectionDefinition(string Location, string? Name, string Prefix)
{
    /// <summary>
    /// Builds the definition from an already-validated configuration's three raw members.
    /// </summary>
    /// <remarks>
    /// Used by the challenge-session projection, whose injection declares the same three members
    /// the exchange reader validates. The location vocabulary is re-checked here because it is
    /// what keeps <see cref="CreateCredential"/> total: a member the reader admits for a different
    /// strategy must not reach a credential this type cannot name.
    /// </remarks>
    public static SessionInjectionDefinition FromValidated(string location, string? name, string? prefix)
    {
        ArgumentException.ThrowIfNullOrEmpty(location);

        return location switch
        {
            "bearer" => new SessionInjectionDefinition(location, null, string.Empty),
            "header" or "cookie" or "query" when !string.IsNullOrEmpty(name)
                => new SessionInjectionDefinition(location, name, prefix ?? string.Empty),
            "header" or "cookie" or "query" => throw new AuthenticationPlanException(
                "session-injection",
                $"A '{location}' injection requires a non-empty wire name."),
            _ => throw new AuthenticationPlanException(
                "session-injection",
                $"Session injection location '{location}' is not supported."),
        };
    }

    /// <summary>
    /// Builds the credential the operation request carries.
    /// </summary>
    /// <remarks>
    /// The result is an ordinary declaration plus its value, so the request is authenticated by
    /// exactly the same applier that handles a manifest-declared credential. A second application
    /// path for derived material would be a second place for the two to disagree about which
    /// header a scheme writes.
    /// </remarks>
    public ResolvedCredential CreateCredential(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return Location switch
        {
            // A bearer injection names no header: the applier reads an empty slot as the
            // Authorization header, which is the only destination the bearer form has.
            "bearer" => new ResolvedCredential(
                new ManifestCredential("exchange-session", CredentialScheme.Bearer, string.Empty, Carrier),
                value),
            "header" => new ResolvedCredential(
                new ManifestCredential("exchange-session", CredentialScheme.Header, Name!, Carrier),
                Prefix + value),
            "cookie" => new ResolvedCredential(
                new ManifestCredential("exchange-session", CredentialScheme.ApiKey, Name!, Carrier, CredentialLocation.Cookie),
                Prefix + value),
            "query" => new ResolvedCredential(
                new ManifestCredential("exchange-session", CredentialScheme.ApiKey, Name!, Carrier, CredentialLocation.Query),
                Prefix + value),
            _ => throw new AuthenticationPlanException(
                "exchange-session",
                "Session injection location is not supported."),
        };
    }

    /// <summary>
    /// The declaration's value reference. It is a placeholder: the acquired material travels in
    /// the resolved value beside a declaration that exists only to select the application rule,
    /// so nothing ever resolves this reference.
    /// </summary>
    private static CredentialReference Carrier { get; } =
        CredentialReference.Literal("exchange-session");
}

/// <summary>
/// The typed projection of a validated token/session exchange configuration.
/// </summary>
/// <remarks>
/// <para>
/// The Manifest reader has already enforced the closed member set, the bounds and the executable
/// refusal for this configuration, so this projection re-states only the facts the runtime needs
/// and the shape checks that keep a hand-built model from reaching execution. Re-running the
/// full rejection vocabulary here would be a second implementation of load validation, and the
/// two would drift; the reader is the authority on what a configuration may say.
/// </para>
/// </remarks>
public sealed record TokenSessionExchangeDefinition
{
    /// <summary>The longest lifetime an acquired session may claim.</summary>
    public static readonly TimeSpan MaximumSessionLifetime = TimeSpan.FromDays(30);

    /// <summary>The reviewed endpoint.</summary>
    public required Uri Endpoint { get; init; }

    /// <summary>The upper-case HTTP method.</summary>
    public required string Method { get; init; }

    /// <summary>The request media type.</summary>
    public required string MediaType { get; init; }

    /// <summary>The non-secret inputs the configuration carries.</summary>
    public required IReadOnlyDictionary<string, string> Inputs { get; init; }

    /// <summary>The body field mappings.</summary>
    public required IReadOnlyDictionary<string, ExchangeValueSource> Fields { get; init; }

    /// <summary>The request header mappings.</summary>
    public required IReadOnlyDictionary<string, ExchangeValueSource> Headers { get; init; }

    /// <summary>The Basic authentication mapping, when the exchange uses one.</summary>
    public (ExchangeValueSource Username, ExchangeValueSource Password)? BasicAuthentication { get; init; }

    /// <summary>Where the acquired session material is read from.</summary>
    public required ExchangeSelector TokenSelector { get; init; }

    /// <summary>How the material's expiry is read, when the response states one.</summary>
    public ExchangeExpiryDefinition? Expiry { get; init; }

    /// <summary>How a response-derived destination is read, when the exchange states one.</summary>
    public ExchangeDestinationDefinition? Destination { get; init; }

    /// <summary>How the material is injected into the operation request.</summary>
    public required SessionInjectionDefinition Injection { get; init; }

    /// <summary>The lifetime used when the response states no expiry.</summary>
    public TimeSpan DefaultLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>The skew subtracted from an expiry before the material is considered usable.</summary>
    public TimeSpan SafetySkew { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>The status codes that mean the acquired session was rejected.</summary>
    public IReadOnlySet<int> AuthenticationFailureStatusCodes { get; init; } = new HashSet<int> { 401 };

    /// <summary>Projects a validated configuration object.</summary>
    /// <exception cref="AuthenticationPlanException">
    /// The configuration is missing a member or states a value the reader's schema could not have
    /// admitted, which means a model was constructed outside load.
    /// </exception>
    public static TokenSessionExchangeDefinition FromConfiguration(JsonObject configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var inputs = ReadInputs(configuration);
        var request = RequireObject(configuration, "request");
        var method = ReadString(configuration, "method");

        var fields = ReadMappings(request, "fields", inputs, headerNames: false);
        var headers = ReadMappings(request, "headers", inputs, headerNames: true);
        var basic = ReadBasic(request, inputs);

        var response = RequireObject(configuration, "response");
        var expiryNode = response["expiry"];
        var destinationNode = configuration["destination"];

        return new TokenSessionExchangeDefinition
        {
            Endpoint = ReadEndpoint(ReadString(configuration, "endpoint")),
            Method = method,
            MediaType = ReadString(request, "mediaType"),
            Inputs = inputs,
            Fields = fields,
            Headers = headers,
            BasicAuthentication = basic,
            TokenSelector = ReadSelector(RequireObject(response, "token")),
            Expiry = expiryNode is JsonObject expiry ? ReadExpiry(expiry) : null,
            Destination = destinationNode is JsonObject destination ? ReadDestination(destination) : null,
            Injection = ReadInjection(RequireObject(configuration, "injection")),
            DefaultLifetime = TimeSpan.FromSeconds(ReadOptionalInt(configuration, "defaultLifetimeSeconds") ?? 300),
            SafetySkew = TimeSpan.FromSeconds(ReadOptionalInt(configuration, "safetySkewSeconds") ?? 15),
            AuthenticationFailureStatusCodes = ReadStatusCodes(configuration),
        };
    }

    /// <summary>Reads one response selector.</summary>
    public static ExchangeSelector ReadSelector(JsonObject selector)
    {
        ArgumentNullException.ThrowIfNull(selector);

        var source = ReadString(selector, "source");
        var value = ReadString(selector, "selector");

        return source switch
        {
            "jsonPointer" => new ExchangeSelector(ExchangeSelectorKind.JsonPointer, value),
            "header" => new ExchangeSelector(ExchangeSelectorKind.Header, value),
            "cookie" => new ExchangeSelector(ExchangeSelectorKind.Cookie, value),
            _ => throw Invalid($"Response selector source '{source}' is not supported."),
        };
    }

    /// <summary>
    /// Selects a value at an RFC 6901 JSON Pointer.
    /// </summary>
    /// <remarks>
    /// A zero-length pointer selects the whole document. An empty or zero-padded array index is
    /// refused rather than coerced, so <c>/items/01</c> cannot select <c>/items/1</c>.
    /// </remarks>
    public static bool TrySelectJsonPointer(JsonNode? root, string pointer, out JsonNode? selected)
    {
        selected = root;

        if (pointer.Length == 0)
        {
            return selected is not null;
        }

        if (pointer[0] != '/')
        {
            return false;
        }

        foreach (string encoded in pointer[1..].Split('/'))
        {
            if (!TryDecodePointerSegment(encoded, out var segment))
            {
                return false;
            }

            switch (selected)
            {
                case JsonObject map:
                    if (!map.TryGetPropertyValue(segment, out selected))
                    {
                        return false;
                    }

                    break;

                case JsonArray array:
                    if (segment.Length == 0
                        || (segment.Length > 1 && segment[0] == '0')
                        || !int.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, out int index)
                        || index < 0
                        || index >= array.Count)
                    {
                        return false;
                    }

                    selected = array[index];
                    break;

                default:
                    return false;
            }
        }

        return selected is not null;
    }

    internal static bool TryDecodePointerSegment(string encoded, out string decoded)
    {
        var buffer = new System.Text.StringBuilder(encoded.Length);

        for (int index = 0; index < encoded.Length; index++)
        {
            if (encoded[index] != '~')
            {
                buffer.Append(encoded[index]);
                continue;
            }

            index++;
            if (index >= encoded.Length || encoded[index] is not ('0' or '1'))
            {
                decoded = string.Empty;
                return false;
            }

            buffer.Append(encoded[index] == '0' ? '~' : '/');
        }

        decoded = buffer.ToString();
        return true;
    }

    private static IReadOnlyDictionary<string, string> ReadInputs(JsonObject configuration)
    {
        var inputs = new Dictionary<string, string>(StringComparer.Ordinal);

        if (configuration["inputs"] is not JsonObject declared)
        {
            return inputs;
        }

        foreach (var (name, node) in declared)
        {
            if (node is not JsonValue value || !value.TryGetValue<string>(out var text))
            {
                throw Invalid($"Input '{name}' is not a string.");
            }

            inputs[name] = text;
        }

        return inputs;
    }

    private static IReadOnlyDictionary<string, ExchangeValueSource> ReadMappings(
        JsonObject parent,
        string member,
        IReadOnlyDictionary<string, string> inputs,
        bool headerNames)
    {
        var comparer = headerNames ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var mappings = new Dictionary<string, ExchangeValueSource>(comparer);

        if (parent[member] is not JsonObject declared)
        {
            return mappings;
        }

        foreach (var (name, node) in declared)
        {
            if (node is not JsonObject mapping)
            {
                throw Invalid($"Mapping '{name}' is not an object.");
            }

            mappings[name] = ReadValueSource(mapping, inputs);
        }

        return mappings;
    }

    private static (ExchangeValueSource Username, ExchangeValueSource Password)? ReadBasic(
        JsonObject request,
        IReadOnlyDictionary<string, string> inputs)
    {
        if (request["basic"] is not JsonObject basic)
        {
            return null;
        }

        return (
            ReadValueSource(RequireObject(basic, "username"), inputs),
            ReadValueSource(RequireObject(basic, "password"), inputs));
    }

    private static ExchangeValueSource ReadValueSource(
        JsonObject mapping,
        IReadOnlyDictionary<string, string> inputs)
    {
        var source = ReadString(mapping, "source");
        string? slot = mapping["slot"] is JsonValue slotValue && slotValue.TryGetValue<string>(out var slotText)
            ? slotText
            : null;
        string? staticValue = mapping["value"] is JsonValue value && value.TryGetValue<string>(out var valueText)
            ? valueText
            : null;

        return source switch
        {
            "input" when slot is not null && staticValue is null && inputs.ContainsKey(slot) =>
                new ExchangeValueSource(ExchangeValueSourceKind.Input, slot),
            "secret" when slot is not null && staticValue is null =>
                new ExchangeValueSource(ExchangeValueSourceKind.Secret, slot),
            "static" when slot is null && staticValue is not null =>
                new ExchangeValueSource(ExchangeValueSourceKind.Static, StaticValue: staticValue),
            _ => throw Invalid(
                $"Value mapping source '{source}' does not match a declared input or literal."),
        };
    }

    private static ExchangeExpiryDefinition ReadExpiry(JsonObject expiry)
    {
        var kind = ReadString(expiry, "kind") switch
        {
            "relativeSeconds" => ExchangeExpiryKind.RelativeSeconds,
            "unixSeconds" => ExchangeExpiryKind.UnixSeconds,
            "absoluteUtc" => ExchangeExpiryKind.AbsoluteUtc,
            _ => throw Invalid("Expiry kind is not supported."),
        };

        return new ExchangeExpiryDefinition(kind, ReadSelector(expiry));
    }

    private static ExchangeDestinationDefinition ReadDestination(JsonObject destination)
    {
        var origins = new List<string>();

        if (destination["allowedOrigins"] is JsonArray declared)
        {
            foreach (var node in declared)
            {
                if (node is JsonValue value && value.TryGetValue<string>(out var text) && text.Length > 0)
                {
                    origins.Add(text);
                    continue;
                }

                throw Invalid("A destination origin is not a non-empty string.");
            }
        }

        return new ExchangeDestinationDefinition(ReadSelector(RequireObject(destination, "selector")), origins);
    }

    private static SessionInjectionDefinition ReadInjection(JsonObject injection)
    {
        var location = ReadString(injection, "location");
        string? name = injection["name"] is JsonValue nameValue && nameValue.TryGetValue<string>(out var nameText)
            ? nameText
            : null;
        string prefix = injection["prefix"] is JsonValue prefixValue && prefixValue.TryGetValue<string>(out var prefixText)
            ? prefixText
            : string.Empty;

        return new SessionInjectionDefinition(location, name, prefix);
    }

    private static IReadOnlySet<int> ReadStatusCodes(JsonObject configuration)
    {
        var codes = new HashSet<int>();

        if (configuration["authFailureStatusCodes"] is not JsonArray declared)
        {
            codes.Add(401);
            return codes;
        }

        foreach (var node in declared)
        {
            if (node is JsonValue value && value.TryGetValue<int>(out int status))
            {
                codes.Add(status);
            }
            else
            {
                throw Invalid("An authentication failure status code is not an integer.");
            }
        }

        if (codes.Count == 0)
        {
            throw Invalid("Authentication failure status codes must not be empty.");
        }

        return codes;
    }

    private static Uri ReadEndpoint(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && uri.Scheme is "https" or "http"
            && !string.IsNullOrEmpty(uri.Host)
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment)
                ? uri
                : throw Invalid("Exchange endpoint is not a usable absolute URL.");

    private static int? ReadOptionalInt(JsonObject parent, string member)
        => parent[member] is JsonValue value && value.TryGetValue<int>(out int number) ? number : null;

    private static JsonObject RequireObject(JsonObject parent, string member)
        => parent[member] as JsonObject
            ?? throw Invalid($"Member '{member}' is not an object.");

    private static string ReadString(JsonObject parent, string member)
        => parent[member] is JsonValue value && value.TryGetValue<string>(out var text)
            ? text
            : throw Invalid($"Member '{member}' is not a string.");

    private static AuthenticationPlanException Invalid(string message)
        => new("exchange", message);
}
