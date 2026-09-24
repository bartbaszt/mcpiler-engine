using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using MCPiler.Engine.Authentication.OAuth1;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

using static MCPiler.Engine.Manifest.Loading.SectionReadContext;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads the <c>authentication</c> section: closed, non-secret generic strategy configuration.
/// </summary>
/// <remarks>
/// <para>
/// A profile declares only what an executing runtime needs: which closed strategy kind runs, the
/// bounded configuration that selects its behavior, which origins may receive the credential, and
/// which <c>credentials</c>-section ids it may reveal. Everything Platform needs for authoring —
/// row ids, preset identity, status text, ciphertext — is refused here rather than ignored, because
/// a member that arrives and has no meaning in Engine is a member the boundary failed to keep out.
/// </para>
/// <para>
/// Strategy configuration is validated member-by-member against a closed schema per kind. The
/// rules mirror the accepted Platform parsers exactly (same member names, same bounds, same
/// executable-member refusal), so a configuration that Platform accepted cannot become a different
/// runtime plan merely by crossing the boundary. An unknown member is an error here, not a
/// forward-compatible extension: an Engine build that ignored it would execute a plan the author
/// did not write.
/// </para>
/// </remarks>
internal static class AuthenticationSectionReader
{
    internal static readonly string[] SectionMembers = ["formatVersion", "profiles"];

    internal static readonly string[] ProfileMembers =
    [
        "id",
        "kind",
        "configuration",
        "authenticationOrigins",
        "destinationOrigins",
        "credentialRef",
        "scopeFingerprint",
        "slots",
    ];

    internal static readonly string[] SlotMembers = ["slot", "authorityEpoch", "runtimeRevision"];

    /// <summary>The longest accepted profile id, matching the credential id charset.</summary>
    internal const int MaxIdLength = AuthenticationProfile.MaxIdLength;

    /// <summary>The longest accepted scope fingerprint, as lowercase hex SHA-256.</summary>
    internal const int MaxFingerprintLength = AuthenticationProfile.Sha256HexLength;

    /// <summary>The longest accepted slot identity.</summary>
    internal const int MaxSlotLength = 200;

    /// <summary>The longest accepted origin entry.</summary>
    internal const int MaxOriginLength = 2048;

    /// <summary>The largest number of profiles one section may declare.</summary>
    internal const int MaxProfiles = 512;

    /// <summary>The largest number of mutable slots one profile may declare.</summary>
    internal const int MaxSlots = 16;

    /// <summary>The largest number of origins one profile may declare.</summary>
    internal const int MaxOrigins = 64;

    /// <summary>The largest number of credential references one profile may declare.</summary>
    internal const int MaxCredentialRefs = 32;

    /// <summary>The reviewed signer ids the closed registry implements.</summary>
    /// <remarks>
    /// The list is duplicated from the Platform registry deliberately: Engine is the authority for
    /// what it can execute, and a signer Platform gains without an Engine implementation must be a
    /// load-time refusal rather than a request-time surprise.
    /// </remarks>
    internal static readonly string[] ReviewedSignerIds =
    [
        "request-signing-aws-sigv4",
        "request-signing-hmac",
        "request-signing-jwt-hmac",
        "request-signing-subsonic-md5",
    ];

    private const int MaxStrategyConfigurationDepth = 16;

    private const int MaxInputsCount = 200;

    private const int MaxInputNameLength = 200;

    private const int MaxInputValueLength = 16_384;

    private const int MaxJsonPointerLength = 500;

    private const int MaxWireNameLength = 200;

    private const int MaxStatusCodes = 8;

    internal static AuthenticationSection? Read(JsonNode? document, SectionReadContext context)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, SectionMembers, string.Empty);
        context.VerifySectionFormatVersionRange(
            root,
            ManifestFormatSupport.AuthenticationFormatVersionMinimum,
            ManifestFormatSupport.AuthenticationFormatVersionMaximum);

        var elements = context.ObjectArray(root, "profiles", string.Empty);

        if (elements.Count > MaxProfiles)
        {
            context.Error(
                ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The authentication section declares {elements.Count} profiles, which exceeds the supported maximum of {MaxProfiles}."),
                SectionReadContext.Child(string.Empty, "profiles"));
            return null;
        }

        var profiles = new List<AuthenticationProfile>(elements.Count);

        foreach (var (element, pointer) in elements)
        {
            var profile = ReadProfile(element, pointer, context);

            if (profile is not null)
            {
                profiles.Add(profile);
            }
        }

        return new AuthenticationSection(profiles);
    }

    private static AuthenticationProfile? ReadProfile(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        context.RejectUnknownMembers(element, ProfileMembers, pointer);

        var id = context.RequiredText(element, "id", pointer);

        if (id is null)
        {
            return null;
        }

        if (!AuthenticationProfile.IsValidId(id))
        {
            context.Error(
                ManifestDiagnosticCodes.AuthenticationIdInvalid,
                $"'{DiagnosticText.Echo(id)}' is not an authentication profile id. An id starts with a lower-case ASCII letter or digit, continues with those or '-', and is at most {MaxIdLength} characters.",
                SectionReadContext.Child(pointer, "id"));
            return null;
        }

        var declaredKind = context.RequiredText(element, "kind", pointer);

        if (declaredKind is null)
        {
            return null;
        }

        if (!Vocabulary.TryReadAuthenticationKind(declaredKind, out var kind))
        {
            context.Error(
                ManifestDiagnosticCodes.AuthenticationKindUnknown,
                $"'{DiagnosticText.Echo(declaredKind)}' is not an authentication strategy kind. Expected one of: {DiagnosticText.List(Vocabulary.AuthenticationKindNames)}.",
                SectionReadContext.Child(pointer, "kind"));
            return null;
        }

        // The kind is in the vocabulary but no accepted artifact defines its runtime
        // semantics, so a profile declaring it is refused before any secret is resolved.
        // Accepting it and failing at invocation would turn an authoring statement into a
        // production outage on the first call that uses it.
        if (kind == AuthenticationKind.ReviewedComposite)
        {
            context.Error(
                ManifestDiagnosticCodes.AuthenticationKindNotExecutable,
                $"Strategy kind '{Vocabulary.Write(kind)}' has no execution semantics in this Engine build. It is part of the vocabulary so a stored value round-trips, but no accepted artifact defines how it executes.",
                SectionReadContext.Child(pointer, "kind"));
            return null;
        }

        var configuration = ReadConfiguration(element, pointer, kind, context);

        if (configuration is null)
        {
            return null;
        }

        var authenticationOrigins = ReadOrigins(element, "authenticationOrigins", pointer, context);
        var destinationOrigins = ReadOrigins(element, "destinationOrigins", pointer, context);

        var credentials = context.TextArray(element, "credentialRef", pointer);

        if (credentials.Count > MaxCredentialRefs)
        {
            context.Error(
                ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'credentialRef' declares {credentials.Count} entries, which exceeds the supported maximum of {MaxCredentialRefs}."),
                SectionReadContext.Child(pointer, "credentialRef"));
            return null;
        }

        var fingerprint = ReadScopeFingerprint(element, pointer, context);

        if (fingerprint is { Valid: false })
        {
            return null;
        }

        var slots = ReadSlots(element, pointer, context);

        if (slots is null)
        {
            return null;
        }

        return new AuthenticationProfile(
            id,
            kind,
            configuration,
            authenticationOrigins,
            destinationOrigins,
            credentials,
            fingerprint?.Value,
            slots);
    }

    /// <summary>
    /// Reads and validates the strategy configuration against the closed schema its kind selects.
    /// </summary>
    /// <remarks>
    /// The configuration is carried as a <see cref="JsonObject"/> — already parsed — because the
    /// runtime consumes it without another parse, and because the loader is where a malformed or
    /// executable member must be refused. Validation is structural: every member set is closed and
    /// every leaf is bounded, so the shape the runtime sees is exactly the shape checked here.
    /// </remarks>
    private static JsonObject? ReadConfiguration(
        JsonObject element,
        string pointer,
        AuthenticationKind kind,
        SectionReadContext context)
    {
        var configurationPointer = SectionReadContext.Child(pointer, "configuration");
        var configuration = context.Object(element, "configuration", pointer);

        if (configuration is null)
        {
            if (element["configuration"] is null)
            {
                context.Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'configuration' is required. Strategy kind '{Vocabulary.Write(kind)}' declares its behavior through it.",
                    configurationPointer);
            }

            return null;
        }

        var validation = new StrategyConfigurationValidator(kind, configurationPointer, context);
        validation.Validate(configuration);

        return validation.Valid ? configuration : null;
    }

    /// <summary>
    /// Reads an origin list, requiring every entry to be a canonical http(s) origin without a path,
    /// query, fragment, or user information.
    /// </summary>
    /// <remarks>
    /// Engine accepts the canonical form the producer emits and nothing else. A path or query would
    /// make the origin comparison depend on how two URLs were written, and normalizing here would
    /// put the runtime's matching rule in two places. The producer owns canonicalization; the
    /// loader owns the invariant that what crossed is canonical.
    /// </remarks>
    private static IReadOnlyList<string> ReadOrigins(
        JsonObject element,
        string member,
        string pointer,
        SectionReadContext context)
    {
        var originsPointer = SectionReadContext.Child(pointer, member);

        if (element[member] is null)
        {
            return [];
        }

        var declared = context.TextArray(element, member, pointer);

        if (declared.Count > MaxOrigins)
        {
            context.Error(
                ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{member}' declares {declared.Count} origins, which exceeds the supported maximum of {MaxOrigins}."),
                originsPointer);
            return [];
        }

        var normalized = new List<string>(declared.Count);
        var index = 0;

        foreach (var origin in declared)
        {
            var entryPointer = originsPointer + "/" + index.ToString(CultureInfo.InvariantCulture);
            index++;

            if (origin.Length == 0 || origin.Length > MaxOriginLength)
            {
                context.Error(
                    ManifestDiagnosticCodes.AuthenticationOriginInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"An origin must be a non-empty canonical origin no longer than {MaxOriginLength} characters."),
                    entryPointer);
                continue;
            }

            if (!IsCanonicalOrigin(origin, out var canonical))
            {
                context.Error(
                    ManifestDiagnosticCodes.AuthenticationOriginInvalid,
                    $"'{DiagnosticText.Echo(origin)}' is not a canonical origin. Expected 'scheme://host[:port]' with no path, query, fragment, or credentials.",
                    entryPointer);
                continue;
            }

            if (!string.Equals(origin, canonical, StringComparison.Ordinal))
            {
                context.Error(
                    ManifestDiagnosticCodes.AuthenticationOriginInvalid,
                    $"'{DiagnosticText.Echo(origin)}' is not in canonical form. Expected '{DiagnosticText.Echo(canonical)}'.",
                    entryPointer);
                continue;
            }

            normalized.Add(origin);
        }

        return normalized;
    }

    private static (string Value, bool Valid)? ReadScopeFingerprint(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        if (element["scopeFingerprint"] is null)
        {
            return null;
        }

        var fingerprintPointer = SectionReadContext.Child(pointer, "scopeFingerprint");
        var fingerprint = context.RequiredText(element, "scopeFingerprint", pointer);

        if (fingerprint is null)
        {
            return (string.Empty, false);
        }

        if (fingerprint.Length != MaxFingerprintLength || !IsLowercaseHex(fingerprint))
        {
            context.Error(
                ManifestDiagnosticCodes.AuthenticationScopeFingerprintInvalid,
                $"A scope fingerprint must be {MaxFingerprintLength} lower-case hexadecimal characters.",
                fingerprintPointer);
            return (string.Empty, false);
        }

        return (fingerprint, true);
    }

    private static IReadOnlyList<AuthenticationSlot>? ReadSlots(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        if (element["slots"] is null)
        {
            return [];
        }

        var slotsPointer = SectionReadContext.Child(pointer, "slots");
        var elements = context.ObjectArray(element, "slots", pointer);

        if (elements.Count > MaxSlots)
        {
            context.Error(
                ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'slots' declares {elements.Count} entries, which exceeds the supported maximum of {MaxSlots}."),
                slotsPointer);
            return null;
        }

        var slots = new List<AuthenticationSlot>(elements.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (slotElement, slotPointer) in elements)
        {
            context.RejectUnknownMembers(slotElement, SlotMembers, slotPointer);

            var slot = context.RequiredText(slotElement, "slot", slotPointer);

            if (slot is null)
            {
                continue;
            }

            if (slot.Length > MaxSlotLength)
            {
                context.Error(
                    ManifestDiagnosticCodes.AuthenticationSlotInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"A mutable slot identity must be a non-empty string no longer than {MaxSlotLength} characters."),
                    SectionReadContext.Child(slotPointer, "slot"));
                continue;
            }

            if (!seen.Add(slot))
            {
                context.Error(
                    ManifestDiagnosticCodes.DuplicateAuthenticationSlot,
                    $"The profile declares the mutable slot '{DiagnosticText.Echo(slot)}' more than once.",
                    SectionReadContext.Child(slotPointer, "slot"));
                continue;
            }

            var epoch = context.Integer64(slotElement, "authorityEpoch", slotPointer);

            if (epoch is null)
            {
                if (slotElement["authorityEpoch"] is not null)
                {
                    continue;
                }

                context.Error(
                    ManifestDiagnosticCodes.AuthenticationSlotInvalid,
                    "'authorityEpoch' is required for a mutable slot. Without it, a runtime rotation cannot be told apart from an explicit authority change.",
                    SectionReadContext.Child(slotPointer, "authorityEpoch"));
                continue;
            }

            if (!context.RequireAtLeast(epoch.Value, 0, "authorityEpoch", slotPointer))
            {
                continue;
            }

            var revision = context.Integer64(slotElement, "runtimeRevision", slotPointer) ?? 0;

            if (revision < 0)
            {
                context.Error(
                    ManifestDiagnosticCodes.AuthenticationSlotInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'runtimeRevision' must not be negative, but {revision} was declared."),
                    SectionReadContext.Child(slotPointer, "runtimeRevision"));
                continue;
            }

            slots.Add(new AuthenticationSlot(slot, epoch.Value, revision));
        }

        return slots;
    }

    /// <summary>
    /// Decides whether a value is a bare origin and returns the canonical spelling it should have.
    /// </summary>
    /// <remarks>
    /// Only scheme, host, and optional port survive; a trailing slash is not an origin because it
    /// is a path, and accepting it would let two spellings of the same origin compare differently.
    /// Wildcard destination origins use the reviewed <c>https://*.parent</c> form, which is not an
    /// absolute URI and is handled by substituting a label before parsing.
    /// </remarks>
    private static bool IsCanonicalOrigin(string value, out string canonical)
    {
        canonical = string.Empty;

        var wildcard = value.Contains("://*.", StringComparison.Ordinal);

        if (!wildcard && value.Contains('*', StringComparison.Ordinal))
        {
            return false;
        }

        var parseValue = wildcard
            ? value.Replace("://*.", "://wildcard.", StringComparison.Ordinal)
            : value;

        if (!Uri.TryCreate(parseValue, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("https" or "http")
            || string.IsNullOrEmpty(uri.Host)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.AbsolutePath is not ("" or "/"))
        {
            return false;
        }

        var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();

        if (host.Length == 0
            || host.Contains('\\', StringComparison.Ordinal)
            || host.Contains('%', StringComparison.Ordinal)
            || host.Any(char.IsControl))
        {
            return false;
        }

        if (wildcard)
        {
            if (uri.Scheme != "https")
            {
                return false;
            }

            var dotIndex = host.IndexOf('.');

            if (dotIndex < 0)
            {
                return false;
            }

            var parent = host[(dotIndex + 1)..];

            if (!parent.Contains('.') || Uri.CheckHostName(parent) is UriHostNameType.IPv4 or UriHostNameType.IPv6)
            {
                return false;
            }

            canonical = $"{uri.Scheme}://*.{parent}:{uri.Port}";
            return true;
        }

        if (uri.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6))
        {
            return false;
        }

        canonical = $"{uri.Scheme}://{host}:{uri.Port}";
        return true;
    }

    private static bool IsLowercaseHex(string value)
    {
        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character) && character is not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return value.Length > 0;
    }

    /// <summary>
    /// Validates one strategy configuration against the closed member schema its kind selects.
    /// </summary>
    /// <remarks>
    /// The validator walks the already-parsed <see cref="JsonObject"/> so a malformed member is
    /// reported against its JSON Pointer instead of a JSON parser's line number, and so the
    /// executable-member refusal covers every depth rather than only the members a hand-written
    /// switch remembered to check. Duplicate JSON members never reach this point: the canonical
    /// parser refuses them, so a configuration that spells one member twice is a section-parse
    /// refusal rather than an ambiguous value read here.
    /// </remarks>
    private sealed class StrategyConfigurationValidator(
        AuthenticationKind kind,
        string pointer,
        SectionReadContext context)
    {
        private readonly HashSet<string> _reportedExecutable = new(StringComparer.Ordinal);

        public bool Valid { get; private set; } = true;

        public void Validate(JsonObject configuration)
        {
            if (Depth(configuration, 0) > MaxStrategyConfigurationDepth)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The strategy configuration exceeds the supported nesting depth of {MaxStrategyConfigurationDepth}."),
                    pointer);
                return;
            }

            RejectExecutableMembers(configuration, pointer);

            if (!Valid)
            {
                return;
            }

            switch (kind)
            {
                case AuthenticationKind.Static:
                    ValidateInputsAndStrategyId(configuration);
                    break;

                case AuthenticationKind.OAuth2ClientCredentials:
                case AuthenticationKind.OAuth2AuthorizationCodePkceRefresh:
                    ValidateOAuth(configuration, authorizationCodeRequired: kind == AuthenticationKind.OAuth2AuthorizationCodePkceRefresh);
                    break;

                case AuthenticationKind.TokenSessionExchange:
                    ValidateTokenSessionExchange(configuration);
                    break;

                case AuthenticationKind.ChallengeSession:
                    ValidateChallengeSession(configuration);
                    break;

                case AuthenticationKind.RequestSigning:
                    ValidateRequestSigning(configuration);
                    break;

                case AuthenticationKind.OAuth1Authorization:
                    ValidateOAuth1(configuration);
                    break;

                default:
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        $"Strategy kind '{Vocabulary.Write(kind)}' has no configuration schema in this Engine build.",
                        pointer);
                    break;
            }
        }

        private void ValidateInputsAndStrategyId(JsonObject configuration)
        {
            RequireKnownMembers(configuration, ["strategyId", "inputs"]);
            RequireStrategyId(configuration);
            ValidateInputs(configuration);
        }

        private void ValidateOAuth(JsonObject configuration, bool authorizationCodeRequired)
        {
            RequireKnownMembers(
                configuration,
                [
                    "strategyId",
                    "inputs",
                    "clientId",
                    "tokenEndpoint",
                    "authorizationEndpoint",
                    "revocationEndpoint",
                    "tokenAuthMethod",
                    "scopes",
                    "resource",
                    "audience",
                    "accessTokenSafetySkewSeconds",
                    "authorizationParameters",
                ]);

            if (authorizationCodeRequired)
            {
                RequireEndpoint(configuration, "authorizationEndpoint", required: true);
            }
            else
            {
                RequireEndpoint(configuration, "authorizationEndpoint", required: false);
            }

            RequireEndpoint(configuration, "tokenEndpoint", required: true);
            RequireEndpoint(configuration, "revocationEndpoint", required: false);

            // Platform accepts the client id either directly or under 'inputs'. Engine accepts the
            // same two shapes so a stored configuration cross the boundary unchanged.
            if (!TryReadBoundedString(configuration, "clientId", 500, out var clientId)
                || string.IsNullOrWhiteSpace(clientId))
            {
                if (!TryReadInput(configuration, "clientId", out clientId) || string.IsNullOrWhiteSpace(clientId))
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        "An OAuth strategy requires a bounded non-empty 'clientId', directly or under 'inputs.clientId'.",
                        Child(pointer, "clientId"));
                    return;
                }
            }

            if (!TryReadBoundedString(configuration, "tokenAuthMethod", 40, out var method))
            {
                method = "client_secret_post";
            }

            if (string.IsNullOrEmpty(method))
            {
                method = "client_secret_post";
            }

            if (method is not ("client_secret_post" or "client_secret_basic" or "none"))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'tokenAuthMethod' must be one of: client_secret_post, client_secret_basic, none.",
                    Child(pointer, "tokenAuthMethod"));
                return;
            }

            ValidateScopes(configuration);
            ValidateOptionalBoundedString(configuration, "resource", 2000);
            ValidateOptionalBoundedString(configuration, "audience", 2000);
            ValidateSafetySkew(configuration);
            ValidateAuthorizationParameters(configuration);
            ValidateInputs(configuration);
        }

        private void ValidateTokenSessionExchange(JsonObject configuration)
        {
            RequireKnownMembers(
                configuration,
                [
                    "strategyId",
                    "inputs",
                    "endpoint",
                    "method",
                    "request",
                    "response",
                    "injection",
                    "destination",
                    "defaultLifetimeSeconds",
                    "safetySkewSeconds",
                    "authFailureStatusCodes",
                ]);

            RequireStrategyId(configuration);
            ValidateInputs(configuration);
            RequireEndpoint(configuration, "endpoint", required: true, allowQuery: false, allowFragment: false);

            var method = ReadRequiredBoundedString(configuration, "method", 16);

            if (method is not ("GET" or "POST" or "PUT" or "PATCH"))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'method' must be one of: GET, POST, PUT, PATCH.",
                    Child(pointer, "method"));
                return;
            }

            var request = RequireObject(configuration, "request");

            if (request is null)
            {
                return;
            }

            RequireKnownMembers(request, ["mediaType", "fields", "headers", "basic"]);

            var mediaType = ReadRequiredBoundedString(request, "mediaType", 100);

            if (mediaType is not ("application/json" or "application/x-www-form-urlencoded"))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'request.mediaType' must be 'application/json' or 'application/x-www-form-urlencoded'.",
                    Child(Child(pointer, "request"), "mediaType"));
                return;
            }

            var fields = ValidateMappings(request, "fields", headerNames: false);

            if (method == "GET" && fields > 0)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "A GET token/session exchange request cannot declare body fields.",
                    Child(Child(pointer, "request"), "fields"));
                return;
            }

            var headers = ValidateMappings(request, "headers", headerNames: true);
            var hasBasic = request["basic"] is not null;

            if (hasBasic)
            {
                var basic = RequireObject(request, "basic");

                if (basic is null)
                {
                    return;
                }

                RequireKnownMembers(basic, ["username", "password"]);
                ValidateValueSource(basic, "username");
                ValidateValueSource(basic, "password");
            }

            if (hasBasic && headers > 0 && HasAuthorizationMapping(request))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "The exchange cannot declare both Basic authentication and an Authorization header mapping.",
                    Child(Child(pointer, "request"), "headers"));
                return;
            }

            var response = RequireObject(configuration, "response");

            if (response is null)
            {
                return;
            }

            RequireKnownMembers(response, ["token", "expiry"]);

            if (!ValidateSelectorMember(response, "token", allowJsonPointer: true))
            {
                return;
            }

            if (response["expiry"] is not null && !ValidateExpiry(response))
            {
                return;
            }

            if (configuration["destination"] is not null)
            {
                var destination = RequireObject(configuration, "destination");

                if (destination is null)
                {
                    return;
                }

                RequireKnownMembers(destination, ["selector", "allowedOrigins"]);

                if (!ValidateSelector(destination, "selector", allowJsonPointer: true))
                {
                    return;
                }

                if (!ValidateStringArray(destination, "allowedOrigins", minCount: 1, maxCount: 32, maxLength: MaxOriginLength))
                {
                    return;
                }
            }

            var injection = RequireObject(configuration, "injection");

            if (injection is null)
            {
                return;
            }

            if (!ValidateInjection(injection))
            {
                return;
            }

            ValidateOptionalInt(configuration, "defaultLifetimeSeconds", 1, 2_592_000);
            ValidateOptionalInt(configuration, "safetySkewSeconds", 0, 300);
            ValidateStatusCodes(configuration);
        }

        private void ValidateChallengeSession(JsonObject configuration)
        {
            RequireKnownMembers(
                configuration,
                [
                    "strategyId",
                    "inputs",
                    "challenge",
                    "injection",
                    "replaySafeOperationKeys",
                    "sessionLifetimeSeconds",
                ]);

            RequireStrategyId(configuration);
            ValidateInputs(configuration);

            var challenge = RequireObject(configuration, "challenge");

            if (challenge is null)
            {
                return;
            }

            RequireKnownMembers(challenge, ["statusCodes", "source", "selector"]);
            ValidateStatusCodes(challenge);

            if (!ValidateSelector(challenge, "source", allowJsonPointer: false, selectorMember: "selector"))
            {
                return;
            }

            var injection = RequireObject(configuration, "injection");

            if (injection is null)
            {
                return;
            }

            if (!ValidateInjection(injection))
            {
                return;
            }

            if (!ValidateStringArray(configuration, "replaySafeOperationKeys", minCount: 0, maxCount: 500, maxLength: 2048))
            {
                return;
            }

            ValidateOptionalInt(configuration, "sessionLifetimeSeconds", 1, 2_592_000);
        }

        private void ValidateOAuth1(JsonObject configuration)
        {
            // The runtime configuration carries only execution-effective fields. Platform-only
            // authorization endpoints, callback state, and stage extras are not members here,
            // so a document carrying them is refused as unknown rather than ignored.
            RequireKnownMembers(configuration, ["consumerKey", "signatureMethod", "parameterTransport"]);

            if (ReadRequiredBoundedString(configuration, "consumerKey", 500) is null)
            {
                return;
            }

            var method = ReadRequiredBoundedString(configuration, "signatureMethod", 20);

            if (method is null)
            {
                return;
            }

            if (!OAuth1Vocabulary.SignatureMethods.Contains(method, StringComparer.Ordinal))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{DiagnosticText.Echo(method)}' is not a signature method. Expected one of: {DiagnosticText.List(OAuth1Vocabulary.SignatureMethods)}.",
                    Child(pointer, "signatureMethod"));
                return;
            }

            var transport = ReadRequiredBoundedString(configuration, "parameterTransport", 30);

            if (transport is null)
            {
                return;
            }

            if (!OAuth1Vocabulary.ParameterTransports.Contains(transport, StringComparer.Ordinal))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{DiagnosticText.Echo(transport)}' is not a parameter transport. Expected one of: {DiagnosticText.List(OAuth1Vocabulary.ParameterTransports)}.",
                    Child(pointer, "parameterTransport"));
            }
        }

        private void ValidateRequestSigning(JsonObject configuration)
        {
            RequireKnownMembers(configuration, ["strategyId", "inputs"]);
            ValidateInputs(configuration);

            var strategyId = ReadRequiredBoundedString(configuration, "strategyId", MaxInputNameLength);

            if (strategyId is null)
            {
                return;
            }

            // The strategy id names a reviewed signer. A signer Engine does not implement must be
            // refused at load, because the alternative is a request that fails — or worse, is sent
            // unsigned — at invocation time.
            if (!ReviewedSignerIds.Contains(strategyId, StringComparer.Ordinal))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationSignerUnknown,
                    $"'{DiagnosticText.Echo(strategyId)}' is not a reviewed signer kind. Expected one of: {DiagnosticText.List(ReviewedSignerIds)}.",
                    Child(pointer, "strategyId"));
                return;
            }

            var inputs = RequireObject(configuration, "inputs");

            if (inputs is null)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "A request-signing strategy requires an 'inputs' object carrying 'accessKeyId'.",
                    Child(pointer, "inputs"));
                return;
            }

            RequireKnownMembers(inputs, ["accessKeyId"]);

            if (!TryReadBoundedString(inputs, "accessKeyId", MaxInputValueLength, out var accessKeyId)
                || string.IsNullOrWhiteSpace(accessKeyId))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'inputs.accessKeyId' is required for a request-signing strategy.",
                    Child(Child(pointer, "inputs"), "accessKeyId"));
            }
        }

        private void RequireStrategyId(JsonObject configuration)
        {
            // The strategy id is producer provenance for the reviewed strategy — it names the
            // durable strategy configuration, not a product. It must be present and bounded, but
            // its value carries no Engine behavior beyond the closed-kind branch taken above.
            if (!TryReadBoundedString(configuration, "strategyId", MaxInputNameLength, out var strategyId)
                || string.IsNullOrWhiteSpace(strategyId))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'strategyId' is required and must be a bounded non-empty string.",
                    Child(pointer, "strategyId"));
            }
        }

        private void ValidateInputs(JsonObject configuration)
        {
            if (configuration["inputs"] is null)
            {
                return;
            }

            var inputs = RequireObject(configuration, "inputs");

            if (inputs is null)
            {
                return;
            }

            if (inputs.Count > MaxInputsCount)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'inputs' declares {inputs.Count} entries, which exceeds the supported maximum of {MaxInputsCount}."),
                    Child(pointer, "inputs"));
                return;
            }

            foreach (var (name, value) in inputs)
            {
                var inputPointer = Child(Child(pointer, "inputs"), name);

                if (name.Length is 0 or > MaxInputNameLength)
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"An input name must be non-empty and no longer than {MaxInputNameLength} characters."),
                        inputPointer);
                    continue;
                }

                if (value is not JsonValue jsonValue || !jsonValue.TryGetValue<string>(out var text) || text.Length > MaxInputValueLength)
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"An input value must be a string no longer than {MaxInputValueLength} characters."),
                        inputPointer);
                }
            }
        }

        private void ValidateScopes(JsonObject configuration)
        {
            if (configuration["scopes"] is null)
            {
                return;
            }

            var scopes = configuration["scopes"] as JsonArray;

            if (scopes is null)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'scopes' must be an array of strings.",
                    Child(pointer, "scopes"));
                return;
            }

            if (scopes.Count > 500)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'scopes' declares {scopes.Count} entries, which exceeds the supported maximum of 500."),
                    Child(pointer, "scopes"));
                return;
            }

            var index = 0;

            foreach (var scope in scopes)
            {
                var scopePointer = Child(pointer, "scopes") + "/" + index.ToString(CultureInfo.InvariantCulture);
                index++;

                if (scope is not JsonValue value || !value.TryGetValue<string>(out var text))
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        "Every scope must be a string.",
                        scopePointer);
                    continue;
                }

                if (text.Length > 500 || text.Any(char.IsWhiteSpace))
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        "A scope must be no longer than 500 characters and contain no whitespace.",
                        scopePointer);
                }
            }
        }

        private void ValidateSafetySkew(JsonObject configuration)
            => ValidateOptionalInt(configuration, "accessTokenSafetySkewSeconds", 0, 300);

        private void ValidateAuthorizationParameters(JsonObject configuration)
        {
            if (configuration["authorizationParameters"] is null)
            {
                return;
            }

            var parameters = RequireObject(configuration, "authorizationParameters");

            if (parameters is null)
            {
                return;
            }

            var reserved = new HashSet<string>(StringComparer.Ordinal)
            {
                "response_type",
                "client_id",
                "redirect_uri",
                "state",
                "code_challenge",
                "code_challenge_method",
                "scope",
            };

            foreach (var (name, value) in parameters)
            {
                var parameterPointer = Child(Child(pointer, "authorizationParameters"), name);

                if (reserved.Contains(name) || name.Length is 0 or > 200)
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        $"'{DiagnosticText.Echo(name)}' is a reserved or over-long authorization parameter name.",
                        parameterPointer);
                    continue;
                }

                if (value is not JsonValue jsonValue
                    || !jsonValue.TryGetValue<string>(out var text)
                    || text.Length > 2000)
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        "An authorization parameter value must be a string no longer than 2000 characters.",
                        parameterPointer);
                }
            }
        }

        private int ValidateMappings(JsonObject parent, string member, bool headerNames)
        {
            if (parent[member] is null)
            {
                return 0;
            }

            var mappings = RequireObject(parent, member);

            if (mappings is null)
            {
                return 0;
            }

            var count = 0;

            foreach (var (name, value) in mappings)
            {
                var mappingPointer = Child(Child(pointer, "request"), name);
                count++;

                if (name.Length is 0 or > MaxInputNameLength || (headerNames && !IsWireName(name)))
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        "A mapping name must be a bounded wire name.",
                        mappingPointer);
                    continue;
                }

                ValidateValueSourceShape(value, mappingPointer);
            }

            return count;
        }

        private bool HasAuthorizationMapping(JsonObject request)
        {
            var headers = request["headers"] as JsonObject;

            return headers is not null
                && headers.Any(pair => string.Equals(pair.Key, "Authorization", StringComparison.OrdinalIgnoreCase));
        }

        private void ValidateValueSource(JsonObject parent, string member)
        {
            var source = RequireObject(parent, member);

            if (source is null)
            {
                return;
            }

            ValidateValueSourceShape(source, Child(Child(pointer, "request"), "basic"));
        }

        private void ValidateValueSourceShape(JsonNode? value, string sourcePointer)
        {
            if (value is not JsonObject source)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "Every exchange value mapping must be an object.",
                    sourcePointer);
                return;
            }

            RequireKnownMembers(source, ["source", "slot", "value"]);

            if (!TryReadBoundedString(source, "source", 20, out var kind))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'source' must be one of: input, secret, static.",
                    Child(sourcePointer, "source"));
                return;
            }

            var hasSlot = source["slot"] is not null;
            var hasValue = source["value"] is not null;

            switch (kind)
            {
                case "input":
                case "secret":
                    if (!hasSlot || hasValue)
                    {
                        Error(
                            ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                            $"A '{kind}' mapping requires 'slot' and must not declare 'value'.",
                            sourcePointer);
                    }
                    break;

                case "static":
                    if (hasSlot || !hasValue)
                    {
                        Error(
                            ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                            "A 'static' mapping requires 'value' and must not declare 'slot'.",
                            sourcePointer);
                    }
                    break;

                default:
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        $"'source' must be one of: input, secret, static. Received '{DiagnosticText.Echo(kind)}'.",
                        Child(sourcePointer, "source"));
                    break;
            }
        }

        private bool ValidateSelectorMember(JsonObject parent, string member, bool allowJsonPointer)
        {
            var selector = RequireObject(parent, member);

            if (selector is null)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{member}' is required and must be an object.",
                    Child(pointer, member));
                return false;
            }

            return ValidateSelectorObject(selector, Child(pointer, member), allowJsonPointer);
        }

        private bool ValidateSelector(JsonObject parent, string member, bool allowJsonPointer, string? selectorMember = null)
        {
            if (selectorMember is null)
            {
                var selector = RequireObject(parent, member);

                if (selector is null)
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        $"'{member}' is required and must be an object.",
                        Child(pointer, member));
                    return false;
                }

                return ValidateSelectorObject(selector, Child(pointer, member), allowJsonPointer);
            }

            // Challenge-session selectors declare 'source' and 'selector' inline instead of a
            // nested object; the accepted Platform parser reads the same two members.
            if (!TryReadBoundedString(parent, member, 30, out var source))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{member}' is required and must be a bounded string.",
                    Child(pointer, member));
                return false;
            }

            if (!TryReadBoundedString(parent, selectorMember, MaxJsonPointerLength, out var selectorText))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{selectorMember}' is required and must be a bounded string.",
                    Child(pointer, selectorMember));
                return false;
            }

            return ValidateSelectorKind(source, selectorText, allowJsonPointer, Child(pointer, selectorMember));
        }

        private bool ValidateSelectorObject(JsonObject selector, string selectorPointer, bool allowJsonPointer)
        {
            RequireKnownMembers(selector, ["source", "selector"]);

            if (!TryReadBoundedString(selector, "source", 30, out var source))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'source' must be a bounded string.",
                    Child(selectorPointer, "source"));
                return false;
            }

            if (!TryReadBoundedString(selector, "selector", MaxJsonPointerLength, out var selectorText))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'selector' must be a bounded string.",
                    Child(selectorPointer, "selector"));
                return false;
            }

            return ValidateSelectorKind(source, selectorText, allowJsonPointer, Child(selectorPointer, "selector"));
        }

        private bool ValidateSelectorKind(string source, string selector, bool allowJsonPointer, string selectorPointer)
        {
            switch (source)
            {
                case "jsonPointer" when allowJsonPointer:
                    if (!IsJsonPointer(selector))
                    {
                        Error(
                            ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                            "A JSON Pointer selector must start with '/' and use only '~0'/'~1' escapes.",
                            selectorPointer);
                        return false;
                    }

                    return true;

                case "header":
                case "cookie":
                    if (!IsWireName(selector))
                    {
                        Error(
                            ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                            "A header or cookie selector name must be a bounded wire name.",
                            selectorPointer);
                        return false;
                    }

                    return true;

                default:
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        allowJsonPointer
                            ? "'source' must be one of: jsonPointer, header, cookie."
                            : "'source' must be one of: header, cookie.",
                        selectorPointer);
                    return false;
            }
        }

        private bool ValidateExpiry(JsonObject response)
        {
            var expiry = RequireObject(response, "expiry");

            if (expiry is null)
            {
                return false;
            }

            RequireKnownMembers(expiry, ["kind", "source", "selector"]);

            if (!TryReadBoundedString(expiry, "kind", 30, out var kind)
                || kind is not ("relativeSeconds" or "unixSeconds" or "absoluteUtc"))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'expiry.kind' must be one of: relativeSeconds, unixSeconds, absoluteUtc.",
                    Child(pointer, "response"));
                return false;
            }

            if (!TryReadBoundedString(expiry, "source", 30, out var source))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'expiry.source' must be a bounded string.",
                    Child(pointer, "response"));
                return false;
            }

            if (!TryReadBoundedString(expiry, "selector", MaxJsonPointerLength, out var selector))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'expiry.selector' must be a bounded string.",
                    Child(pointer, "response"));
                return false;
            }

            return ValidateSelectorKind(source, selector, allowJsonPointer: true, Child(pointer, "response"));
        }

        private bool ValidateInjection(JsonObject injection)
        {
            RequireKnownMembers(injection, ["location", "name", "prefix"]);

            var injectionPointer = Child(pointer, "injection");

            if (!TryReadBoundedString(injection, "location", 20, out var location)
                || location is not ("bearer" or "header" or "cookie" or "query"))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "'injection.location' must be one of: bearer, header, cookie, query.",
                    Child(injectionPointer, "location"));
                return false;
            }

            var hasName = injection["name"] is not null;
            var hasPrefix = injection["prefix"] is not null;

            if (location == "bearer")
            {
                if (hasName || (hasPrefix && !IsEmptyPrefix(injection)))
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        "Bearer injection cannot declare a name or a non-empty prefix.",
                        injectionPointer);
                    return false;
                }

                return true;
            }

            if (!TryReadBoundedString(injection, "name", MaxWireNameLength, out var name) || !IsWireName(name))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    "A named injection requires a bounded valid header/cookie/query name.",
                    Child(injectionPointer, "name"));
                return false;
            }

            if (injection["prefix"] is not null)
            {
                if (!TryReadBoundedString(injection, "prefix", MaxWireNameLength, out var prefix)
                    || prefix.Contains('\r') || prefix.Contains('\n'))
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        "An injection prefix must not contain a line break.",
                        Child(injectionPointer, "prefix"));
                    return false;
                }
            }

            return true;
        }

        private bool IsEmptyPrefix(JsonObject injection)
        {
            if (injection["prefix"] is not JsonValue value || !value.TryGetValue<string>(out var prefix))
            {
                return true;
            }

            return prefix.Length == 0;
        }

        private void ValidateStatusCodes(JsonObject parent, string member = "statusCodes")
        {
            if (parent[member] is null)
            {
                return;
            }

            var codes = parent[member] as JsonArray;

            if (codes is null || codes.Count is 0 or > MaxStatusCodes)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'{member}' must be an array of at most {MaxStatusCodes} HTTP status codes."),
                    Child(pointer, member));
                return;
            }

            var index = 0;

            foreach (var code in codes)
            {
                var codePointer = Child(pointer, member) + "/" + index.ToString(CultureInfo.InvariantCulture);
                index++;

                if (code is not JsonValue value
                    || !value.TryGetValue<int>(out var status)
                    || status is < 400 or > 599)
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        "Every status code must be an integer between 400 and 599.",
                        codePointer);
                }
            }
        }

        private void ValidateOptionalBoundedString(JsonObject parent, string member, int maxLength)
        {
            if (parent[member] is null)
            {
                return;
            }

            if (!TryReadBoundedString(parent, member, maxLength, out _))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'{member}' must be a string no longer than {maxLength} characters."),
                    Child(pointer, member));
            }
        }

        private void ValidateOptionalInt(JsonObject parent, string member, int minimum, int maximum)
        {
            if (parent[member] is null)
            {
                return;
            }

            if (parent[member] is not JsonValue value || !value.TryGetValue<int>(out var number))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{member}' must be an integer.",
                    Child(pointer, member));
                return;
            }

            if (number < minimum || number > maximum)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'{member}' must be between {minimum} and {maximum}, but {number} was declared."),
                    Child(pointer, member));
            }
        }

        private bool ValidateStringArray(
            JsonObject parent,
            string member,
            int minCount,
            int maxCount,
            int maxLength)
        {
            if (parent[member] is null)
            {
                return true;
            }

            var array = parent[member] as JsonArray;

            if (array is null)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{member}' must be an array of strings.",
                    Child(pointer, member));
                return false;
            }

            if (array.Count < minCount || array.Count > maxCount)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'{member}' must declare between {minCount} and {maxCount} entries, but {array.Count} were declared."),
                    Child(pointer, member));
                return false;
            }

            var index = 0;

            foreach (var item in array)
            {
                var itemPointer = Child(pointer, member) + "/" + index.ToString(CultureInfo.InvariantCulture);
                index++;

                if (item is not JsonValue value
                    || !value.TryGetValue<string>(out var text)
                    || text.Length == 0
                    || text.Length > maxLength)
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"An entry must be a non-empty string no longer than {maxLength} characters."),
                        itemPointer);
                    return false;
                }
            }

            return true;
        }

        private void RequireEndpoint(
            JsonObject parent,
            string member,
            bool required,
            bool allowQuery = true,
            bool allowFragment = true)
        {
            if (parent[member] is null)
            {
                if (required)
                {
                    Error(
                        ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                        $"'{member}' is required for this strategy kind.",
                        Child(pointer, member));
                }

                return;
            }

            if (!TryReadBoundedString(parent, member, 2048, out var text))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{member}' must be a bounded absolute URL.",
                    Child(pointer, member));
                return;
            }

            if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)
                || uri.Scheme is not ("https" or "http")
                || string.IsNullOrEmpty(uri.Host)
                || !string.IsNullOrEmpty(uri.UserInfo)
                || (!allowQuery && !string.IsNullOrEmpty(uri.Query))
                || (!allowFragment && !string.IsNullOrEmpty(uri.Fragment)))
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{member}' must be an absolute http(s) URL with a host and no embedded credentials.",
                    Child(pointer, member));
            }
        }

        private string? ReadRequiredBoundedString(JsonObject parent, string member, int maxLength)
        {
            if (!TryReadBoundedString(parent, member, maxLength, out var value) || value.Length == 0)
            {
                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{member}' is required and must be a bounded non-empty string.",
                    Child(pointer, member));
                return null;
            }

            return value;
        }

        private static bool TryReadBoundedString(
            JsonObject parent,
            string member,
            int maxLength,
            out string value)
        {
            value = string.Empty;

            if (parent[member] is not JsonValue jsonValue
                || !jsonValue.TryGetValue<string>(out var text)
                || text.Length > maxLength)
            {
                return false;
            }

            value = text;
            return true;
        }

        private static bool TryReadInput(JsonObject configuration, string name, out string value)
        {
            value = string.Empty;

            if (configuration["inputs"] is not JsonObject inputs
                || inputs[name] is not JsonValue jsonValue
                || !jsonValue.TryGetValue<string>(out var text))
            {
                return false;
            }

            value = text;
            return true;
        }

        private JsonObject? RequireObject(JsonObject parent, string member)
        {
            if (parent[member] is null)
            {
                return null;
            }

            if (parent[member] is JsonObject value)
            {
                return value;
            }

            Error(
                ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                $"'{member}' must be an object.",
                Child(pointer, member));
            return null;
        }

        private void RequireKnownMembers(JsonObject value, IReadOnlyList<string> allowed)
        {
            foreach (var (name, _) in value)
            {
                if (allowed.Contains(name, StringComparer.Ordinal))
                {
                    continue;
                }

                Error(
                    ManifestDiagnosticCodes.AuthenticationConfigurationInvalid,
                    $"'{DiagnosticText.Echo(name)}' is not a member this strategy configuration defines here. Expected one of: {DiagnosticText.List(allowed)}.",
                    Child(pointer, name));
            }
        }

        private void RejectExecutableMembers(JsonNode? node, string nodePointer)
        {
            switch (node)
            {
                case JsonObject value:
                    foreach (var (name, child) in value)
                    {
                        var childPointer = Child(nodePointer, name);

                        if (IsExecutableMemberName(name))
                        {
                            if (_reportedExecutable.Add(childPointer))
                            {
                                Error(
                                    ManifestDiagnosticCodes.AuthenticationExecutableMember,
                                    $"'{DiagnosticText.Echo(name)}' names executable behavior, which a strategy configuration may never carry.",
                                    childPointer);
                            }

                            continue;
                        }

                        RejectExecutableMembers(child, childPointer);
                    }

                    break;

                case JsonArray array:
                    var index = 0;

                    foreach (var item in array)
                    {
                        RejectExecutableMembers(item, nodePointer + "/" + index.ToString(CultureInfo.InvariantCulture));
                        index++;
                    }

                    break;
            }
        }

        private static bool IsExecutableMemberName(string name)
            => name.Equals("regex", StringComparison.OrdinalIgnoreCase)
                || name.Equals("script", StringComparison.OrdinalIgnoreCase)
                || name.Equals("expression", StringComparison.OrdinalIgnoreCase)
                || name.Equals("template", StringComparison.OrdinalIgnoreCase)
                || name.Equals("command", StringComparison.OrdinalIgnoreCase)
                || name.Equals("shell", StringComparison.OrdinalIgnoreCase);

        private static int Depth(JsonNode? node, int depth)
        {
            if (depth > MaxStrategyConfigurationDepth)
            {
                return depth;
            }

            return node switch
            {
                JsonObject value => value.Count == 0
                    ? depth
                    : value.Max(pair => Depth(pair.Value, depth + 1)),
                JsonArray array => array.Count == 0
                    ? depth
                    : array.Max(item => Depth(item, depth + 1)),
                _ => depth,
            };
        }

        private static bool IsWireName(string? value)
            => value is { Length: > 0 and <= MaxWireNameLength }
                && value.All(character => char.IsAsciiLetterOrDigit(character)
                    || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');

        private static bool IsJsonPointer(string pointer)
        {
            if (pointer.Length > MaxJsonPointerLength)
            {
                return false;
            }

            if (pointer.Length == 0)
            {
                return true;
            }

            if (pointer[0] != '/')
            {
                return false;
            }

            foreach (var segment in pointer[1..].Split('/'))
            {
                for (var i = 0; i < segment.Length; i++)
                {
                    if (segment[i] != '~')
                    {
                        continue;
                    }

                    if (++i >= segment.Length || segment[i] is not ('0' or '1'))
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        private void Error(string code, string message, string errorPointer)
        {
            Valid = false;
            context.Error(code, message, errorPointer);
        }
    }
}
