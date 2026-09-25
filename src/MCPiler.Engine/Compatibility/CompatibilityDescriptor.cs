using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Runtime;

public static class CompatibilitySchema
{
    public const int Version = 1;
    public const string ManagedGeneration = "managed-generation";
    public const string ResponseCacheOperator = "response-cache-operator";
    public const string ResponseCacheOperatorGeneration = "1";
    public const string ContractGenerationHeader = "X-MCPiler-Contract-Generation";

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        WriteIndented = false,
    };

    public static IReadOnlyList<string> RequiredSections { get; } =
    [
        "server",
        "policy",
        "operations",
        "agentSurface",
        "credentials",
        "authentication",
        "tools",
        "search",
    ];

    public static bool TryParseRoot(string? value, out (int Major, int Minor) version)
    {
        version = default;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 32)
        {
            return false;
        }

        string[] parts = value.Split('.', StringSplitOptions.None);
        if (parts.Length != 2 || !IsCanonicalNumber(parts[0]) || !IsCanonicalNumber(parts[1]))
        {
            return false;
        }

        if (!int.TryParse(parts[0], out int major) || !int.TryParse(parts[1], out int minor)
            || major > 999_999
            || minor > 999_999)
        {
            return false;
        }

        version = (major, minor);
        return true;
    }

    public static bool IsCanonicalNumber(string? value)
    {
        if (string.IsNullOrEmpty(value) || (value.Length > 1 && value[0] == '0'))
        {
            return false;
        }

        foreach (char character in value)
        {
            if (character is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsValidContractId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64 || value[0] == '-')
        {
            return false;
        }

        bool previousDash = false;
        foreach (char character in value)
        {
            if (character == '-')
            {
                if (previousDash)
                {
                    return false;
                }

                previousDash = true;
                continue;
            }

            if (character is not (>= 'a' and <= 'z') && character is not (>= '0' and <= '9'))
            {
                return false;
            }

            previousDash = false;
        }

        return !previousDash;
    }
}

public sealed record CompatibilityRange(string Minimum, string Maximum);

public sealed record CompatibilitySectionRange(int Minimum, int Maximum);

public sealed record CompatibilityManifest(
    string Minimum,
    string Maximum,
    Dictionary<string, CompatibilitySectionRange> Sections);

public sealed record CompatibilityDescriptor(
    int SchemaVersion,
    CompatibilityManifest Manifest,
    Dictionary<string, CompatibilityRange> Contracts)
{
    public static CompatibilityDescriptor EngineSupport() => new(
        CompatibilitySchema.Version,
        new CompatibilityManifest(
            ManifestFormatSupport.Minimum.ToString(),
            ManifestFormatSupport.Maximum.ToString(),
            new Dictionary<string, CompatibilitySectionRange>(StringComparer.Ordinal)
            {
                ["server"] = new(ServerSection.FormatVersion, ServerSection.FormatVersion),
                ["policy"] = new(PolicySection.FormatVersion, PolicySection.FormatVersion),
                ["operations"] = new(OperationsSection.FormatVersion, OperationsSection.FormatVersion),
                ["agentSurface"] = new(AgentSurfaceSection.FormatVersion, AgentSurfaceSection.FormatVersion),
                ["credentials"] = new(CredentialsSection.FormatVersion, CredentialsSection.FormatVersion),
                ["authentication"] = new(AuthenticationSection.FormatVersion, AuthenticationSection.FormatVersion),
                ["tools"] = new(ToolsSection.FormatVersion, ToolsSection.FormatVersion),
                ["search"] = new(SearchSection.FormatVersion, SearchSection.FormatVersion),
            }),
        new Dictionary<string, CompatibilityRange>(StringComparer.Ordinal)
        {
            [CompatibilitySchema.ManagedGeneration] = new("1", "1"),
            [CompatibilitySchema.ResponseCacheOperator] = new("1", "1"),
        });

    public CompatibilityDescriptor Canonicalize() => new(
        SchemaVersion,
        new CompatibilityManifest(
            Manifest.Minimum,
            Manifest.Maximum,
            Manifest.Sections
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal)),
        Contracts
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));

    public string ToCanonicalJson() => JsonSerializer.Serialize(Canonicalize(), CompatibilitySchema.JsonOptions);

    public string CanonicalDigest()
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(ToCanonicalJson()));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static bool TryParse(ReadOnlySpan<byte> utf8, out CompatibilityDescriptor? descriptor, out string reasonCode, out string message)
    {
        descriptor = null;
        reasonCode = string.Empty;
        message = string.Empty;

        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF)
        {
            utf8 = utf8[3..];
        }

        try
        {
            descriptor = JsonSerializer.Deserialize<CompatibilityDescriptor>(utf8, CompatibilitySchema.JsonOptions);
        }
        catch (JsonException)
        {
            reasonCode = "compatibility/descriptor-json-invalid";
            message = "The compatibility descriptor is not valid JSON.";
            return false;
        }
        catch (NotSupportedException)
        {
            reasonCode = "compatibility/descriptor-json-unsupported";
            message = "The compatibility descriptor uses an unsupported JSON shape.";
            return false;
        }

        if (descriptor is null)
        {
            reasonCode = "compatibility/descriptor-missing";
            message = "The compatibility descriptor was empty.";
            return false;
        }

        if (!Validate(descriptor, out reasonCode, out message))
        {
            descriptor = null;
            return false;
        }

        descriptor = descriptor.Canonicalize();
        return true;
    }

    public static bool Validate(CompatibilityDescriptor descriptor, out string reasonCode, out string message)
    {
        reasonCode = string.Empty;
        message = string.Empty;

        if (descriptor.SchemaVersion != CompatibilitySchema.Version)
        {
            return Invalid("compatibility/schema-version-unsupported", "The compatibility descriptor schema version is not supported.", out reasonCode, out message);
        }

        if (descriptor.Manifest is null)
        {
            return Invalid("compatibility/manifest-missing", "The compatibility descriptor has no Manifest range.", out reasonCode, out message);
        }

        if (!TryGetRootRange(descriptor.Manifest, out reasonCode, out message))
        {
            return false;
        }

        if (descriptor.Manifest.Sections is null)
        {
            return Invalid("compatibility/sections-missing", "The compatibility descriptor has no section ranges.", out reasonCode, out message);
        }

        foreach (string section in CompatibilitySchema.RequiredSections)
        {
            if (!descriptor.Manifest.Sections.TryGetValue(section, out CompatibilitySectionRange? range))
            {
                return Invalid("compatibility/section-missing", $"The compatibility descriptor is missing the '{section}' section range.", out reasonCode, out message);
            }

            if (range is null || range.Minimum < 1 || range.Maximum < range.Minimum)
            {
                return Invalid("compatibility/section-range-invalid", $"The compatibility descriptor has an invalid '{section}' section range.", out reasonCode, out message);
            }
        }

        foreach (string section in descriptor.Manifest.Sections.Keys)
        {
            if (!CompatibilitySchema.RequiredSections.Contains(section, StringComparer.Ordinal))
            {
                return Invalid("compatibility/section-unknown", $"The compatibility descriptor contains an unknown section '{section}'.", out reasonCode, out message);
            }
        }

        if (descriptor.Contracts is null)
        {
            return Invalid("compatibility/contracts-missing", "The compatibility descriptor has no contract ranges.", out reasonCode, out message);
        }

        foreach ((string id, CompatibilityRange range) in descriptor.Contracts)
        {
            if (!CompatibilitySchema.IsValidContractId(id))
            {
                return Invalid("compatibility/contract-id-invalid", "The compatibility descriptor contains an invalid contract identifier.", out reasonCode, out message);
            }

            if (range is null || !TryParseGenerationRange(range, out int minimum, out int maximum))
            {
                return Invalid("compatibility/contract-range-invalid", $"The compatibility descriptor has an invalid '{id}' contract range.", out reasonCode, out message);
            }
        }

        return true;

        static bool Invalid(string code, string text, out string outputCode, out string outputMessage)
        {
            outputCode = code;
            outputMessage = text;
            return false;
        }
    }

    private static bool TryGetRootRange(
        CompatibilityManifest manifest,
        out string reasonCode,
        out string message)
    {
        reasonCode = string.Empty;
        message = string.Empty;

        if (!CompatibilitySchema.TryParseRoot(manifest.Minimum, out (int Major, int Minor) minimum)
            || !CompatibilitySchema.TryParseRoot(manifest.Maximum, out (int Major, int Minor) maximum))
        {
            reasonCode = "compatibility/manifest-range-invalid";
            message = "The compatibility descriptor has an invalid Manifest root range.";
            return false;
        }

        if (maximum.Major * 1_000_000 + maximum.Minor < minimum.Major * 1_000_000 + minimum.Minor)
        {
            reasonCode = "compatibility/manifest-range-inverted";
            message = "The compatibility descriptor has an inverted Manifest root range.";
            return false;
        }

        return true;
    }

    private static bool TryParseGenerationRange(CompatibilityRange range, out int minimum, out int maximum)
    {
        minimum = 0;
        maximum = 0;
        if (!CompatibilitySchema.IsCanonicalNumber(range.Minimum)
            || !CompatibilitySchema.IsCanonicalNumber(range.Maximum)
            || !int.TryParse(range.Minimum, out minimum)
            || !int.TryParse(range.Maximum, out maximum)
            || minimum < 1
            || maximum < minimum)
        {
            return false;
        }

        return true;
    }
}

public static class CompatibilityComparator
{
    public static CompatibilityResult Compare(CompatibilityDescriptor requirements, CompatibilityDescriptor support)
    {
        if (!CompatibilityDescriptor.Validate(requirements, out string requirementCode, out string requirementMessage))
        {
            return CompatibilityResult.Invalid("requirements/" + requirementCode, requirementMessage);
        }

        if (!CompatibilityDescriptor.Validate(support, out string supportCode, out string supportMessage))
        {
            return CompatibilityResult.Invalid("support/" + supportCode, supportMessage);
        }

        if (!TryRootIntersection(
                requirements.Manifest.Minimum,
                requirements.Manifest.Maximum,
                support.Manifest.Minimum,
                support.Manifest.Maximum,
                out string requiredRoot,
                out string supportedRoot))
        {
            return CompatibilityResult.Incompatible(
                "compatibility/manifest-root-incompatible",
                "manifest-root",
                requiredRoot,
                supportedRoot,
                support.SchemaVersion);
        }

        foreach (string section in CompatibilitySchema.RequiredSections)
        {
            CompatibilitySectionRange required = requirements.Manifest.Sections[section];
            CompatibilitySectionRange supported = support.Manifest.Sections[section];
            if (required.Maximum < supported.Minimum || supported.Maximum < required.Minimum)
            {
                return CompatibilityResult.Incompatible(
                    "compatibility/manifest-section-incompatible",
                    $"manifest-section/{section}",
                    $"{required.Minimum}-{required.Maximum}",
                    $"{supported.Minimum}-{supported.Maximum}",
                    support.SchemaVersion);
            }
        }

        foreach (string contract in requirements.Contracts.Keys.OrderBy(value => value, StringComparer.Ordinal))
        {
            if (!support.Contracts.TryGetValue(contract, out CompatibilityRange? supported))
            {
                return CompatibilityResult.Incompatible(
                    "compatibility/contract-missing",
                    $"contract/{contract}",
                    FormatRange(requirements.Contracts[contract]),
                    null,
                    support.SchemaVersion);
            }

            CompatibilityRange required = requirements.Contracts[contract];
            if (!TryGenerationIntersection(required, supported, out string requiredValue, out string supportedValue))
            {
                return CompatibilityResult.Incompatible(
                    "compatibility/contract-incompatible",
                    $"contract/{contract}",
                    requiredValue,
                    supportedValue,
                    support.SchemaVersion);
            }
        }

        return CompatibilityResult.Compatible(support.SchemaVersion);
    }

    private static bool TryRootIntersection(
        string requiredMinimum,
        string requiredMaximum,
        string supportedMinimum,
        string supportedMaximum,
        out string required,
        out string supported)
    {
        required = requiredMinimum + "-" + requiredMaximum;
        supported = supportedMinimum + "-" + supportedMaximum;

        if (!CompatibilitySchema.TryParseRoot(requiredMinimum, out var requiredMinimumValue)
            || !CompatibilitySchema.TryParseRoot(requiredMaximum, out var requiredMaximumValue)
            || !CompatibilitySchema.TryParseRoot(supportedMinimum, out var supportedMinimumValue)
            || !CompatibilitySchema.TryParseRoot(supportedMaximum, out var supportedMaximumValue))
        {
            return false;
        }

        return requiredMaximumValue.Major * 1_000_000 + requiredMaximumValue.Minor >= supportedMinimumValue.Major * 1_000_000 + supportedMinimumValue.Minor
            && supportedMaximumValue.Major * 1_000_000 + supportedMaximumValue.Minor >= requiredMinimumValue.Major * 1_000_000 + requiredMinimumValue.Minor;
    }

    private static bool TryGenerationIntersection(
        CompatibilityRange required,
        CompatibilityRange supported,
        out string requiredValue,
        out string supportedValue)
    {
        requiredValue = FormatRange(required);
        supportedValue = FormatRange(supported);
        if (!int.TryParse(required.Minimum, out int requiredMinimum)
            || !int.TryParse(required.Maximum, out int requiredMaximum)
            || !int.TryParse(supported.Minimum, out int supportedMinimum)
            || !int.TryParse(supported.Maximum, out int supportedMaximum))
        {
            return false;
        }

        return requiredMaximum >= supportedMinimum && supportedMaximum >= requiredMinimum;
    }

    private static string FormatRange(CompatibilityRange range) => range.Minimum + "-" + range.Maximum;
}

public sealed record CompatibilityResult(
    string Status,
    string ReasonCode,
    string Dimension,
    string? Required,
    string? Supported,
    string Message,
    int? DescriptorSchemaVersion = null)
{
    public bool IsCompatible => string.Equals(Status, "compatible", StringComparison.Ordinal);

    public static CompatibilityResult Compatible(int descriptorSchemaVersion) => new(
        "compatible",
        "compatibility/compatible",
        "contract",
        null,
        null,
        "The Platform requirements and Engine support are compatible.",
        descriptorSchemaVersion);

    public static CompatibilityResult Incompatible(
        string reasonCode,
        string dimension,
        string? required,
        string? supported,
        int? descriptorSchemaVersion = null) => new(
        "incompatible",
        reasonCode,
        dimension,
        required,
        supported,
        $"The compatibility dimension '{dimension}' does not intersect.",
        descriptorSchemaVersion);

    public static CompatibilityResult Invalid(
        string reasonCode,
        string message,
        int? descriptorSchemaVersion = null) => new(
        "invalid",
        reasonCode,
        "contract",
        null,
        null,
        message,
        descriptorSchemaVersion);
}
