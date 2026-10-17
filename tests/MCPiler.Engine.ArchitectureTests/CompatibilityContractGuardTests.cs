using System.Globalization;
using System.Text.Json;

using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Guards the half of the Engine compatibility descriptor that is a shared contract with the
/// Platform: the Manifest root and section versions, the managed-generation contract, and the
/// reviewed protocol/capability entries.
/// </summary>
/// <remarks>
/// <para>
/// The compatibility descriptor is Engine's own statement of implementation support. Platform
/// owns a separate requirements descriptor, and compatibility is their deterministic inclusive
/// intersection; one shared mutable descriptor is explicitly rejected by the independent
/// descriptor decision (it would force lockstep and turn independent fixture evolution into
/// false failure). This guard therefore pins the dimensions a Platform-published Manifest
/// depends on - root and section versions, whose writer and reader sit on opposite sides of the
/// repository split - while treating the sparse protocol/capability ranges as Engine-owned
/// support that may gain entries: every reviewed entry must stay present at its reviewed
/// generation, and an extra entry is accepted rather than refused.
/// </para>
/// <para>
/// This is deliberately not a restatement of the unit test that proves the fixture equals the
/// serializer output. That test proves the runtime and the fixture agree today; this one makes a
/// future change to the shared Manifest contract, or a silent removal or regrading of an
/// operator channel, a decision an editor has to take here as well.
/// </para>
/// </remarks>
public sealed class CompatibilityContractGuardTests
{
    /// <summary>The canonical descriptor fixture; Platform duplicates it as its own requirements baseline.</summary>
    private const string Fixture = "tests/fixtures/compatibility/current-v1.json";

    /// <summary>The Manifest root the Platform writer and this reader agree on. A bump moves both.</summary>
    private const string ManifestRoot = "0.3";

    /// <summary>
    /// The section versions of the shared Manifest contract. Platform writes these versions and
    /// Engine reads them, so changing one side alone would break every published Manifest; the
    /// values here are the reviewed pairing, not an accident of either reader.
    /// </summary>
    private static readonly Dictionary<string, int> ReviewedSections = new(StringComparer.Ordinal)
    {
        ["agentSurface"] = 5,
        ["authentication"] = 2,
        ["credentials"] = 4,
        ["operations"] = 1,
        ["policy"] = 2,
        ["search"] = 1,
        ["server"] = 2,
        ["tools"] = 1,
    };

    /// <summary>
    /// The protocol/capability contracts this build is reviewed to advertise. The set may grow -
    /// an extra Engine-only capability does not make a compatible Platform incompatible - but
    /// these entries must stay present at exactly these generations.
    /// </summary>
    private static readonly Dictionary<string, string> ReviewedContracts = new(StringComparer.Ordinal)
    {
        // Platform requires this generation before it delivers a managed generation.
        ["managed-generation"] = "2",

        // The response-cache operator channel; Engine advertises the generation it serves.
        ["response-cache-operator"] = "1",

        // The standalone-authorization operator channel. Support-only: no Platform requirement
        // refers to it, and it exists as its own contract rather than under the response-cache
        // identifier because the two channels carry different credentials and different powers.
        ["oauth-operator"] = "1",
    };

    [Fact]
    public void The_descriptor_fixture_states_exactly_the_reviewed_manifest_contract()
    {
        var text = File.ReadAllText(EngineRepository.Absolute(Fixture));
        var violation = FindManifestContractViolation(text);

        Assert.True(
            violation is null,
            $"The shared descriptor fixture no longer states the reviewed Manifest contract: {violation}");
    }

    /// <summary>
    /// The guard is checked against the mistakes it exists to catch, so that a passing fixture is
    /// evidence of the rule rather than of the checker never firing.
    /// </summary>
    [Theory]
    [InlineData("manifest-root-bumped", "0.3")]
    [InlineData("authentication-version-bumped", "authentication")]
    [InlineData("credentials-version-bumped", "credentials")]
    [InlineData("section-added", "not part of the reviewed contract")]
    [InlineData("managed-generation-regressed", "managed-generation")]
    [InlineData("oauth-operator-generation-bumped", "oauth-operator")]
    [InlineData("reviewed-contract-removed", "oauth-operator")]
    [InlineData("extra-contract-allowed", null)]
    public void The_guard_recognises_each_contract_change(string mutation, string? expectedReason)
    {
        var mutated = Mutate(FixtureText(), mutation);
        var violation = FindManifestContractViolation(mutated);

        if (expectedReason is null)
        {
            Assert.Null(violation);
            return;
        }

        Assert.NotNull(violation);
        Assert.Contains(expectedReason, violation, StringComparison.Ordinal);
    }

    /// <summary>
    /// The fixture the guard reads must be the one the descriptor ships, and the reviewed contract
    /// identifiers must be the ones the runtime declares, or the pin would describe a different
    /// artifact than the build emits.
    /// </summary>
    [Fact]
    public void The_guard_reads_the_shipped_fixture_and_the_runtime_declares_the_same_contracts()
    {
        Assert.True(
            EngineRepository.Exists(Fixture),
            $"The compatibility descriptor fixture is missing from {Fixture}, so the guard asserts nothing.");

        var source = File.ReadAllText(
            EngineRepository.Absolute("src/MCPiler.Engine/Compatibility/CompatibilityDescriptor.cs"));

        foreach (var contract in ReviewedContracts.Keys)
        {
            Assert.Contains($"\"{contract}\"", source, StringComparison.Ordinal);
        }

        Assert.Contains("EngineSupport", source, StringComparison.Ordinal);
        Assert.Contains("ManifestFormatSupport.Minimum.ToString()", source, StringComparison.Ordinal);
        Assert.Contains("ManifestFormatSupport.Maximum.ToString()", source, StringComparison.Ordinal);
    }

    /// <summary>
    /// Returns null when the JSON states the reviewed shared contract, or the first violation.
    /// An additional, well-formed contract entry is accepted on purpose: Engine support may
    /// outgrow Platform requirements, and the intersection rule is what makes that safe.
    /// </summary>
    private static string? FindManifestContractViolation(string json)
    {
        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return "the fixture is not valid JSON";
        }

        using (document)
        {
            var root = document.RootElement;

            if (!root.TryGetProperty("manifest", out var manifest))
            {
                return "the 'manifest' member is missing";
            }

            if (!TryReadRootRange(manifest, out var minimum, out var maximum)
                || minimum != ManifestRoot
                || maximum != ManifestRoot)
            {
                return $"the Manifest root range is not exactly '{ManifestRoot}'";
            }

            if (!manifest.TryGetProperty("sections", out var sections)
                || sections.ValueKind != JsonValueKind.Object)
            {
                return "the 'sections' object is missing";
            }

            var seenSections = new Dictionary<string, int>(StringComparer.Ordinal);

            foreach (var section in sections.EnumerateObject())
            {
                if (!ReviewedSections.TryGetValue(section.Name, out var reviewed))
                {
                    return $"section '{section.Name}' is not part of the reviewed contract";
                }

                if (!TryReadSectionRange(section.Value, out var sectionMinimum, out var sectionMaximum)
                    || sectionMinimum != reviewed
                    || sectionMaximum != reviewed)
                {
                    return $"section '{section.Name}' is not the reviewed version {reviewed}";
                }

                seenSections[section.Name] = reviewed;
            }

            foreach (var section in ReviewedSections.Keys)
            {
                if (!seenSections.ContainsKey(section))
                {
                    return $"section '{section}' is missing";
                }
            }

            if (!root.TryGetProperty("contracts", out var contracts)
                || contracts.ValueKind != JsonValueKind.Object)
            {
                return "the 'contracts' object is missing";
            }

            var seenContracts = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var contract in contracts.EnumerateObject())
            {
                if (!TryReadGenerationRange(contract.Value, out var contractMinimum, out var contractMaximum))
                {
                    return $"contract '{contract.Name}' is not a single valid generation";
                }

                seenContracts[contract.Name] = contractMinimum.ToString(CultureInfo.InvariantCulture);

                if (contractMinimum != contractMaximum)
                {
                    return $"contract '{contract.Name}' is not a single generation";
                }
            }

            foreach (var contract in ReviewedContracts)
            {
                if (!seenContracts.TryGetValue(contract.Key, out var generation))
                {
                    return $"reviewed contract '{contract.Key}' is missing";
                }

                if (generation != contract.Value)
                {
                    return $"contract '{contract.Key}' is generation {generation}, reviewed {contract.Value}";
                }
            }

            return null;
        }
    }

    private static bool TryReadRootRange(JsonElement manifest, out string minimum, out string maximum)
    {
        minimum = string.Empty;
        maximum = string.Empty;

        return manifest.TryGetProperty("minimum", out var minimumElement)
            && minimumElement.ValueKind == JsonValueKind.String
            && !string.IsNullOrEmpty(minimum = minimumElement.GetString()!)
            && manifest.TryGetProperty("maximum", out var maximumElement)
            && maximumElement.ValueKind == JsonValueKind.String
            && !string.IsNullOrEmpty(maximum = maximumElement.GetString()!);
    }

    private static bool TryReadSectionRange(JsonElement range, out int minimum, out int maximum)
        => TryReadNumberRange(range, out minimum, out maximum)
            && minimum >= 1
            && maximum >= minimum;

    /// <summary>Generation ranges are canonical integer strings, as the descriptor schema requires.</summary>
    private static bool TryReadGenerationRange(JsonElement range, out int minimum, out int maximum)
        => TryReadNumberRange(range, out minimum, out maximum, asString: true)
            && minimum >= 1
            && maximum >= minimum;

    private static bool TryReadNumberRange(JsonElement range, out int minimum, out int maximum, bool asString = false)
    {
        minimum = 0;
        maximum = 0;

        if (range.ValueKind != JsonValueKind.Object
            || !range.TryGetProperty("minimum", out var minimumElement)
            || !range.TryGetProperty("maximum", out var maximumElement))
        {
            return false;
        }

        return TryReadCanonicalInteger(minimumElement, asString, out minimum)
            && TryReadCanonicalInteger(maximumElement, asString, out maximum);
    }

    private static bool TryReadCanonicalInteger(JsonElement element, bool asString, out int value)
    {
        value = 0;

        if (asString)
        {
            if (element.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var text = element.GetString()!;
            if (text.Length == 0 || (text.Length > 1 && text[0] == '0'))
            {
                return false;
            }

            return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
        }

        return element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out value);
    }

    private static string FixtureText()
        => File.ReadAllText(EngineRepository.Absolute(Fixture));

    /// <summary>Applies one reviewed mutation to the fixture bytes, or the identity for the control.</summary>
    private static string Mutate(string fixture, string mutation) => mutation switch
    {
        "manifest-root-bumped"
            => fixture.Replace("\"maximum\":\"0.3\"", "\"maximum\":\"0.4\"", StringComparison.Ordinal),
        "authentication-version-bumped"
            => fixture.Replace(
                "\"authentication\":{\"minimum\":2,\"maximum\":2}",
                "\"authentication\":{\"minimum\":3,\"maximum\":3}",
                StringComparison.Ordinal),
        "credentials-version-bumped"
            => fixture.Replace(
                "\"credentials\":{\"minimum\":4,\"maximum\":4}",
                "\"credentials\":{\"minimum\":3,\"maximum\":3}",
                StringComparison.Ordinal),
        "section-added"
            => fixture.Replace(
                "\"sections\":{",
                "\"sections\":{\"futureSection\":{\"minimum\":1,\"maximum\":1},",
                StringComparison.Ordinal),
        "managed-generation-regressed"
            => fixture.Replace(
                "\"managed-generation\":{\"minimum\":\"2\",\"maximum\":\"2\"}",
                "\"managed-generation\":{\"minimum\":\"1\",\"maximum\":\"1\"}",
                StringComparison.Ordinal),
        "oauth-operator-generation-bumped"
            => fixture.Replace(
                "\"oauth-operator\":{\"minimum\":\"1\",\"maximum\":\"1\"}",
                "\"oauth-operator\":{\"minimum\":\"2\",\"maximum\":\"2\"}",
                StringComparison.Ordinal),
        "reviewed-contract-removed"
            => fixture.Replace(
                ",\"oauth-operator\":{\"minimum\":\"1\",\"maximum\":\"1\"}",
                string.Empty,
                StringComparison.Ordinal),
        "extra-contract-allowed"
            => fixture.Replace(
                "\"contracts\":{",
                "\"contracts\":{\"future-capability\":{\"minimum\":\"9\",\"maximum\":\"9\"},",
                StringComparison.Ordinal),
        _ => fixture,
    };
}
