using System.Text;

using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Compatibility;

public sealed class CompatibilityDescriptorTests
{
    [Fact]
    public void Engine_support_matches_the_shared_fixture()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "fixtures", "compatibility", "current-v1.json");
        string expected = File.ReadAllText(path).Trim();

        Assert.Equal(expected, CompatibilityDescriptor.EngineSupport().ToCanonicalJson());
    }

    [Fact]
    public void Current_support_matches_itself()
    {
        CompatibilityResult result = CompatibilityComparator.Compare(
            CompatibilityDescriptor.EngineSupport(),
            CompatibilityDescriptor.EngineSupport());

        Assert.True(result.IsCompatible);
    }

    [Fact]
    public void A_disjoint_section_is_named()
    {
        CompatibilityDescriptor requirements = CompatibilityDescriptor.EngineSupport();
        CompatibilityDescriptor support = requirements with
        {
            Manifest = requirements.Manifest with
            {
                Sections = new Dictionary<string, CompatibilitySectionRange>(StringComparer.Ordinal)
                {
                    ["server"] = new(2, 2),
                    ["policy"] = new(2, 2),
                    ["operations"] = new(1, 1),
                    ["agentSurface"] = new(4, 4),
                    ["credentials"] = new(4, 4),
                    ["authentication"] = new(2, 2),
                    ["tools"] = new(1, 1),
                    ["search"] = new(1, 1),
                },
            },
        };

        CompatibilityResult result = CompatibilityComparator.Compare(requirements, support);

        Assert.Equal("incompatible", result.Status);
        Assert.Equal("manifest-section/policy", result.Dimension);
    }

    [Fact]
    public void A_missing_required_contract_is_named()
    {
        CompatibilityDescriptor requirements = CompatibilityDescriptor.EngineSupport();
        CompatibilityDescriptor support = requirements with
        {
            Contracts = new Dictionary<string, CompatibilityRange>(StringComparer.Ordinal)
            {
                [CompatibilitySchema.ResponseCacheOperator] = new("1", "1"),
            },
        };

        CompatibilityResult result = CompatibilityComparator.Compare(requirements, support);

        Assert.Equal("incompatible", result.Status);
        Assert.Equal("contract/managed-generation", result.Dimension);
    }

    [Fact]
    public void Unknown_members_are_rejected()
    {
        byte[] json = Encoding.UTF8.GetBytes(
            "{\"schemaVersion\":1,\"manifest\":{\"minimum\":\"0.3\",\"maximum\":\"0.3\",\"sections\":{}},\"contracts\":{},\"unexpected\":true}");

        bool parsed = CompatibilityDescriptor.TryParse(json, out CompatibilityDescriptor? descriptor, out string code, out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/descriptor-json-invalid", code);
    }

    [Fact]
    public void Duplicate_members_are_rejected()
    {
        byte[] json = Encoding.UTF8.GetBytes(
            "{\"schemaVersion\":1,\"schemaVersion\":1,\"manifest\":{\"minimum\":\"0.3\",\"maximum\":\"0.3\",\"sections\":{}},\"contracts\":{}}");

        bool parsed = CompatibilityDescriptor.TryParse(json, out CompatibilityDescriptor? descriptor, out string code, out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/descriptor-json-invalid", code);
    }

    [Fact]
    public void Non_canonical_generation_values_are_rejected()
    {
        CompatibilityDescriptor descriptor = CompatibilityDescriptor.EngineSupport() with
        {
            Contracts = new Dictionary<string, CompatibilityRange>(StringComparer.Ordinal)
            {
                [CompatibilitySchema.ManagedGeneration] = new("01", "1"),
            },
        };

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(descriptor.ToCanonicalJson()),
            out CompatibilityDescriptor? parsedDescriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(parsedDescriptor);
        Assert.Equal("compatibility/contract-range-invalid", code);
    }

    [Fact]
    public void Compatible_result_records_descriptor_schema_version()
    {
        CompatibilityResult result = CompatibilityComparator.Compare(
            CompatibilityDescriptor.EngineSupport(),
            CompatibilityDescriptor.EngineSupport());

        Assert.True(result.IsCompatible);
        Assert.Equal(CompatibilitySchema.Version, result.DescriptorSchemaVersion);
    }
}
