using System.Globalization;
using System.Text;

using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Compatibility;

public sealed class CompatibilityDescriptorAdversarialTests
{
    private const string CanonicalText =
        "{\"schemaVersion\":1,\"manifest\":{\"minimum\":\"0.3\",\"maximum\":\"0.3\",\"sections\":{\"agentSurface\":{\"minimum\":4,\"maximum\":4},\"authentication\":{\"minimum\":2,\"maximum\":2},\"credentials\":{\"minimum\":4,\"maximum\":4},\"operations\":{\"minimum\":1,\"maximum\":1},\"policy\":{\"minimum\":1,\"maximum\":1},\"search\":{\"minimum\":1,\"maximum\":1},\"server\":{\"minimum\":2,\"maximum\":2},\"tools\":{\"minimum\":1,\"maximum\":1}}},\"contracts\":{\"managed-generation\":{\"minimum\":\"1\",\"maximum\":\"1\"},\"response-cache-operator\":{\"minimum\":\"1\",\"maximum\":\"1\"}}}";

    private const string DisjointPolicySectionText =
        "{\"schemaVersion\":1,\"manifest\":{\"minimum\":\"0.3\",\"maximum\":\"0.3\",\"sections\":{\"agentSurface\":{\"minimum\":4,\"maximum\":4},\"authentication\":{\"minimum\":2,\"maximum\":2},\"credentials\":{\"minimum\":4,\"maximum\":4},\"operations\":{\"minimum\":1,\"maximum\":1},\"policy\":{\"minimum\":2,\"maximum\":2},\"search\":{\"minimum\":1,\"maximum\":1},\"server\":{\"minimum\":2,\"maximum\":2},\"tools\":{\"minimum\":1,\"maximum\":1}}},\"contracts\":{\"managed-generation\":{\"minimum\":\"1\",\"maximum\":\"1\"},\"response-cache-operator\":{\"minimum\":\"1\",\"maximum\":\"1\"}}}";

    [Theory]
    [InlineData("canonical")]
    [InlineData("crlf-pretty")]
    [InlineData("lf-tab-pretty")]
    [InlineData("spacey-separators")]
    [InlineData("newline-between-values")]
    [InlineData("outer-whitespace")]
    [InlineData("utf8-bom")]
    public void Equivalent_serializations_canonicalize_to_one_form(string format)
    {
        bool parsed = CompatibilityDescriptor.TryParse(Reformat(CanonicalText, format), out CompatibilityDescriptor? descriptor, out string code, out string message);

        Assert.True(parsed, $"{format}: {code} {message}");
        Assert.NotNull(descriptor);
        Assert.Equal(CanonicalText, descriptor.ToCanonicalJson());
        Assert.Equal(
            CompatibilityDescriptor.EngineSupport().CanonicalDigest(),
            descriptor.CanonicalDigest());
    }

    [Theory]
    [InlineData("canonical")]
    [InlineData("crlf-pretty")]
    [InlineData("spacey-separators")]
    [InlineData("utf8-bom")]
    public void Equivalent_support_serializations_produce_one_verdict(string format)
    {
        CompatibilityResult expected = Compare(DisjointPolicySectionText, "canonical");

        CompatibilityResult actual = Compare(DisjointPolicySectionText, format);

        Assert.Equal("incompatible", actual.Status);
        Assert.Equal(expected.Status, actual.Status);
        Assert.Equal(expected.ReasonCode, actual.ReasonCode);
        Assert.Equal(expected.Dimension, actual.Dimension);
        Assert.Equal(expected.Required, actual.Required);
        Assert.Equal(expected.Supported, actual.Supported);
        Assert.Equal("manifest-section/policy", actual.Dimension);
    }

    [Theory]
    [InlineData("manifest-root")]
    [InlineData("contract-minimum")]
    [InlineData("contract-maximum")]
    public void Escaped_digits_canonicalize_to_the_same_descriptor(string target)
    {
        string escaped = target switch
        {
            "manifest-root" => CanonicalText.Replace("\"0.3\"", "\"\\u0030.3\"", StringComparison.Ordinal),
            "contract-minimum" => CanonicalText.Replace("\"1\",\"maximum\"", "\"\\u0031\",\"maximum\"", StringComparison.Ordinal),
            _ => CanonicalText.Replace("\"maximum\":\"1\"", "\"maximum\":\"\\u0031\"", StringComparison.Ordinal),
        };

        Assert.NotEqual(CanonicalText, escaped);
        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(escaped),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out string message);

        Assert.True(parsed, $"{target}: {code} {message}");
        Assert.NotNull(descriptor);
        Assert.Equal(CanonicalText, descriptor.ToCanonicalJson());
    }

    [Fact]
    public void Escaping_cannot_hide_an_invalid_contract_identifier()
    {
        string escaped = CanonicalText.Replace("\"managed-generation\"", "\"\\u002Dmanaged-generation\"", StringComparison.Ordinal);

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(escaped),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/contract-id-invalid", code);
    }

    [Fact]
    public void Escaping_cannot_hide_a_non_canonical_generation()
    {
        string escaped = CanonicalText.Replace("\"1\",\"maximum\":\"1\"}", "\"\\u0030\\u0031\",\"maximum\":\"1\"}", StringComparison.Ordinal);

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(escaped),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/contract-range-invalid", code);
    }

    [Theory]
    [InlineData("\uFF13")]
    [InlineData("\u0663")]
    [InlineData("\u2462")]
    public void Non_ascii_digit_lookalikes_are_rejected(string lookalike)
    {
        string json = CanonicalText.Replace("\"1\",\"maximum\":\"1\"}", $"\"{lookalike}\",\"maximum\":\"1\"}}", StringComparison.Ordinal);

        Assert.NotEqual(CanonicalText, json);
        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(json),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/contract-range-invalid", code);
    }

    [Fact]
    public void A_renamed_required_section_is_reported_as_missing()
    {
        string json = CanonicalText.Replace("\"policy\"", "\"polic\\u044F\"", StringComparison.Ordinal);

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(json),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/section-missing", code);
    }

    [Fact]
    public void An_extra_non_ascii_section_name_is_rejected_as_unknown()
    {
        string json = WithExtraSection("\"polic\\u044F\":{\"minimum\":1,\"maximum\":1}");

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(json),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/section-unknown", code);
    }

    [Fact]
    public void An_oversized_section_name_is_rejected_as_unknown()
    {
        string json = WithExtraSection($"\"{new string('x', 10_000)}\":{{\"minimum\":1,\"maximum\":1}}");

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(json),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/section-unknown", code);
    }

    [Fact]
    public void An_oversized_manifest_root_is_rejected_without_throwing()
    {
        string hostile = new('9', 100_000);
        string json = CanonicalText.Replace("\"0.3\",\"maximum\":\"0.3\"", $"\"{hostile}\",\"maximum\":\"0.3\"", StringComparison.Ordinal);

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(json),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/manifest-range-invalid", code);
    }

    [Fact]
    public void An_oversized_contract_identifier_is_rejected_without_throwing()
    {
        string hostile = new('a', 20_000);
        string json = CanonicalText.Replace("\"managed-generation\"", $"\"{hostile}\"", StringComparison.Ordinal);

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(json),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/contract-id-invalid", code);
    }

    [Fact]
    public void Deep_nesting_is_rejected_as_invalid_json()
    {
        var builder = new StringBuilder("{\"schemaVersion\":1,\"manifest\":{\"minimum\":\"0.3\",\"maximum\":\"0.3\",\"sections\":{}},\"contracts\":");
        builder.Append(new string('[', 200));
        builder.Append(new string(']', 200));
        builder.Append('}');

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(builder.ToString()),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/descriptor-json-invalid", code);
    }

    [Fact]
    public void Many_repeated_unknown_members_are_rejected_as_invalid_json()
    {
        var builder = new StringBuilder("{\"schemaVersion\":1,\"manifest\":{\"minimum\":\"0.3\",\"maximum\":\"0.3\",\"sections\":{}},\"contracts\":{}");
        for (int index = 0; index < 5_000; index++)
        {
            builder.Append(string.Create(CultureInfo.InvariantCulture, $",\"padding{index}\":{index}"));
        }

        builder.Append('}');

        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(builder.ToString()),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/descriptor-json-invalid", code);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\n\t ")]
    public void Empty_and_whitespace_only_payloads_are_reported_as_invalid_json(string payload)
    {
        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes(payload),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/descriptor-json-invalid", code);
    }

    [Fact]
    public void A_json_null_payload_is_reported_as_missing()
    {
        bool parsed = CompatibilityDescriptor.TryParse(
            Encoding.UTF8.GetBytes("null"),
            out CompatibilityDescriptor? descriptor,
            out string code,
            out _);

        Assert.False(parsed);
        Assert.Null(descriptor);
        Assert.Equal("compatibility/descriptor-missing", code);
    }

    [Theory]
    [InlineData("1-1", "1-1", true)]
    [InlineData("1-2", "2-3", true)]
    [InlineData("1-2", "3-3", false)]
    [InlineData("2-2", "1-1", false)]
    [InlineData("1-3", "2-2", true)]
    public void Generation_ranges_intersect_inclusively_at_the_boundary(string required, string supported, bool expected)
    {
        CompatibilityResult result = CompatibilityComparator.Compare(
            DescriptorWithContract(required),
            DescriptorWithContract(supported));

        Assert.Equal(expected, result.IsCompatible);
    }

    [Theory]
    [InlineData("0.3-0.3", "0.3-0.3", true)]
    [InlineData("0.3-0.4", "0.4-0.5", true)]
    [InlineData("0.3-0.3", "0.4-0.4", false)]
    [InlineData("1.0-1.0", "0.3-0.9", false)]
    public void Manifest_root_ranges_intersect_inclusively_at_the_boundary(string required, string supported, bool expected)
    {
        CompatibilityResult result = CompatibilityComparator.Compare(
            DescriptorWithRoot(required),
            DescriptorWithRoot(supported));

        Assert.Equal(expected, result.IsCompatible);
    }

    private static string WithExtraSection(string extraSection)
    {
        const string Anchor = "\"tools\":{\"minimum\":1,\"maximum\":1}}";
        const string Replacement = "\"tools\":{\"minimum\":1,\"maximum\":1},";

        Assert.Contains(Anchor, CanonicalText, StringComparison.Ordinal);
        return CanonicalText.Replace(Anchor, Replacement + extraSection + "}", StringComparison.Ordinal);
    }

    private static CompatibilityResult Compare(string supportText, string format)
    {
        bool parsed = CompatibilityDescriptor.TryParse(Reformat(supportText, format), out CompatibilityDescriptor? support, out string code, out string message);

        Assert.True(parsed, $"{format}: {code} {message}");
        Assert.NotNull(support);
        return CompatibilityComparator.Compare(CompatibilityDescriptor.EngineSupport(), support);
    }

    private static CompatibilityDescriptor DescriptorWithContract(string range)
    {
        string[] parts = range.Split('-');
        return CompatibilityDescriptor.EngineSupport() with
        {
            Contracts = new Dictionary<string, CompatibilityRange>(StringComparer.Ordinal)
            {
                [CompatibilitySchema.ManagedGeneration] = new(parts[0], parts[1]),
                [CompatibilitySchema.ResponseCacheOperator] = new("1", "1"),
            },
        };
    }

    private static CompatibilityDescriptor DescriptorWithRoot(string range)
    {
        string[] parts = range.Split('-');
        return CompatibilityDescriptor.EngineSupport() with
        {
            Manifest = CompatibilityDescriptor.EngineSupport().Manifest with
            {
                Minimum = parts[0],
                Maximum = parts[1],
            },
        };
    }

    private static byte[] Reformat(string canonical, string format)
    {
        switch (format)
        {
            case "canonical":
                return Encoding.UTF8.GetBytes(canonical);
            case "crlf-pretty":
                return Encoding.UTF8.GetBytes(Pretty(canonical, "  ", "\r\n"));
            case "lf-tab-pretty":
                return Encoding.UTF8.GetBytes(Pretty(canonical, "\t", "\n"));
            case "spacey-separators":
                return Encoding.UTF8.GetBytes(
                    canonical.Replace(",", ", ", StringComparison.Ordinal).Replace(":", ": ", StringComparison.Ordinal));
            case "newline-between-values":
                return Encoding.UTF8.GetBytes(canonical.Replace(",", ",\n", StringComparison.Ordinal));
            case "outer-whitespace":
                return Encoding.UTF8.GetBytes("\n\t  " + canonical + "  \n\t");
            case "utf8-bom":
            {
                byte[] body = Encoding.UTF8.GetBytes(canonical);
                var withBom = new byte[body.Length + 3];
                withBom[0] = 0xEF;
                withBom[1] = 0xBB;
                withBom[2] = 0xBF;
                body.CopyTo(withBom, 3);
                return withBom;
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(format), format, "Unknown format.");
        }
    }

    private static string Pretty(string json, string indent, string newLine)
    {
        var builder = new StringBuilder();
        int depth = 0;
        foreach (char character in json)
        {
            switch (character)
            {
                case '{':
                case '[':
                    builder.Append(character);
                    depth++;
                    builder.Append(newLine).Append(Indent(indent, depth));
                    break;
                case '}':
                case ']':
                    depth--;
                    builder.Append(newLine).Append(Indent(indent, depth)).Append(character);
                    break;
                case ',':
                    builder.Append(character).Append(newLine).Append(Indent(indent, depth));
                    break;
                case ':':
                    builder.Append(": ");
                    break;
                default:
                    builder.Append(character);
                    break;
            }
        }

        return builder.ToString();
    }

    private static string Indent(string indent, int depth)
    {
        var builder = new StringBuilder(indent.Length * depth);
        for (int level = 0; level < depth; level++)
        {
            builder.Append(indent);
        }

        return builder.ToString();
    }
}
