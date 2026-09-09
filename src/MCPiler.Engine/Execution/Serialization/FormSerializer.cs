using System.Text;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.Execution.Serialization;

/// <summary>
/// Writes an object value as <c>application/x-www-form-urlencoded</c> body bytes.
/// </summary>
/// <remarks>
/// An array repeats its key; a nested object is flattened into bracket notation. The declared schema
/// is deliberately not consulted: the value's own JSON shape decides the encoding, so a body whose
/// shape disagrees with its schema is transmitted as given rather than reshaped to fit. Validating
/// that disagreement is a separate concern from writing the bytes.
/// </remarks>
public static class FormSerializer
{
    /// <summary>Writes the body bytes for an object value.</summary>
    public static byte[] Serialize(JsonNode? value)
    {
        if (value is not JsonObject obj)
        {
            throw new UnsupportedSerializationException("Form-urlencoded body requires an object value.");
        }

        var sb = new StringBuilder();
        var first = true;

        foreach (var kv in obj)
        {
            foreach (var pair in Flatten(kv.Key, kv.Value))
            {
                if (!first)
                {
                    sb.Append('&');
                }

                first = false;
                sb.Append(pair);
            }
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static IEnumerable<string> Flatten(string prefix, JsonNode? value)
    {
        switch (value)
        {
            case JsonArray array:
                foreach (var item in array)
                {
                    yield return $"{Encode(prefix)}={Encode(ParameterSerializer.ScalarText(item))}";
                }

                break;

            case JsonObject nested:
                foreach (var kv in nested)
                {
                    foreach (var pair in Flatten($"{prefix}[{kv.Key}]", kv.Value))
                    {
                        yield return pair;
                    }
                }

                break;

            default:
                yield return $"{Encode(prefix)}={Encode(ParameterSerializer.ScalarText(value))}";
                break;
        }
    }

    // A form body never preserves reserved characters: the body is one flat encoding with no
    // parameter to declare an allowance.
    private static string Encode(string value) => PercentEncoding.Encode(value, allowReserved: false);
}
