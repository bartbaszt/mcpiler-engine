using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution.Serialization;

/// <summary>
/// Serializes a path, query, header, or cookie parameter across the styles and explode combinations
/// the operation model can express, for primitive, array, and object values.
/// </summary>
/// <remarks>
/// <para>
/// Style and explode are read from the parameter's effective values, so a parameter that declares
/// neither behaves exactly like one that declares the documented defaults. That is not a
/// convenience: a writer omits a style or explode equal to the default, so the two forms are the
/// same document and must serialize identically.
/// </para>
/// <para>
/// A style this serializer does not implement fails compilation. There is no fallback, because a
/// substituted style produces a legal request carrying a different meaning, and nothing downstream
/// can tell that happened.
/// </para>
/// </remarks>
public static class ParameterSerializer
{
    /// <summary>Serializes a path parameter into the replacement text for its <c>{name}</c> placeholder.</summary>
    public static string PathValue(ManifestParameter p, JsonNode? value)
        => p.EffectiveStyle switch
        {
            ParameterStyle.Simple => Encode(ScalarText(value), p.AllowReserved),
            ParameterStyle.Matrix => Matrix(p.Name, value, p.EffectiveExplode, p.AllowReserved),
            ParameterStyle.Label => Label(value, p.EffectiveExplode, p.AllowReserved),
            _ => throw new UnsupportedSerializationException(
                $"Path parameter '{p.Name}' declares unsupported style '{Vocabulary.Write(p.EffectiveStyle)}'.",
                p.Name),
        };

    /// <summary>Serializes a query parameter into its full query contribution, name included.</summary>
    public static string QueryValue(ManifestParameter p, JsonNode? value)
    {
        var enc = p.AllowReserved;
        var explode = p.EffectiveExplode;

        switch (p.EffectiveStyle)
        {
            case ParameterStyle.Form:
                if (value is JsonArray arr && explode)
                {
                    return string.Join("&", arr.Select(v => $"{Encode(p.Name, enc)}={Encode(ScalarText(v), enc)}"));
                }

                if (value is JsonObject obj && explode)
                {
                    return string.Join("&", obj.Select(kv => $"{Encode(kv.Key, enc)}={Encode(ScalarText(kv.Value), enc)}"));
                }

                return $"{Encode(p.Name, enc)}={FormValueBody(value, enc)}";

            case ParameterStyle.SpaceDelimited:
                return $"{Encode(p.Name, enc)}={SpaceDelimited(value, enc)}";

            case ParameterStyle.PipeDelimited:
                return $"{Encode(p.Name, enc)}={PipeDelimited(value, enc)}";

            case ParameterStyle.DeepObject:
                return DeepObject(p.Name, value, enc);

            default:
                throw new UnsupportedSerializationException(
                    $"Query parameter '{p.Name}' declares unsupported style '{Vocabulary.Write(p.EffectiveStyle)}'.",
                    p.Name);
        }
    }

    /// <summary>Serializes a header parameter into its header value.</summary>
    public static string HeaderValue(ManifestParameter p, JsonNode? value)
    {
        if (p.EffectiveStyle != ParameterStyle.Simple)
        {
            throw new UnsupportedSerializationException(
                $"Header parameter '{p.Name}' declares unsupported style '{Vocabulary.Write(p.EffectiveStyle)}'.",
                p.Name);
        }

        return SimpleValue(value, p.AllowReserved);
    }

    /// <summary>Serializes a cookie parameter into its <c>name=value</c> contribution.</summary>
    public static string CookieValue(ManifestParameter p, JsonNode? value)
    {
        if (p.EffectiveStyle != ParameterStyle.Form)
        {
            throw new UnsupportedSerializationException(
                $"Cookie parameter '{p.Name}' declares unsupported style '{Vocabulary.Write(p.EffectiveStyle)}'.",
                p.Name);
        }

        return FormValue(p.Name, value, p.EffectiveExplode, p.AllowReserved);
    }

    // -- value-form builders -------------------------------------------------

    /// <summary>Encodes a value body without its parameter name, joining an array or object with commas.</summary>
    private static string FormValueBody(JsonNode? value, bool enc)
        => value switch
        {
            JsonArray arr => string.Join(",", arr.Select(v => Encode(ScalarText(v), enc))),
            JsonObject obj => string.Join(
                ",",
                obj.SelectMany(kv => new[] { Encode(kv.Key, enc), Encode(ScalarText(kv.Value), enc) })),
            _ => Encode(ScalarText(value), enc),
        };

    private static string FormValue(string parameterName, JsonNode? value, bool explode, bool enc)
    {
        var name = Encode(parameterName, enc);

        switch (value)
        {
            case JsonArray arr:
                return explode
                    ? string.Join("&", arr.Select(v => $"{name}={Encode(ScalarText(v), enc)}"))
                    : $"{name}={string.Join(",", arr.Select(v => Encode(ScalarText(v), enc)))}";

            case JsonObject obj:
                return explode
                    ? string.Join("&", obj.Select(kv => $"{Encode(kv.Key, enc)}={Encode(ScalarText(kv.Value), enc)}"))
                    : $"{name}={string.Join(",", obj.SelectMany(kv => new[] { Encode(kv.Key, enc), Encode(ScalarText(kv.Value), enc) }))}";

            default:
                return $"{name}={Encode(ScalarText(value), enc)}";
        }
    }

    /// <summary>
    /// The simple-style value form, which joins an array or an object's flattened pairs with commas.
    /// </summary>
    /// <remarks>
    /// Explode does not reach this form. The simple style has no exploded spelling for a header, and
    /// the model's default explode for a simple-style parameter is false, so an exploded simple value
    /// is not expressible.
    /// </remarks>
    private static string SimpleValue(JsonNode? value, bool allowReserved)
        => value switch
        {
            JsonArray arr => string.Join(",", arr.Select(v => Encode(ScalarText(v), allowReserved))),
            JsonObject obj => string.Join(
                ",",
                obj.SelectMany(kv => new[] { Encode(kv.Key, allowReserved), Encode(ScalarText(kv.Value), allowReserved) })),
            _ => Encode(ScalarText(value), allowReserved),
        };

    private static string Matrix(string name, JsonNode? value, bool explode, bool allowReserved)
    {
        if (explode && value is JsonArray arr)
        {
            return string.Concat(arr.Select(v => $";{Encode(name, allowReserved)}={Encode(ScalarText(v), allowReserved)}"));
        }

        if (explode && value is JsonObject obj)
        {
            return string.Concat(obj.Select(kv => $";{Encode(kv.Key, allowReserved)}={Encode(ScalarText(kv.Value), allowReserved)}"));
        }

        return $";{Encode(name, allowReserved)}={SimpleValue(value, allowReserved)}";
    }

    private static string Label(JsonNode? value, bool explode, bool allowReserved)
    {
        if (explode && value is JsonArray arr)
        {
            return string.Concat(arr.Select(v => $".{Encode(ScalarText(v), allowReserved)}"));
        }

        if (explode && value is JsonObject obj)
        {
            return string.Concat(obj.Select(kv => $".{Encode(kv.Key, allowReserved)}={Encode(ScalarText(kv.Value), allowReserved)}"));
        }

        return $".{SimpleValue(value, allowReserved)}";
    }

    private static string SpaceDelimited(JsonNode? value, bool allowReserved)
        => value is JsonArray arr
            ? string.Join("%20", arr.Select(v => Encode(ScalarText(v), allowReserved)))
            : Encode(ScalarText(value), allowReserved);

    private static string PipeDelimited(JsonNode? value, bool allowReserved)
        => value is JsonArray arr
            ? string.Join("|", arr.Select(v => Encode(ScalarText(v), allowReserved)))
            : Encode(ScalarText(value), allowReserved);

    private static string DeepObject(string name, JsonNode? value, bool allowReserved)
    {
        if (value is not JsonObject obj)
        {
            throw new UnsupportedSerializationException(
                $"Parameter '{name}' uses deepObject style but the supplied value is not an object.",
                name);
        }

        return string.Join(
            "&",
            obj.Select(kv =>
                $"{Encode(name, allowReserved)}[{Encode(kv.Key, allowReserved)}]={Encode(ScalarText(kv.Value), allowReserved)}"));
    }

    /// <summary>Renders a JSON node as the scalar text a parameter carries.</summary>
    /// <remarks>
    /// A JSON string yields its unquoted content; anything else yields its JSON spelling. That is why
    /// a number and a boolean are transmitted as <c>1</c> and <c>true</c> rather than as quoted text.
    /// A JSON null cannot reach this method as a value: the node model represents it as a null
    /// reference, so an explicit null and an absent argument are one case here and both yield the
    /// empty string.
    /// </remarks>
    public static string ScalarText(JsonNode? node) => node switch
    {
        null => string.Empty,
        JsonValue v => v.TryGetValue<string>(out var s) ? s : v.ToJsonString(),
        _ => node.ToJsonString(),
    };

    /// <summary>Percent-encodes a single value.</summary>
    public static string Encode(string value, bool allowReserved) => PercentEncoding.Encode(value, allowReserved);
}
