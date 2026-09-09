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
    {
        if (IsContentTyped(p))
        {
            return ContentValue(p, value);
        }

        return p.EffectiveStyle switch
        {
            ParameterStyle.Simple => Encode(ScalarText(value), p.AllowReserved),
            ParameterStyle.Matrix => Matrix(p.Name, value, p.EffectiveExplode, p.AllowReserved),
            ParameterStyle.Label => Label(value, p.EffectiveExplode, p.AllowReserved),
            _ => throw new UnsupportedSerializationException(
                $"Path parameter '{p.Name}' declares unsupported style '{Vocabulary.Write(p.EffectiveStyle)}'.",
                p.Name),
        };
    }

    /// <summary>Serializes a query parameter into its full query contribution, name included.</summary>
    public static string QueryValue(ManifestParameter p, JsonNode? value)
    {
        if (IsContentTyped(p))
        {
            return $"{Encode(p.Name, p.AllowReserved)}={ContentValue(p, value)}";
        }

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
        if (IsContentTyped(p))
        {
            return ContentValue(p, value);
        }

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
        if (IsContentTyped(p))
        {
            return $"{Encode(p.Name, p.AllowReserved)}={ContentValue(p, value)}";
        }

        if (p.EffectiveStyle != ParameterStyle.Form)
        {
            throw new UnsupportedSerializationException(
                $"Cookie parameter '{p.Name}' declares unsupported style '{Vocabulary.Write(p.EffectiveStyle)}'.",
                p.Name);
        }

        return CookieFormValue(p.Name, value, p.EffectiveExplode, p.AllowReserved);
    }

    // -- content-typed parameters --------------------------------------------

    /// <summary>True when the effective contract describes this parameter by media type rather than by style.</summary>
    private static bool IsContentTyped(ManifestParameter p) => p.Content is { Count: > 0 };

    /// <summary>
    /// Serializes a parameter whose effective contract declares <c>content</c> instead of a style,
    /// writing the value in the declared media type before percent-encoding it for its location.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A style says how a value is spread across a URI construct; a media type says how the value is
    /// written before it gets there. The two are alternatives, so a content-typed parameter has no
    /// style to dispatch on and every entry point has to ask before it reaches its style switch.
    /// Until this existed the declaration was read into the model and then ignored, so the parameter
    /// contributed nothing to the request and nothing reported that.
    /// </para>
    /// <para>
    /// Exactly one media type is allowed, so a second is a defect in the contract rather than a
    /// choice to resolve here. A media type with no defined parameter encoding fails compilation for
    /// the same reason an unsupported style does: guessing would put bytes on the wire the contract
    /// never described.
    /// </para>
    /// </remarks>
    private static string ContentValue(ManifestParameter p, JsonNode? value)
    {
        if (p.Content!.Count > 1)
        {
            throw new UnsupportedSerializationException(
                $"Parameter '{p.Name}' declares {p.Content.Count} content media types; exactly one is allowed.",
                p.Name);
        }

        return Encode(ContentText(p.Name, p.Content.Keys.First(), value), p.AllowReserved);
    }

    /// <summary>Writes the value in the declared media type, without any location-specific encoding.</summary>
    private static string ContentText(string parameterName, string mediaType, JsonNode? value)
    {
        var normalized = mediaType.Split(';')[0].Trim().ToLowerInvariant();
        if (normalized == "application/json" || normalized.EndsWith("+json", StringComparison.Ordinal))
        {
            return value?.ToJsonString() ?? "null";
        }

        if (normalized.StartsWith("text/", StringComparison.Ordinal))
        {
            return ScalarText(value);
        }

        throw new UnsupportedSerializationException(
            $"Parameter '{parameterName}' declares content media type '{mediaType}', which has no defined "
            + "parameter encoding.",
            parameterName);
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

    /// <summary>Serializes a cookie parameter into the pairs it contributes to the <c>Cookie</c> header.</summary>
    /// <remarks>
    /// An exploded value contributes several pairs, and they are separated with <c>"; "</c> because
    /// RFC 6265 defines that as the cookie-pair separator. The style table shows <c>&amp;</c> for
    /// form-style explosion, but that table describes a query string; reusing its separator inside a
    /// <c>Cookie</c> header produces one cookie whose value happens to contain the remaining pairs, so
    /// the receiver never sees the later ones. The declared style still decides the shape — whether the
    /// value explodes into pairs or collapses into one comma-joined value — and only the separator
    /// between those pairs follows the header's own grammar.
    /// </remarks>
    private static string CookieFormValue(string parameterName, JsonNode? value, bool explode, bool enc)
    {
        var name = Encode(parameterName, enc);

        switch (value)
        {
            case JsonArray arr:
                return explode
                    ? string.Join("; ", arr.Select(v => $"{name}={Encode(ScalarText(v), enc)}"))
                    : $"{name}={string.Join(",", arr.Select(v => Encode(ScalarText(v), enc)))}";

            case JsonObject obj:
                return explode
                    ? string.Join("; ", obj.Select(kv => $"{Encode(kv.Key, enc)}={Encode(ScalarText(kv.Value), enc)}"))
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
