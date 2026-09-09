using System.Text.Json.Nodes;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Serialization;
using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Covers style, explode, and encoding resolution at the serializer, which the golden corpus can only
/// exercise for the combinations its documents happen to declare. Rows 2, 3, 6, 7 and 8 of the change's
/// adversarial matrix.
/// </summary>
public sealed class ParameterSerializerTests
{
    private static ManifestParameter Param(
        string name,
        ParameterLocation location,
        ParameterStyle? style = null,
        bool? explode = null,
        bool allowReserved = false)
        => new(name, location, Style: style, Explode: explode, AllowReserved: allowReserved);

    private static JsonNode Json(string text) => JsonNode.Parse(text)!;

    // ---- default resolution ------------------------------------------------

    [Fact]
    public void An_absent_query_style_resolves_to_form_and_an_absent_explode_to_true()
    {
        var declared = Param("ids", ParameterLocation.Query, ParameterStyle.Form, explode: true);
        var inherited = Param("ids", ParameterLocation.Query);
        var value = Json("""["a","b"]""");

        Assert.Equal("ids=a&ids=b", ParameterSerializer.QueryValue(inherited, value));
        Assert.Equal(
            ParameterSerializer.QueryValue(declared, value),
            ParameterSerializer.QueryValue(inherited, value));
    }

    [Fact]
    public void An_absent_cookie_style_resolves_to_form_and_an_absent_explode_to_true()
    {
        // The pair that the query-only explode rule got wrong before this change: a cookie parameter's
        // default style is form, so its default explode is true for the same reason a query's is.
        var declared = Param("meta", ParameterLocation.Cookie, ParameterStyle.Form, explode: true);
        var inherited = Param("meta", ParameterLocation.Cookie);
        var value = Json("""{"a":"x","b":"y"}""");

        Assert.Equal("a=x&b=y", ParameterSerializer.CookieValue(inherited, value));
        Assert.Equal(
            ParameterSerializer.CookieValue(declared, value),
            ParameterSerializer.CookieValue(inherited, value));
    }

    [Fact]
    public void An_absent_explode_on_a_non_form_style_resolves_to_false()
    {
        var inherited = Param("ids", ParameterLocation.Query, ParameterStyle.SpaceDelimited);
        var explicitly = Param("ids", ParameterLocation.Query, ParameterStyle.SpaceDelimited, explode: false);
        var value = Json("""["a","b"]""");

        Assert.Equal("ids=a%20b", ParameterSerializer.QueryValue(inherited, value));
        Assert.Equal(
            ParameterSerializer.QueryValue(explicitly, value),
            ParameterSerializer.QueryValue(inherited, value));
    }

    [Fact]
    public void An_absent_path_style_resolves_to_simple_and_an_absent_header_style_too()
    {
        Assert.Equal(
            "42",
            ParameterSerializer.PathValue(Param("id", ParameterLocation.Path), Json("42")));
        Assert.Equal(
            "t-1",
            ParameterSerializer.HeaderValue(Param("trace", ParameterLocation.Header), Json("\"t-1\"")));
    }

    // ---- style coverage ----------------------------------------------------

    [Theory]
    [InlineData(false, "ids=a,b")]
    [InlineData(true, "ids=a&ids=b")]
    public void A_form_query_array_honours_explode(bool explode, string expected)
    {
        var p = Param("ids", ParameterLocation.Query, ParameterStyle.Form, explode);

        Assert.Equal(expected, ParameterSerializer.QueryValue(p, Json("""["a","b"]""")));
    }

    [Theory]
    [InlineData(false, "meta=a,x,b,y")]
    [InlineData(true, "a=x&b=y")]
    public void A_form_query_object_flattens_or_explodes(bool explode, string expected)
    {
        var p = Param("meta", ParameterLocation.Query, ParameterStyle.Form, explode);

        Assert.Equal(expected, ParameterSerializer.QueryValue(p, Json("""{"a":"x","b":"y"}""")));
    }

    [Fact]
    public void A_deep_object_query_brackets_every_member()
    {
        var p = Param("meta", ParameterLocation.Query, ParameterStyle.DeepObject);

        // The brackets are the convention's own syntax and stay literal, exactly as the pipe delimiter
        // does. Note the asymmetry with a form body, where the bracketed key is built as text first and
        // then encoded whole, so there the brackets arrive percent-encoded. Both spellings are pinned
        // because a reader would otherwise assume one rule covers both.
        Assert.Equal(
            "meta[a]=x&meta[b]=y",
            ParameterSerializer.QueryValue(p, Json("""{"a":"x","b":"y"}""")));
    }

    [Fact]
    public void A_deep_object_query_refuses_a_value_that_is_not_an_object()
    {
        var p = Param("meta", ParameterLocation.Query, ParameterStyle.DeepObject);

        var ex = Assert.Throws<UnsupportedSerializationException>(
            () => ParameterSerializer.QueryValue(p, Json("\"scalar\"")));

        Assert.Equal("meta", ex.ParameterName);
    }

    [Theory]
    [InlineData(false, ";ids=a,b")]
    [InlineData(true, ";ids=a;ids=b")]
    public void A_matrix_path_array_honours_explode(bool explode, string expected)
    {
        var p = Param("ids", ParameterLocation.Path, ParameterStyle.Matrix, explode);

        Assert.Equal(expected, ParameterSerializer.PathValue(p, Json("""["a","b"]""")));
    }

    [Theory]
    [InlineData(false, ".a,b")]
    [InlineData(true, ".a.b")]
    public void A_label_path_array_honours_explode(bool explode, string expected)
    {
        var p = Param("ids", ParameterLocation.Path, ParameterStyle.Label, explode);

        Assert.Equal(expected, ParameterSerializer.PathValue(p, Json("""["a","b"]""")));
    }

    [Fact]
    public void A_pipe_delimited_query_joins_with_an_unencoded_pipe()
    {
        // The delimiter is the convention's own literal, so it is not encoded even though a pipe is
        // not an unreserved URI character. Encoding it would make the value indistinguishable from a
        // single element containing a pipe.
        var p = Param("names", ParameterLocation.Query, ParameterStyle.PipeDelimited);

        Assert.Equal("names=a|b", ParameterSerializer.QueryValue(p, Json("""["a","b"]""")));
    }

    // ---- refusals ----------------------------------------------------------

    [Theory]
    [InlineData(ParameterStyle.Form)]
    [InlineData(ParameterStyle.Matrix)]
    [InlineData(ParameterStyle.DeepObject)]
    public void A_header_refuses_every_style_but_simple(ParameterStyle style)
    {
        var p = Param("trace", ParameterLocation.Header, style);

        var ex = Assert.Throws<UnsupportedSerializationException>(
            () => ParameterSerializer.HeaderValue(p, Json("\"t\"")));

        Assert.Equal("trace", ex.ParameterName);
    }

    [Theory]
    [InlineData(ParameterStyle.Simple)]
    [InlineData(ParameterStyle.Label)]
    public void A_cookie_refuses_every_style_but_form(ParameterStyle style)
    {
        var p = Param("session", ParameterLocation.Cookie, style);

        Assert.Throws<UnsupportedSerializationException>(
            () => ParameterSerializer.CookieValue(p, Json("\"s\"")));
    }

    [Theory]
    [InlineData(ParameterStyle.Form)]
    [InlineData(ParameterStyle.SpaceDelimited)]
    public void A_path_refuses_a_style_that_has_no_path_spelling(ParameterStyle style)
    {
        var p = Param("id", ParameterLocation.Path, style);

        Assert.Throws<UnsupportedSerializationException>(() => ParameterSerializer.PathValue(p, Json("1")));
    }

    // ---- the reserved allowance -------------------------------------------

    [Fact]
    public void The_reserved_allowance_applies_to_the_value_and_to_the_name_alike()
    {
        var guarded = Param("a/b", ParameterLocation.Query, ParameterStyle.Form, explode: false);
        var permissive = Param("a/b", ParameterLocation.Query, ParameterStyle.Form, explode: false, allowReserved: true);
        var value = Json("\"x/y\"");

        Assert.Equal("a%2Fb=x%2Fy", ParameterSerializer.QueryValue(guarded, value));
        Assert.Equal("a/b=x/y", ParameterSerializer.QueryValue(permissive, value));
    }

    // ---- scalar rendering --------------------------------------------------

    [Theory]
    [InlineData("\"text\"", "text")]
    [InlineData("42", "42")]
    [InlineData("42.50", "42.50")]
    [InlineData("true", "true")]
    public void A_scalar_renders_as_its_json_spelling_except_that_a_string_loses_its_quotes(
        string json,
        string expected)
        => Assert.Equal(expected, ParameterSerializer.ScalarText(Json(json)));

    [Fact]
    public void A_json_null_and_an_absent_value_are_the_same_thing_and_both_render_empty()
    {
        // Not a choice the serializer makes. `System.Text.Json.Nodes` represents a JSON null as a null
        // reference, so `JsonNode.Parse("null")` returns null and `{"a":null}` yields a null member
        // value. The two are indistinguishable below the containing object, where only ContainsKey
        // tells them apart. Nothing downstream can therefore transmit the four characters n-u-l-l for
        // a parameter, and a value the caller explicitly set to null reaches the compiler as an absent
        // argument.
        Assert.Null(JsonNode.Parse("null"));
        Assert.Equal(string.Empty, ParameterSerializer.ScalarText(null));
        Assert.Equal(string.Empty, ParameterSerializer.ScalarText(JsonNode.Parse("null")));
    }

    [Fact]
    public void A_number_keeps_its_lexical_spelling()
    {
        // 42.50 must not become 42.5: the upstream may be comparing text, and the manifest format
        // preserves numeric bounds lexically for the same reason.
        Assert.Equal(
            "price=42.50",
            ParameterSerializer.QueryValue(Param("price", ParameterLocation.Query), Json("42.50")));
    }

    // ---- empty collections -------------------------------------------------

    [Fact]
    public void An_exploded_empty_collection_serializes_to_nothing_at_all()
    {
        // CHARACTERIZATION. An exploded empty array has no members to repeat, so the contribution is
        // the empty string rather than "ids=". The compiler then joins an empty contribution into the
        // query string like any other; see RequestCompilerEdgeTests for what that produces.
        var array = Param("ids", ParameterLocation.Query, ParameterStyle.Form, explode: true);
        var obj = Param("meta", ParameterLocation.Query, ParameterStyle.Form, explode: true);

        Assert.Equal(string.Empty, ParameterSerializer.QueryValue(array, Json("[]")));
        Assert.Equal(string.Empty, ParameterSerializer.QueryValue(obj, Json("{}")));
    }

    [Fact]
    public void A_non_exploded_empty_collection_keeps_its_name_with_an_empty_value()
    {
        var array = Param("ids", ParameterLocation.Query, ParameterStyle.Form, explode: false);
        var obj = Param("meta", ParameterLocation.Query, ParameterStyle.Form, explode: false);

        Assert.Equal("ids=", ParameterSerializer.QueryValue(array, Json("[]")));
        Assert.Equal("meta=", ParameterSerializer.QueryValue(obj, Json("{}")));
    }

    [Fact]
    public void An_empty_deep_object_contributes_nothing()
    {
        var p = Param("meta", ParameterLocation.Query, ParameterStyle.DeepObject);

        Assert.Equal(string.Empty, ParameterSerializer.QueryValue(p, Json("{}")));
    }

    // ---- member order ------------------------------------------------------

    [Fact]
    public void Member_order_is_the_value_s_order_and_is_not_sorted()
    {
        // Two argument objects that differ only in member order are different values here, because the
        // wire form preserves the order given. This is stated so a future change cannot start sorting
        // members and call it a normalization.
        var p = Param("meta", ParameterLocation.Query, ParameterStyle.Form, explode: true);

        Assert.Equal("a=x&b=y", ParameterSerializer.QueryValue(p, Json("""{"a":"x","b":"y"}""")));
        Assert.Equal("b=y&a=x", ParameterSerializer.QueryValue(p, Json("""{"b":"y","a":"x"}""")));
    }
}
