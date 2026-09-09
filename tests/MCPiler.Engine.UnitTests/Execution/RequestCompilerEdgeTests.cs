using System.Text.Json.Nodes;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Compiler-level cases the recorded corpus has no document for: an argument that contributes nothing
/// to the query string, and the refusals that protect the caller from a silently wrong request.
/// </summary>
public sealed class RequestCompilerEdgeTests
{
    private static ManifestOperation Operation(string path, params ManifestParameter[] parameters)
        => new("GET " + path, "GET", path, Parameters: parameters);

    private static ManifestParameter Query(
        string name,
        ParameterStyle? style = null,
        bool? explode = null,
        bool required = false)
        => new(name, ParameterLocation.Query, required, Style: style, Explode: explode);

    private static JsonObject Args(string json) => JsonNode.Parse(json)!.AsObject();

    private static readonly Uri Base = new("https://api.example.com");

    [Fact]
    public void An_exploded_empty_collection_leaves_an_empty_query_segment()
    {
        // CHARACTERIZATION of a defect, not a statement of intent.
        //
        // An exploded empty array contributes the empty string, and the compiler joins every
        // contribution with "&" without discarding the empty ones. The result carries a stray
        // separator: "?a=1&&b=2". A server is entitled to read that as a third, nameless parameter.
        //
        // The behaviour is recorded rather than corrected because the correction changes outbound
        // request bytes and needs its own requirement and goldens. Both implementations carry it
        // identically, so parity is unaffected.
        var operation = Operation(
            "/items",
            Query("a"),
            Query("ids", ParameterStyle.Form, explode: true),
            Query("b"));

        var compiled = RequestCompiler.Compile(
            operation,
            Base,
            Args("""{"a":"1","ids":[],"b":"2"}"""));

        Assert.Equal("https://api.example.com/items?a=1&&b=2", compiled.ExactUrl);
    }

    [Fact]
    public void A_single_empty_contribution_leaves_a_bare_question_mark()
    {
        var operation = Operation("/items", Query("ids", ParameterStyle.Form, explode: true));

        var compiled = RequestCompiler.Compile(operation, Base, Args("""{"ids":[]}"""));

        Assert.Equal("https://api.example.com/items?", compiled.ExactUrl);
    }

    [Fact]
    public void An_absent_optional_parameter_contributes_no_segment_at_all()
    {
        // The contrast that makes the two cases above a defect rather than a convention: an argument
        // the caller omitted is dropped cleanly, so an argument the caller supplied as empty should be
        // too.
        var operation = Operation("/items", Query("a"), Query("ids", ParameterStyle.Form, explode: true));

        var compiled = RequestCompiler.Compile(operation, Base, Args("""{"a":"1"}"""));

        Assert.Equal("https://api.example.com/items?a=1", compiled.ExactUrl);
    }

    [Fact]
    public void An_operation_with_no_parameters_carries_no_question_mark()
    {
        var compiled = RequestCompiler.Compile(Operation("/items"), Base, Args("{}"));

        Assert.Equal("https://api.example.com/items", compiled.ExactUrl);
    }

    [Fact]
    public void An_argument_whose_name_differs_only_in_case_does_not_bind()
    {
        // Parameter names are matched exactly, so "PetId" is not "petId". A case-insensitive match
        // would let a caller satisfy a required parameter by accident and would make two distinct
        // declared parameters collide.
        var operation = Operation(
            "/items/{petId}",
            new ManifestParameter("petId", ParameterLocation.Path, Required: true));

        var ex = Assert.Throws<ArgumentValidationException>(
            () => RequestCompiler.Compile(operation, Base, Args("""{"PetId":"1"}""")));

        Assert.Equal("petId", ex.ParameterName);
    }

    [Fact]
    public void A_missing_required_path_parameter_is_refused_before_a_url_is_produced()
    {
        var operation = Operation(
            "/items/{id}",
            new ManifestParameter("id", ParameterLocation.Path, Required: true));

        var ex = Assert.Throws<ArgumentValidationException>(
            () => RequestCompiler.Compile(operation, Base, Args("{}")));

        Assert.Equal("id", ex.ParameterName);
    }

    [Fact]
    public void An_unknown_placeholder_in_the_path_is_refused_rather_than_transmitted()
    {
        // A placeholder no parameter declares cannot be filled, and sending the literal "{tenant}"
        // upstream would turn a contract defect into a confusing 404.
        var operation = Operation("/tenants/{tenant}/items");

        Assert.Throws<ArgumentValidationException>(
            () => RequestCompiler.Compile(operation, Base, Args("{}")));
    }

    [Fact]
    public void An_optional_declared_placeholder_left_unsupplied_collapses_to_nothing()
    {
        var operation = Operation(
            "/items/{id}",
            new ManifestParameter("id", ParameterLocation.Path));

        var compiled = RequestCompiler.Compile(operation, Base, Args("{}"));

        Assert.Equal("https://api.example.com/items/", compiled.ExactUrl);
    }

    [Theory]
    [InlineData("https://api.example.com/v2?x=1")]
    [InlineData("https://api.example.com/v2#frag")]
    public void A_base_url_carrying_a_query_or_a_fragment_is_refused(string baseUrl)
        => Assert.Throws<InvalidBaseUrlException>(
            () => RequestCompiler.Compile(Operation("/items"), new Uri(baseUrl), Args("{}")));

    [Theory]
    [InlineData("https://api.example.com", "/items", "https://api.example.com/items")]
    [InlineData("https://api.example.com/", "/items", "https://api.example.com/items")]
    [InlineData("https://api.example.com/v2", "/items", "https://api.example.com/v2/items")]
    [InlineData("https://api.example.com/v2/", "/items", "https://api.example.com/v2/items")]
    [InlineData("https://api.example.com/v2", "items", "https://api.example.com/v2/items")]
    public void The_base_path_is_preserved_and_only_the_join_boundary_is_normalised(
        string baseUrl,
        string path,
        string expected)
    {
        var compiled = RequestCompiler.Compile(Operation(path), new Uri(baseUrl), Args("{}"));

        Assert.Equal(expected, compiled.ExactUrl);
    }

    [Fact]
    public void A_method_is_upper_cased_so_a_lower_case_declaration_still_compiles_one_way()
    {
        var operation = new ManifestOperation("get /items", "get", "/items");

        var compiled = RequestCompiler.Compile(operation, Base, Args("{}"));

        Assert.Equal("GET", compiled.Method);
    }

    [Fact]
    public void Repeated_compilation_of_the_same_inputs_is_byte_identical()
    {
        var operation = Operation("/items", Query("a"), Query("ids", ParameterStyle.Form, explode: true));
        var args = Args("""{"a":"1","ids":["x","y"]}""");

        var first = RequestCompiler.Compile(operation, Base, args);
        var second = RequestCompiler.Compile(operation, Base, args);

        Assert.Equal(first.ExactUrl, second.ExactUrl);
        Assert.Equal(first.Method, second.Method);
        Assert.Equal(first.Body, second.Body);
    }

    [Fact]
    public void Every_serialized_parameter_is_recorded_as_a_decision_for_inspection()
    {
        var operation = Operation("/items", Query("a"), Query("ids", ParameterStyle.PipeDelimited));

        var compiled = RequestCompiler.Compile(operation, Base, Args("""{"a":"1","ids":["x","y"]}"""));

        Assert.Equal(2, compiled.Decisions.Count);
        Assert.Contains(compiled.Decisions, d => d.ParameterName == "ids" && d.Style == "pipeDelimited");
        Assert.Contains(compiled.Decisions, d => d.ParameterName == "a" && d.Style == "form" && d.Explode == true);
    }
}
