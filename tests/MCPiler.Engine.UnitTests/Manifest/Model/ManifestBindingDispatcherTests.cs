using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Model;

public sealed class ManifestBindingDispatcherTests
{
    private static readonly HttpBinding Http = new("GET /pets");

    [Fact]
    public void An_http_binding_resolves_to_itself()
        => Assert.Same(Http, ManifestBindingDispatcher.TryResolveHttp(Http));

    /// <summary>
    /// A transformed binding resolves to its base, never to anything re-derived.
    /// </summary>
    /// <remarks>
    /// This is the case a local type switch got wrong once: a transformed binding fell through
    /// to the source key while invocation ran the base key, and a file upload slipped past a
    /// gate that forbade files.
    /// </remarks>
    [Fact]
    public void A_transformed_binding_resolves_to_its_base()
    {
        HttpBinding actualExecution = new("POST /pets/upload");
        TransformedHttpBinding transformed = new(actualExecution);

        Assert.Same(actualExecution, ManifestBindingDispatcher.TryResolveHttp(transformed));
        Assert.Equal("POST /pets/upload", ManifestBindingDispatcher.TryResolveOperationKey(transformed));
    }

    [Fact]
    public void A_compound_binding_resolves_to_no_http_shape()
    {
        CompoundBinding compound = new([new CompoundStepEntry("one", "list-pets")]);

        Assert.Null(ManifestBindingDispatcher.TryResolveHttp(compound));
        Assert.Null(ManifestBindingDispatcher.TryResolveOperationKey(compound));
        Assert.Null(ManifestBindingDispatcher.TryResolveServerUrl(compound));
    }

    [Fact]
    public void A_null_binding_resolves_to_nothing_rather_than_throwing()
    {
        Assert.Null(ManifestBindingDispatcher.TryResolveHttp(binding: null));
        Assert.Null(ManifestBindingDispatcher.TryResolveOperationKey(binding: null));
        Assert.Null(ManifestBindingDispatcher.TryResolveServerUrl(binding: null));
        Assert.Null(ManifestBindingDispatcher.TryResolveCompoundSteps(binding: null));
        Assert.Empty(ManifestBindingDispatcher.CredentialRefsOf(binding: null));
    }

    /// <summary>
    /// Credential scope resolves through the same seam that resolves the executed operation.
    /// </summary>
    /// <remarks>
    /// A separate resolution path for credentials is how a gate and an execution end up
    /// disagreeing about which binding actually runs.
    /// </remarks>
    [Fact]
    public void Credential_scope_resolves_through_the_seam()
    {
        HttpBinding scoped = new("GET /pets", CredentialRef: ["bearer", "x-tenant"]);

        Assert.Equal(["bearer", "x-tenant"], ManifestBindingDispatcher.CredentialRefsOf(scoped));
        Assert.Equal(["bearer", "x-tenant"], ManifestBindingDispatcher.CredentialRefsOf(new TransformedHttpBinding(scoped)));
        Assert.Empty(ManifestBindingDispatcher.CredentialRefsOf(Http));
        Assert.Empty(ManifestBindingDispatcher.CredentialRefsOf(new CompoundBinding([new CompoundStepEntry("one", "x")])));
    }

    [Fact]
    public void A_server_url_resolves_through_a_transformation()
    {
        TransformedHttpBinding transformed = new(new HttpBinding("GET /pets", ServerUrl: "https://eu.example.com"));

        Assert.Equal("https://eu.example.com", ManifestBindingDispatcher.TryResolveServerUrl(transformed));
    }

    [Fact]
    public void Compound_steps_resolve_only_for_a_compound_binding()
    {
        CompoundBinding compound = new([new CompoundStepEntry("one", "list-pets"), new CompoundStepEntry("two", "tag-pet")]);

        Assert.Equal(2, ManifestBindingDispatcher.TryResolveCompoundSteps(compound)!.Count);
        Assert.Null(ManifestBindingDispatcher.TryResolveCompoundSteps(Http));
        Assert.Null(ManifestBindingDispatcher.TryResolveCompoundSteps(new TransformedHttpBinding(Http)));
    }

    [Theory]
    [InlineData(AgentOperationKind.SourceBacked, true)]
    [InlineData(AgentOperationKind.CustomHttp, true)]
    [InlineData(AgentOperationKind.Compound, false)]
    public void An_http_binding_agrees_with_every_kind_except_compound(AgentOperationKind kind, bool agrees)
        => Assert.Equal(agrees, ManifestBindingDispatcher.KindAgreesWithBinding(kind, Http));

    [Theory]
    [InlineData(AgentOperationKind.SourceBacked, false)]
    [InlineData(AgentOperationKind.CustomHttp, false)]
    [InlineData(AgentOperationKind.Compound, true)]
    public void A_compound_binding_agrees_only_with_the_compound_kind(AgentOperationKind kind, bool agrees)
        => Assert.Equal(
            agrees,
            ManifestBindingDispatcher.KindAgreesWithBinding(kind, new CompoundBinding([new CompoundStepEntry("one", "x")])));

    [Fact]
    public void Derivation_reports_the_source_backed_shape_for_a_single_key_binding()
    {
        Assert.Equal(AgentOperationKind.SourceBacked, ManifestBindingDispatcher.DeriveKind(Http));
        Assert.Equal(AgentOperationKind.SourceBacked, ManifestBindingDispatcher.DeriveKind(new TransformedHttpBinding(Http)));
        Assert.Equal(
            AgentOperationKind.Compound,
            ManifestBindingDispatcher.DeriveKind(new CompoundBinding([new CompoundStepEntry("one", "x")])));
    }

    /// <summary>
    /// The model's own kind derivation must go through the seam.
    /// </summary>
    [Fact]
    public void The_agent_entry_derives_its_kind_through_the_dispatcher()
    {
        AgentOperationEntry entry = new("bundle", "Bundle", new CompoundBinding([new CompoundStepEntry("one", "x")]));

        Assert.Equal(ManifestBindingDispatcher.DeriveKind(entry.Binding), entry.DerivedKind);
        Assert.Equal(AgentOperationKind.Compound, entry.EffectiveKind);
    }
}
