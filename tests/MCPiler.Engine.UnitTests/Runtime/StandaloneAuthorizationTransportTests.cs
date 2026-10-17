using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Runtime;

/// <summary>
/// What the operator's loopback allowance widens, and what it deliberately does not.
/// </summary>
/// <remarks>
/// <para>
/// The allowance exists for one case: an authorization server running on the operator's own
/// machine. These cases pin the bound from both sides. Loopback becomes reachable, and nothing
/// else does — not the link-local range an instance-metadata service answers on, not private
/// ranges, and not the unspecified addresses whose meaning the local stack decides.
/// </para>
/// <para>
/// The judgement is asserted by resolving literals, which is what the transport does before it
/// opens a socket, so a case here fails for the same reason a real authorization attempt would.
/// </para>
/// </remarks>
public sealed class StandaloneAuthorizationTransportTests
{
    [Fact]
    public async Task Without_the_allowance_the_shipped_table_refuses_loopback()
    {
        OutboundConnectionPolicy policy = StandaloneAuthorizationTransport.Policy(
            connections: null, allowLoopbackAuthorization: false);

        Assert.True(policy.UsesDefaultGuard);

        await Assert.ThrowsAsync<AddressPolicyViolationException>(
            () => policy.ResolveValidatedAsync("127.0.0.1", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task With_the_allowance_exactly_the_loopback_forms_are_reachable()
    {
        OutboundConnectionPolicy policy = StandaloneAuthorizationTransport.Policy(
            connections: null, allowLoopbackAuthorization: true);

        Assert.False(policy.UsesDefaultGuard);

        foreach (string literal in new[] { "127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1" })
        {
            var addresses = await policy.ResolveValidatedAsync(literal, TestContext.Current.CancellationToken);

            Assert.NotEmpty(addresses);
        }
    }

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("10.0.0.1")]
    [InlineData("192.168.1.10")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("fe80::1")]
    [InlineData("::ffff:169.254.169.254")]
    public async Task With_the_allowance_every_other_reserved_range_stays_refused(string literal)
    {
        OutboundConnectionPolicy policy = StandaloneAuthorizationTransport.Policy(
            connections: null, allowLoopbackAuthorization: true);

        await Assert.ThrowsAsync<AddressPolicyViolationException>(
            () => policy.ResolveValidatedAsync(literal, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void An_explicit_judgement_is_used_verbatim_and_the_allowance_is_ignored()
    {
        var explicitJudgement = new OutboundConnectionPolicy(
            static address => address.AddressFamily == AddressFamily.InterNetworkV6);

        Assert.Same(
            explicitJudgement,
            StandaloneAuthorizationTransport.Policy(explicitJudgement, allowLoopbackAuthorization: true));
        Assert.Same(
            explicitJudgement,
            StandaloneAuthorizationTransport.Policy(explicitJudgement, allowLoopbackAuthorization: false));
    }

    [Fact]
    public void The_allowance_leaves_the_shipped_table_itself_untouched()
    {
        // The serving path takes the shipped judgement, never this transport's, so the table must
        // read the same after an allowance was built from it.
        _ = StandaloneAuthorizationTransport.Policy(null, allowLoopbackAuthorization: true);

        Assert.True(new OutboundConnectionPolicy().UsesDefaultGuard);
        Assert.True(OutboundConnectionPolicy.DefaultGuard(IPAddress.Loopback));
        Assert.True(OutboundConnectionPolicy.DefaultGuard(IPAddress.IPv6Loopback));
        Assert.True(OutboundConnectionPolicy.DefaultGuard(IPAddress.Parse("169.254.169.254")));
    }
}
