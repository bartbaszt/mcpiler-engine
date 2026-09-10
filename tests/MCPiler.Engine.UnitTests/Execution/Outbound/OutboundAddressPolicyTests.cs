using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Outbound;

/// <summary>
/// Outbound address containment: which concrete addresses are refused, and that the refusal
/// happens against a resolved address rather than against host text.
/// </summary>
/// <remarks>
/// The table is duplicated from the compiling host rather than shared, so both copies are
/// checkable against the published reservations rather than against each other. That is only
/// worth anything if each copy is asserted on its own side, which is what this file is.
/// </remarks>
public sealed class OutboundAddressPolicyTests
{
    private static readonly (string Address, bool Denied, string Why)[] AddressRows =
    [
        ("0.0.0.0", true, "unspecified"),
        ("10.1.2.3", true, "private class A"),
        ("100.64.0.1", true, "carrier NAT"),
        ("127.0.0.1", true, "loopback"),
        ("169.254.169.254", true, "instance metadata"),
        ("172.16.5.5", true, "private class B"),
        ("192.0.0.1", true, "protocol assignment"),
        ("192.0.2.5", true, "documentation"),
        ("192.88.99.1", true, "anycast relay"),
        ("192.168.1.10", true, "private class C"),
        ("198.18.0.5", true, "benchmarking"),
        ("198.51.100.7", true, "documentation"),
        ("203.0.113.9", true, "documentation"),
        ("224.0.0.1", true, "multicast"),
        ("240.0.0.1", true, "reserved"),
        ("255.255.255.255", true, "broadcast"),
        ("::", true, "unspecified v6"),
        ("::1", true, "loopback v6"),
        ("100::1", true, "discard v6"),
        ("2001:db8::1", true, "documentation v6"),
        ("fc00::1", true, "unique local"),
        ("fe80::1", true, "link local v6"),
        ("ff02::1", true, "multicast v6"),
        ("::ffff:127.0.0.1", true, "v4-mapped loopback"),
        ("::ffff:10.0.0.1", true, "v4-mapped private"),
        ("::127.0.0.1", true, "v4-compatible loopback"),
        ("2002:7f00:1::", true, "6to4 carrying loopback"),
        ("64:ff9b::7f00:1", true, "NAT64 carrying loopback"),
        ("64:ff9b:1::1", true, "local-use NAT64, refused wholesale"),
        ("93.184.216.34", false, "public v4"),
        ("8.8.8.8", false, "public v4"),
        ("2606:2800:220:1:248:1893:25c8:1946", false, "public v6"),
        ("::ffff:93.184.216.34", false, "v4-mapped public"),
        ("2002:5db8:d822::", false, "6to4 carrying a public address"),
        ("64:ff9b::5db8:d822", false, "NAT64 carrying a public address"),
    ];

    public static TheoryData<string, bool> Addresses()
    {
        var data = new TheoryData<string, bool>();
        foreach (var (address, denied, _) in AddressRows)
        {
            data.Add(address, denied);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Addresses))]
    public void An_address_is_denied_exactly_when_the_reservation_table_says_so(string address, bool expected)
        => Assert.Equal(expected, OutboundAddressPolicy.IsDenied(IPAddress.Parse(address)));

    [Fact]
    public void The_address_table_is_populated_and_states_both_outcomes()
    {
        Assert.Equal(AddressRows.Length, Addresses().Count);
        Assert.Contains(true, AddressRows.Select(row => row.Denied).ToList());
        Assert.Contains(false, AddressRows.Select(row => row.Denied).ToList());

        // Every row carries a reason. A table of bare addresses is unreviewable: a reader
        // cannot tell a deliberate reservation from a typo.
        Assert.All(AddressRows, row => Assert.False(string.IsNullOrWhiteSpace(row.Why)));
    }

    [Fact]
    public void An_embedded_transitional_form_is_judged_by_the_address_it_carries()
    {
        // The families are a spelling, not a boundary. A denied address reached through a
        // transitional form is the same destination, and unmapping before the check is what
        // stops the form from being an escape.
        Assert.True(OutboundAddressPolicy.IsDenied(IPAddress.Parse("2002:c0a8:1::")));
        Assert.False(OutboundAddressPolicy.IsDenied(IPAddress.Parse("2002:0808:0808::")));
    }

    [Fact]
    public void A_known_metadata_name_is_refused_by_name_as_well()
    {
        Assert.True(OutboundAddressPolicy.IsDeniedHostName("metadata.google.internal"));
        Assert.True(OutboundAddressPolicy.IsDeniedHostName("METADATA.GOOGLE.INTERNAL"));
        Assert.True(OutboundAddressPolicy.IsDeniedHostName("metadata.google.internal."));
        Assert.True(OutboundAddressPolicy.IsDeniedHostName("169.254.169.254"));
        Assert.False(OutboundAddressPolicy.IsDeniedHostName("api.example.com"));
    }

    [Fact]
    public async Task A_literal_in_a_denied_range_is_refused_naming_the_address()
    {
        var policy = new OutboundConnectionPolicy();

        var failure = await Assert.ThrowsAsync<AddressPolicyViolationException>(
            () => policy.ResolveValidatedAsync("127.0.0.1", TestContext.Current.CancellationToken));

        Assert.Equal("127.0.0.1", failure.Host);
        Assert.Equal("127.0.0.1", failure.Address);
    }

    [Fact]
    public async Task A_name_resolving_into_a_denied_range_is_refused()
    {
        // localhost is the one name every machine resolves the same way, so this is the
        // resolution path rather than the literal path: an allow-listed name whose answer is
        // denied is still refused.
        var policy = new OutboundConnectionPolicy();

        var failure = await Assert.ThrowsAsync<AddressPolicyViolationException>(
            () => policy.ResolveValidatedAsync("localhost", TestContext.Current.CancellationToken));

        Assert.Equal("localhost", failure.Host);
    }

    [Fact]
    public async Task A_host_that_resolves_to_nothing_is_a_resolution_failure_and_not_a_policy_refusal()
    {
        var policy = new OutboundConnectionPolicy();

        // Reserved by the DNS registry for exactly this: it never resolves, on any network.
        var failure = await Assert.ThrowsAsync<HostResolutionException>(
            () => policy.ResolveValidatedAsync("nonexistent.invalid", TestContext.Current.CancellationToken));

        Assert.Equal("nonexistent.invalid", failure.Host);
    }

    [Fact]
    public async Task Every_resolved_answer_is_judged_and_one_denied_answer_refuses_the_host()
    {
        var seen = new List<string>();
        var policy = new OutboundConnectionPolicy(address =>
        {
            seen.Add(address.ToString());
            return OutboundAddressPolicy.IsDenied(address);
        });

        await Assert.ThrowsAsync<AddressPolicyViolationException>(
            () => policy.ResolveValidatedAsync("localhost", TestContext.Current.CancellationToken));

        // Fail-closed rather than filtering to the acceptable answers: a name answering with
        // both a public and a private address means something different depending on which
        // answer a resolver returns first, and connecting to the acceptable half is how a
        // rebinding attempt succeeds on its second try.
        Assert.NotEmpty(seen);
    }

    [Fact]
    public void The_shipped_policy_uses_the_shipped_judgement()
    {
        // The substitutable judgement exists for the tests that must reach an in-process
        // server, which necessarily lives in a denied range. It must not be what production
        // gets, and the default constructor is what production uses.
        Assert.True(new OutboundConnectionPolicy().UsesDefaultGuard);
        Assert.False(new OutboundConnectionPolicy(_ => false).UsesDefaultGuard);
        Assert.True(OutboundConnectionPolicy.DefaultGuard(IPAddress.Loopback));
    }

    [Fact]
    public async Task A_permitted_address_that_refuses_the_connection_is_a_transport_failure()
    {
        // Judgement and reachability are different findings. Reporting an unreachable host as a
        // containment refusal would send an operator to edit a policy that was never consulted.
        var policy = new OutboundConnectionPolicy(_ => false);
        var port = ReserveAndReleasePort();

        var failure = await Record.ExceptionAsync(
            () => policy.ConnectAsync("127.0.0.1", port, TestContext.Current.CancellationToken).AsTask());

        Assert.NotNull(failure);
        Assert.IsNotType<AddressPolicyViolationException>(failure);
    }

    /// <summary>
    /// A loopback port the operating system just confirmed was free and that nothing is
    /// listening on, so a connection to it is refused rather than hanging.
    /// </summary>
    /// <remarks>
    /// A hard-coded port would either be occupied on someone's machine or would depend on
    /// nothing ever binding it, and an unroutable address would hang until a connect timeout
    /// this call does not impose.
    /// </remarks>
    private static int ReserveAndReleasePort()
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }
}
