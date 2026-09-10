using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// The two places a manifest policy becomes numbers an adapter acts on.
/// </summary>
/// <remarks>
/// <para>
/// ADR-0057 keeps manifest knowledge out of the adapter directories, which means the policy is
/// read here and handed over as values. That moves a whole class of mistake into one place: a
/// projection that swapped two members of the same type would compile, would leave every
/// adapter test green because the adapter cannot tell one <c>TimeSpan</c> from another, and
/// would send every request under the wrong limit.
/// </para>
/// <para>
/// Every number below is distinct from every other number of its type for exactly that reason.
/// A projection asserted against defaults proves nothing, because the defaults it maps from and
/// the defaults it maps to agree by construction.
/// </para>
/// </remarks>
public sealed class PolicyProjectionTests
{
    [Fact]
    public void Outbound_limits_take_the_transport_members_and_leave_the_rest_behind()
    {
        var limits = new ExecutionLimits(
            UpstreamConnectTimeout: TimeSpan.FromSeconds(7),
            UpstreamRequestTimeout: TimeSpan.FromSeconds(41),
            UpstreamResponseSizeLimitBytes: 123_456,
            RedirectHopLimit: 3,
            Concurrency: 11,
            McpRequestSizeLimitBytes: 654_321);

        var outbound = OutboundLimits.From(limits);

        Assert.Equal(TimeSpan.FromSeconds(7), outbound.ConnectTimeout);
        Assert.Equal(11, outbound.MaxConnectionsPerServer);
        Assert.Equal(3, outbound.RedirectHopLimit);
    }

    /// <summary>
    /// The whole-exchange budget and the response ceiling are deliberately absent.
    /// </summary>
    /// <remarks>
    /// The budget is the caller's cancellation token, because a chain of hops is measured by
    /// whoever is following it rather than by each request. The response ceiling is enforced
    /// while the body is read, which happens after the transport has handed the stream back.
    /// Carrying either into the transport would create a second place where the same limit
    /// could be applied, and two places produce two classifications for one fault.
    /// </remarks>
    [Fact]
    public void Outbound_limits_carry_neither_the_exchange_budget_nor_the_response_ceiling()
    {
        string[] declared = [.. typeof(OutboundLimits)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(member => member.Name)
            .Where(name => !string.Equals(name, "EqualityContract", StringComparison.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)];

        Assert.Equal(["ConnectTimeout", "MaxConnectionsPerServer", "RedirectHopLimit"], declared);
    }

    [Fact]
    public void The_default_outbound_limits_are_the_manifest_defaults()
    {
        Assert.Equal(OutboundLimits.From(ExecutionLimits.Default), OutboundLimits.Default);
    }

    [Fact]
    public void Store_options_take_the_file_policy_members()
    {
        var policy = new FilePolicy(
            HandleLifetime: TimeSpan.FromMinutes(90),
            UploadSizeLimitBytes: 777_777,
            RejectMagicMismatch: false);

        var options = FileHandleStoreOptions.For("/store", policy, ["/served"], TimeSpan.FromSeconds(30));

        Assert.Equal("/store", options.Root);
        Assert.Equal(TimeSpan.FromMinutes(90), options.HandleLifetime);
        Assert.Equal(777_777, options.UploadSizeLimitBytes);
        Assert.False(options.RejectMagicMismatch);
        Assert.Equal<IReadOnlyList<string>>(["/served"], options.ServedContentRoots);
        Assert.Equal(TimeSpan.FromSeconds(30), options.OrphanGrace);
    }

    [Fact]
    public void Store_options_fall_back_to_the_manifest_file_defaults()
    {
        var options = FileHandleStoreOptions.For("/store");

        Assert.Equal(FilePolicy.Default.HandleLifetime, options.HandleLifetime);
        Assert.Equal(FilePolicy.Default.UploadSizeLimitBytes, options.UploadSizeLimitBytes);
        Assert.Equal(FilePolicy.Default.RejectMagicMismatch, options.RejectMagicMismatch);
        Assert.Empty(options.ServedContentRoots);
        Assert.Equal(FileHandleStoreOptions.DefaultOrphanGrace, options.OrphanGrace);
    }
}
