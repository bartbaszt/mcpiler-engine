using System;
using System.Collections.Generic;
using System.Linq;

using MCPiler.Engine.Execution;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Failure classification: by type, never by message text, and complete over the declared set.
/// </summary>
/// <remarks>
/// A caller branching on <see cref="ExecutionFailureKind"/> is making an operational decision —
/// retry, re-authenticate, widen a perimeter, raise a limit. Deriving that from a message would
/// make a typo fix a behavioural change, and would make the set of outcomes something a reader
/// could only discover by grepping for string literals.
/// </remarks>
public sealed class ExecutionFailureClassificationTests
{
    private static readonly (Exception Failure, ExecutionFailureKind Kind)[] ClassificationRows =
    [
        (new CredentialUnavailableException("api", "unset"), ExecutionFailureKind.Authentication),
        (new OriginPolicyViolationException(new Uri("https://evil.test/x")), ExecutionFailureKind.OriginPolicy),
        (new AddressPolicyViolationException("internal.test", "10.0.0.1"), ExecutionFailureKind.AddressPolicy),
        (new HostResolutionException("nowhere.invalid"), ExecutionFailureKind.AddressPolicy),
        (new RedirectLimitException(5), ExecutionFailureKind.RedirectLimit),
        (new ResponseSizeLimitException(2048, 1024), ExecutionFailureKind.ResponseSize),
        (new FileRuntimeException("too large"), ExecutionFailureKind.FileRuntime),
        (new MalformedRedirectException(new Uri("https://api.test/x")), ExecutionFailureKind.Transport),
        (new UpstreamTransportException("reset"), ExecutionFailureKind.Transport),
    ];

    public static TheoryData<int> Rows()
    {
        var data = new TheoryData<int>();
        for (var index = 0; index < ClassificationRows.Length; index++)
        {
            data.Add(index);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Rows))]
    public void A_failure_is_classified_by_its_type(int index)
    {
        var (failure, kind) = ClassificationRows[index];

        Assert.Equal(kind, ExecutionService.Classify(failure));
    }

    [Fact]
    public void Rewording_a_message_changes_no_classification()
    {
        // The same fault, described three ways. If any of these disagreed, the classification
        // would be a property of the prose rather than of what happened.
        Assert.Equal(
            ExecutionFailureKind.FileRuntime,
            ExecutionService.Classify(new FileRuntimeException("the payload exceeds the configured size limit")));

        Assert.Equal(
            ExecutionFailureKind.FileRuntime,
            ExecutionService.Classify(new FileRuntimeException("payload too big")));

        Assert.Equal(
            ExecutionFailureKind.FileRuntime,
            ExecutionService.Classify(new FileRuntimeException(string.Empty)));
    }

    [Fact]
    public void A_malformed_redirect_is_a_transport_fault_and_not_a_policy_refusal()
    {
        // Both mean no response comes back to compare, and nothing else. Reporting a redirect
        // with no destination as a refused origin would tell an operator their allow-list
        // rejected a target the upstream never named.
        Assert.Equal(
            ExecutionFailureKind.Transport,
            ExecutionService.Classify(new MalformedRedirectException(new Uri("https://api.test/x"))));

        Assert.Equal(
            ExecutionFailureKind.OriginPolicy,
            ExecutionService.Classify(new OriginPolicyViolationException(new Uri("https://api.test/x"))));
    }

    [Fact]
    public void An_unrecognized_fault_falls_back_to_transport_rather_than_to_nothing()
    {
        // A floor rather than the usual answer: the transport wraps whatever a framework
        // raised, so anything reaching here is genuinely unclassified.
        Assert.Equal(ExecutionFailureKind.Transport, ExecutionService.Classify(new InvalidOperationException("?")));
        Assert.NotEqual(ExecutionFailureKind.None, ExecutionService.Classify(new InvalidOperationException("?")));
    }

    [Fact]
    public void Every_declared_failure_kind_has_a_site_that_produces_it()
    {
        // The classification is only useful if it is complete. A member with no producing site
        // is either dead or, worse, a case that reaches a caller as some other member's value.
        var producedBySendClassification = ClassificationRows
            .Select(row => row.Kind)
            .ToHashSet();

        var producedElsewhere = new Dictionary<ExecutionFailureKind, string>
        {
            [ExecutionFailureKind.None] = "a successful result carries it",
            [ExecutionFailureKind.Compilation] = "ExecutionService refuses an unexposed operation, an unresolvable binding, or a compiler rejection",
            [ExecutionFailureKind.Timeout] = "ExecutionService reports budget expiry on the send and on the body read",
            [ExecutionFailureKind.Transformation] = "ExecutionService refuses a declared program that Tier 1 rejects or that aborts, in either direction",
        };

        var unaccounted = Enum.GetValues<ExecutionFailureKind>()
            .Where(kind => !producedBySendClassification.Contains(kind) && !producedElsewhere.ContainsKey(kind))
            .ToList();

        Assert.Empty(unaccounted);

        // And nothing claimed here is stale: every kind named as produced elsewhere is still a
        // declared member.
        Assert.All(producedElsewhere.Keys, kind => Assert.True(Enum.IsDefined(kind)));
    }

    /// <summary>
    /// The members the compiling host declares too, in its order.
    /// </summary>
    /// <remarks>
    /// Stated as a list so that adding a member is an edit here as well, and a reviewer of
    /// either repository can see the set the other is expected to carry.
    /// </remarks>
    private static readonly ExecutionFailureKind[] Shared =
    [
        ExecutionFailureKind.None,
        ExecutionFailureKind.Compilation,
        ExecutionFailureKind.Authentication,
        ExecutionFailureKind.OriginPolicy,
        ExecutionFailureKind.AddressPolicy,
        ExecutionFailureKind.RedirectLimit,
        ExecutionFailureKind.Timeout,
        ExecutionFailureKind.ResponseSize,
        ExecutionFailureKind.FileRuntime,
        ExecutionFailureKind.Transport,
    ];

    /// <summary>
    /// The members this implementation declares and the compiling host does not, with why.
    /// </summary>
    /// <remarks>
    /// One entry, and it is structural rather than a dialect: the compiling host evaluates a
    /// transformation above its execution service, so an abort there never reaches a
    /// classification at all. Naming the exception explicitly is what keeps the shared list
    /// above readable as a shared list instead of quietly drifting into two.
    /// </remarks>
    private static readonly ExecutionFailureKind[] EngineOnly = [ExecutionFailureKind.Transformation];

    [Fact]
    public void The_declared_set_extends_the_one_both_implementations_share()
    {
        Assert.Equal(
            Shared.Concat(EngineOnly).OrderBy(static kind => kind.ToString(), StringComparer.Ordinal),
            Enum.GetValues<ExecutionFailureKind>().OrderBy(static kind => kind.ToString(), StringComparer.Ordinal));
    }

    [Fact]
    public void The_shared_members_keep_the_order_both_implementations_declare()
    {
        // Order is part of what a reader compares across the two files, so the extension is
        // asserted to be an insertion rather than a reshuffle.
        Assert.Equal(
            Shared,
            Enum.GetValues<ExecutionFailureKind>().Where(kind => !EngineOnly.Contains(kind)).ToList());
    }
}
