using System;
using System.Collections.Generic;
using System.Linq;

using MCPiler.Engine.Execution;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// The redirect decision table, asserted directly rather than inferred from an exchange.
/// </summary>
/// <remarks>
/// <para>
/// These rules are the reason the sender is thin. Testing them here means a change to what a
/// 303 does fails against a statement of what a 303 does, instead of failing somewhere inside a
/// chain of substituted responses where the cause has to be reconstructed.
/// </para>
/// <para>
/// Every table below is declared as a plain row array and projected into theory data, so the
/// same rows can be counted and checked for stating both outcomes. A table that had drifted to
/// one answer would otherwise pass against a predicate that answered that way unconditionally,
/// which is a green suite proving nothing.
/// </para>
/// </remarks>
public sealed class RedirectRulesTests
{
    /// <summary>
    /// Every status this path treats as a redirect, and the adjacent ones it must not.
    /// </summary>
    /// <remarks>
    /// The neighbours are the point. A predicate written as a range would admit 304 and 305,
    /// neither of which names a destination to follow, and a chain that tried to follow one
    /// would fail as a malformed redirect instead of returning the response it was handed.
    /// </remarks>
    private static readonly (int Status, bool IsRedirect)[] StatusRows =
    [
        (299, false),
        (300, false),
        (301, true),
        (302, true),
        (303, true),
        (304, false),
        (305, false),
        (306, false),
        (307, true),
        (308, true),
        (309, false),
        (200, false),
        (400, false),
    ];

    private static readonly (int Status, string Current, string Method, bool PreserveBody)[] RewriteRows =
    [
        (301, "POST", "GET", false),
        (302, "POST", "GET", false),
        (303, "POST", "GET", false),
        (303, "GET", "GET", false),
        (303, "HEAD", "HEAD", false),
        (303, "PUT", "GET", false),
        (301, "GET", "GET", true),
        (301, "PUT", "PUT", true),
        (302, "DELETE", "DELETE", true),
        (307, "POST", "POST", true),
        (308, "POST", "POST", true),
        (307, "PATCH", "PATCH", true),
    ];

    private static readonly (string HeaderName, bool IsSensitive)[] SensitivityRows =
    [
        ("Authorization", true),
        ("authorization", true),
        ("AUTHORIZATION", true),
        ("Proxy-Authorization", true),
        ("Cookie", true),
        ("cookie", true),
        ("X-Api-Token", true),
        ("x-api-token", true),
        ("X-Authorization-Scheme", false),
        ("Authorization-Hint", false),
        ("Cookies", false),
        ("X-Correlation-Id", false),
    ];

    private static readonly (string Left, string Right, bool SameOrigin)[] OriginRows =
    [
        ("https://api.example.com/a", "https://api.example.com/b", true),
        ("https://api.example.com/a", "https://API.EXAMPLE.COM/b", true),
        ("https://api.example.com/a", "HTTPS://api.example.com/b", true),
        ("https://api.example.com/a", "https://api.example.com:443/b", true),
        ("https://xn--bcher-kva.example/a", "https://b\u00fccher.example/b", true),
        ("https://api.example.com/a", "http://api.example.com/b", false),
        ("https://api.example.com/a", "https://api.example.com:8443/b", false),
        ("https://api.example.com/a", "https://cdn.example.com/b", false),
        ("https://api.example.com/a", "https://api.example.com.evil.test/b", false),
    ];

    public static TheoryData<int, bool> Statuses()
    {
        var data = new TheoryData<int, bool>();
        foreach (var (status, isRedirect) in StatusRows)
        {
            data.Add(status, isRedirect);
        }

        return data;
    }

    public static TheoryData<int, string, string, bool> Rewrites()
    {
        var data = new TheoryData<int, string, string, bool>();
        foreach (var (status, current, method, preserveBody) in RewriteRows)
        {
            data.Add(status, current, method, preserveBody);
        }

        return data;
    }

    public static TheoryData<string, bool> Sensitivity()
    {
        var data = new TheoryData<string, bool>();
        foreach (var (headerName, isSensitive) in SensitivityRows)
        {
            data.Add(headerName, isSensitive);
        }

        return data;
    }

    public static TheoryData<string, string, bool> Origins()
    {
        var data = new TheoryData<string, string, bool>();
        foreach (var (left, right, sameOrigin) in OriginRows)
        {
            data.Add(left, right, sameOrigin);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Statuses))]
    public void A_status_is_a_redirect_exactly_when_it_names_a_destination_to_follow(int status, bool expected)
        => Assert.Equal(expected, RedirectRules.IsRedirect(status));

    [Theory]
    [MemberData(nameof(Rewrites))]
    public void The_next_request_carries_the_method_and_body_the_status_implies(
        int status,
        string current,
        string expectedMethod,
        bool expectedPreservesBody)
    {
        var (method, preserveBody) = RedirectRules.NextRequest(status, current);

        Assert.Equal(expectedMethod, method);
        Assert.Equal(expectedPreservesBody, preserveBody);
    }

    [Theory]
    [MemberData(nameof(Sensitivity))]
    public void A_header_is_sensitive_by_whole_name_and_regardless_of_case(string headerName, bool expected)
        => Assert.Equal(expected, RedirectRules.IsSensitive(headerName, ["X-Api-Token"]));

    [Theory]
    [MemberData(nameof(Origins))]
    public void Two_destinations_share_an_origin_only_when_scheme_host_and_port_agree(
        string left,
        string right,
        bool expected)
        => Assert.Equal(expected, RedirectRules.IsSameOrigin(new Uri(left), new Uri(right)));

    [Fact]
    public void Every_table_is_populated_and_states_both_outcomes()
    {
        AssertBothOutcomes("statuses", StatusRows.Length, StatusRows.Select(row => row.IsRedirect));
        AssertBothOutcomes("rewrites", RewriteRows.Length, RewriteRows.Select(row => row.PreserveBody));
        AssertBothOutcomes("sensitivity", SensitivityRows.Length, SensitivityRows.Select(row => row.IsSensitive));
        AssertBothOutcomes("origins", OriginRows.Length, OriginRows.Select(row => row.SameOrigin));

        // The theory data and the row arrays are the same rows. A projection that dropped rows
        // would leave the assertions above describing cases no theory ever ran.
        Assert.Equal(StatusRows.Length, Statuses().Count);
        Assert.Equal(RewriteRows.Length, Rewrites().Count);
        Assert.Equal(SensitivityRows.Length, Sensitivity().Count);
        Assert.Equal(OriginRows.Length, Origins().Count);
    }

    [Fact]
    public void A_method_is_recognized_whatever_case_it_is_written_in()
    {
        // A compiled request upper-cases its method, so this guards against a caller that did
        // not rather than an expected input. Answering "preserve the body" for a lower-case
        // post on a 302 would replay a body every deployed upstream expects to be dropped.
        var (method, preserveBody) = RedirectRules.NextRequest(302, "post");

        Assert.Equal("GET", method);
        Assert.False(preserveBody);
    }

    [Fact]
    public void The_host_header_is_dropped_even_on_a_same_origin_redirect()
    {
        // It names the destination of a request that has already been answered. Carried
        // forward, it addresses the new destination under the old name.
        Assert.True(RedirectRules.IsDroppedOnRedirect("Host", sameOrigin: true, []));
        Assert.True(RedirectRules.IsDroppedOnRedirect("host", sameOrigin: false, []));
    }

    [Fact]
    public void A_credential_header_crosses_a_same_origin_redirect_and_not_a_cross_origin_one()
    {
        Assert.False(RedirectRules.IsDroppedOnRedirect("Authorization", sameOrigin: true, []));
        Assert.True(RedirectRules.IsDroppedOnRedirect("Authorization", sameOrigin: false, []));

        Assert.False(RedirectRules.IsDroppedOnRedirect("X-Api-Token", sameOrigin: true, ["X-Api-Token"]));
        Assert.True(RedirectRules.IsDroppedOnRedirect("X-Api-Token", sameOrigin: false, ["X-Api-Token"]));

        // A header nobody declared sensitive crosses either way.
        Assert.False(RedirectRules.IsDroppedOnRedirect("X-Correlation-Id", sameOrigin: false, ["X-Api-Token"]));
    }

    [Fact]
    public void A_relative_location_resolves_against_the_request_it_answered()
    {
        var current = new Uri("https://api.example.com/v1/items/42");

        Assert.Equal(
            "https://api.example.com/v1/items/43",
            RedirectRules.ResolveLocation(current, new Uri("43", UriKind.Relative)).ToString());

        Assert.Equal(
            "https://api.example.com/other",
            RedirectRules.ResolveLocation(current, new Uri("/other", UriKind.Relative)).ToString());

        // A relative value can leave the origin. It must resolve to an absolute destination so
        // the perimeter check has something to judge, rather than being treated as local
        // because of how it was spelled.
        Assert.Equal(
            "https://evil.test/x",
            RedirectRules.ResolveLocation(current, new Uri("//evil.test/x", UriKind.Relative)).ToString());
    }

    [Fact]
    public void An_absolute_location_is_used_as_stated()
        => Assert.Equal(
            "https://cdn.example.com/end",
            RedirectRules.ResolveLocation(
                new Uri("https://api.example.com/start"),
                new Uri("https://cdn.example.com/end")).ToString());

    [Fact]
    public void The_unconditionally_sensitive_set_is_exactly_the_three_well_known_names()
        => Assert.Equal(
            new List<string> { "Authorization", "Proxy-Authorization", "Cookie" },
            RedirectRules.AlwaysSensitiveHeaders.ToList());

    private static void AssertBothOutcomes(string table, int count, IEnumerable<bool> outcomes)
    {
        var rows = outcomes.ToList();

        Assert.True(count > 0, $"The '{table}' table is empty, so the theory over it proves nothing.");
        Assert.Contains(true, rows);
        Assert.Contains(false, rows);
    }
}
