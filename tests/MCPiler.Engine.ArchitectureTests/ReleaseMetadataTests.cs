using System.Text.RegularExpressions;
using System.Xml;

using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Static release-contract guards for the standalone Engine repository.
/// </summary>
public sealed class ReleaseMetadataTests
{
    private static string Read(string relative)
    {
        var path = EngineRepository.Absolute(relative);
        Assert.True(File.Exists(path), $"Expected release file is missing: {relative}");
        return File.ReadAllText(path);
    }

    private static string HostVersion()
    {
        var xml = new XmlDocument();
        xml.Load(EngineRepository.Absolute("src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj"));
        var value = xml.SelectSingleNode("//PropertyGroup/Version")?.InnerText.Trim();
        Assert.False(string.IsNullOrWhiteSpace(value));
        return value!;
    }

    [Fact]
    public void Host_version_and_first_changelog_header_are_the_same_stable_release()
    {
        var version = HostVersion();
        Assert.Matches(@"^\d+\.\d+\.\d+$", version);

        var changelog = Read("CHANGELOG.md");
        var first = Regex.Match(
            changelog,
            @"(?m)^##\s+(v\d+\.\d+\.\d+)\s*$",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));

        Assert.True(first.Success, "CHANGELOG.md has no stable release header.");
        Assert.Equal($"v{version}", first.Groups[1].Value);
        Assert.Contains("Manifest format", changelog, StringComparison.Ordinal);
        Assert.Contains("Diagnostic codes", changelog, StringComparison.Ordinal);
    }

    [Fact]
    public void Standalone_release_entry_points_and_helpers_exist()
    {
        string[] required =
        [
            "eng/check-release-metadata.sh",
            "eng/check-licenses.sh",
            "eng/test-release-helpers.sh",
            "eng/release.sh",
            "eng/publish-release.sh",
            "eng/verify-container.sh",
            ".github/workflows/release-patch.yml",
            ".github/workflows/release-minor.yml",
            ".github/workflows/release-major.yml",
            ".github/workflows/release.yml",
            ".github/workflows/release-resume.yml",
        ];

        Assert.All(required, relative => Assert.True(EngineRepository.Exists(relative), $"Missing {relative}"));
    }

    [Fact]
    public void Release_workflow_separates_repository_package_and_oidc_write_permissions()
    {
        var workflow = Read(".github/workflows/release.yml");

        Assert.Contains("contents: read", workflow, StringComparison.Ordinal);
        Assert.Contains("contents: write", workflow, StringComparison.Ordinal);
        Assert.Contains("packages: write", workflow, StringComparison.Ordinal);
        Assert.Contains("id-token: write", workflow, StringComparison.Ordinal);
        Assert.Contains("ubuntu-24.04-arm", workflow, StringComparison.Ordinal);
        Assert.Contains("linux/amd64,linux/arm64", workflow, StringComparison.Ordinal);
        Assert.Contains("provenance: false", workflow, StringComparison.Ordinal);
        Assert.Contains("sbom: false", workflow, StringComparison.Ordinal);

        var gitJob = Job(workflow, "git_publish");
        Assert.Contains("contents: write", gitJob, StringComparison.Ordinal);
        Assert.DoesNotContain("packages: write", gitJob, StringComparison.Ordinal);

        var candidateJob = Job(workflow, "candidate_publish");
        Assert.Contains("packages: write", candidateJob, StringComparison.Ordinal);
        Assert.DoesNotContain("contents: write", candidateJob, StringComparison.Ordinal);

        var supplyJob = Job(workflow, "supply_chain");
        Assert.Contains("id-token: write", supplyJob, StringComparison.Ordinal);
        Assert.DoesNotContain("contents: write", supplyJob, StringComparison.Ordinal);
    }

    [Fact]
    public void Supply_chain_attestation_types_match_the_predicate_shapes()
    {
        var workflow = Read(".github/workflows/release.yml");
        var verifier = Read("eng/verify-supply-chain.sh");

        // The workflow writes an in-toto SLSA v1 predicate ({ buildDefinition, runDetails }).
        // cosign's plain `slsaprovenance` type validates the v0.2 shape and rejects v1 with
        // "required field builder missing", so signing and verification must both select the v1
        // type. A mismatch here fails only at release time, after the candidate was already built.
        Assert.Contains("slsaprovenance1", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("--type slsaprovenance ", workflow, StringComparison.Ordinal);
        Assert.Contains("slsaprovenance1", verifier, StringComparison.Ordinal);
        Assert.DoesNotContain("--type slsaprovenance ", verifier, StringComparison.Ordinal);

        // The predicate really is the v1 shape, and the SPDX SBOM uses the json flavour.
        Assert.Contains("buildDefinition", workflow, StringComparison.Ordinal);
        Assert.Contains("runDetails", workflow, StringComparison.Ordinal);
        Assert.Contains("spdxjson", workflow, StringComparison.Ordinal);
        Assert.Contains("spdxjson", verifier, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_bundle_carries_head_so_consumer_jobs_get_a_working_tree()
    {
        // Normalize line endings: this file is read on Windows and in Linux CI alike, and the
        // assertions below are about the Git command, not about the checkout's line endings.
        var workflow = Read(".github/workflows/release.yml").Replace("\r\n", "\n");

        // A bundle created with only the branch ref leaves a plain `git clone` with
        // "remote HEAD refers to nonexistent ref, unable to checkout": the clone succeeds, the
        // working tree is empty, and every consumer job then fails with a missing-script error.
        var bundleCommands = workflow
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.StartsWith("git bundle create", StringComparison.Ordinal))
            .ToArray();
        Assert.NotEmpty(bundleCommands);
        Assert.All(bundleCommands, command =>
            Assert.EndsWith("main HEAD", command, StringComparison.Ordinal));

        // Every consumer must actually clone the bundle; if that changes, the bundle contract changes too.
        Assert.Contains("git clone release.bundle source", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void Prepare_job_can_read_the_private_remote_without_gaining_repository_write()
    {
        var workflow = Read(".github/workflows/release.yml");
        var prepareJob = Job(workflow, "prepare");
        var release = Read("eng/release.sh");

        // eng/release.sh --prepare checks the live remote: the origin-race guard fetches main and the
        // immutable-tag guard lists remote tags. The Engine repository is private, so the job must
        // retain read credentials or those checks fail with exit 128 before any metadata is prepared.
        Assert.Contains("persist-credentials: true", prepareJob, StringComparison.Ordinal);
        Assert.Contains("git -C \"$ROOT\" fetch origin main --tags", release, StringComparison.Ordinal);
        Assert.Contains("ls-remote --tags origin", release, StringComparison.Ordinal);

        // Retaining read credentials must not widen the job's repository permission.
        Assert.Contains("contents: read", prepareJob, StringComparison.Ordinal);
        Assert.DoesNotContain("contents: write", prepareJob, StringComparison.Ordinal);
        Assert.DoesNotContain("packages: write", prepareJob, StringComparison.Ordinal);
    }

    [Fact]
    public void Latest_is_owned_only_by_the_stable_release_path()
    {
        var ci = Read(".github/workflows/ci.yml");
        Assert.DoesNotContain("mcpiler-engine:latest", ci, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("imagetools create", ci, StringComparison.OrdinalIgnoreCase);

        var release = Read(".github/workflows/release.yml");
        Assert.Contains("LATEST_PROMOTED", release, StringComparison.Ordinal);
        Assert.Contains(":latest", release, StringComparison.Ordinal);
    }

    /// <summary>
    /// The deterministic metadata, licence and release-helper gates must run in ordinary CI, not
    /// only in the release workflow. When they ran only at release time, a guard that cannot pass
    /// where it actually executes (the executable-bit check on Linux) stayed latent until the first
    /// stable release.
    /// </summary>
    [Fact]
    public void Ordinary_ci_runs_the_deterministic_release_gates()
    {
        var ci = Read(".github/workflows/ci.yml");
        foreach (var gate in new[]
                 {
                     "bash eng/check-release-metadata.sh",
                     "bash eng/check-licenses.sh",
                     "bash eng/test-release-helpers.sh"
                 })
        {
            Assert.Contains(gate, ci, StringComparison.Ordinal);
        }

        // Ordinary CI must stay read-only; running the gates is verification, not mutation.
        Assert.Contains("contents: read", ci, StringComparison.Ordinal);
        Assert.DoesNotContain("contents: write", ci, StringComparison.Ordinal);
        Assert.DoesNotContain("packages: write", ci, StringComparison.Ordinal);

        // The release workflow keeps its own copy so a release never depends on ordinary CI having run.
        var release = Read(".github/workflows/release.yml");
        foreach (var gate in new[]
                 {
                     "bash eng/check-release-metadata.sh",
                     "bash eng/check-licenses.sh",
                     "bash eng/test-release-helpers.sh"
                 })
        {
            Assert.Contains(gate, release, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Release_identity_is_the_documented_dco_bot_identity()
    {
        var release = Read("eng/release.sh");
        Assert.Contains("github-actions[bot]", release, StringComparison.Ordinal);
        Assert.Contains("41898282+github-actions[bot]@users.noreply.github.com", release, StringComparison.Ordinal);
        Assert.Contains("git commit -s", release, StringComparison.Ordinal);
        Assert.Contains("Signed-off-by", release, StringComparison.Ordinal);
    }

    /// <summary>
    /// An annotated tag records a tagger identity, and <c>--publish-git</c> runs in its own job on a
    /// fresh runner where the prepare job's checkout-local identity does not exist. A bare
    /// <c>git tag -a</c> therefore fails with <c>fatal: empty ident name ... not allowed</c> after the
    /// candidate has already been built, published and smoked — observed on the first release run that
    /// passed the visibility gate. The tag command must carry the documented bot identity explicitly.
    /// </summary>
    [Fact]
    public void Annotated_release_tag_carries_the_bot_identity_explicitly()
    {
        var release = Read("eng/release.sh").Replace("\r\n", "\n");

        // Join backslash continuations first so a multi-line invocation is one logical command;
        // otherwise the identity on the first physical line would be invisible to a check that
        // starts at the line containing `tag -a`.
        var joined = release.Replace("\\\n", " ");
        var tagCommands = joined
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.Contains("tag -a", StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(tagCommands);

        // Every annotated tag invocation must set both identity values in the same command, because
        // the job has no configured identity and `-c` is scoped to that one invocation.
        foreach (var command in tagCommands)
        {
            Assert.Contains("user.name=", command, StringComparison.Ordinal);
            Assert.Contains("user.email=", command, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Dockerfile_carries_public_release_metadata_and_redistribution_material()
    {
        var dockerfile = Read("Dockerfile");

        foreach (var label in new[]
                 {
                     "org.opencontainers.image.source",
                     "org.opencontainers.image.revision",
                     "org.opencontainers.image.version",
                     "org.opencontainers.image.licenses",
                     "org.opencontainers.image.title",
                     "org.opencontainers.image.description",
                     "org.opencontainers.image.documentation",
                 })
        {
            Assert.Contains(label, dockerfile, StringComparison.Ordinal);
        }

        Assert.Contains("/licenses/mcpiler-engine/", dockerfile, StringComparison.Ordinal);
        Assert.Contains("LICENSE", dockerfile, StringComparison.Ordinal);
        Assert.Contains("NOTICE", dockerfile, StringComparison.Ordinal);
        Assert.Contains("THIRD-PARTY-NOTICES", dockerfile, StringComparison.Ordinal);
        Assert.Contains("/usr/share/dotnet/LICENSE.txt", dockerfile, StringComparison.Ordinal);
        Assert.Contains("/usr/share/dotnet/ThirdPartyNotices.txt", dockerfile, StringComparison.Ordinal);
    }

    [Fact]
    public void Container_verifier_runtime_state_check_supplies_a_valid_manifest_mount()
    {
        var verifier = Read("eng/verify-container.sh");

        Assert.Contains("tests/fixtures/manifests/minimal", verifier, StringComparison.Ordinal);
        Assert.Contains("--mount \"type=bind,src=$manifest_fixture,dst=/manifests/minimal,readonly\"", verifier, StringComparison.Ordinal);
        Assert.Contains("--mount /minimal=/manifests/minimal", verifier, StringComparison.Ordinal);
        Assert.Contains("--file-store-root /data/files", verifier, StringComparison.Ordinal);
        Assert.Contains("--runtime-state-root /data/runtime-state", verifier, StringComparison.Ordinal);
        Assert.Contains("runtime-state-key-file", verifier, StringComparison.Ordinal);
    }

    /// <summary>
    /// The resume workflow branches into two mutually exclusive modes, so exactly one branch job is
    /// always skipped, and GitHub Actions propagates a skip to every later job in the dependency chain.
    /// Only <c>stable_promote</c> used to declare the accepting <c>always()</c> form, so
    /// <c>latest_promote</c> and <c>github_release</c> were skipped with zero steps while the run still
    /// reported success (hosted run 35845059978) - a resume could not repair the very artifacts it
    /// exists to repair. Every job reachable after a conditional job must therefore declare its own
    /// accepting <c>if:</c>.
    /// </summary>
    [Fact]
    public void Every_resume_job_after_a_conditional_job_declares_an_accepting_if()
    {
        const string Workflow = ".github/workflows/release-resume.yml";
        var text = Read(Workflow);

        var jobs = ParseJobs(text);
        Assert.True(jobs.Count >= 6, $"Expected the resume job graph, parsed only {jobs.Count} jobs.");

        // The conditional jobs that always exist in exactly one mode: their sibling is always skipped.
        Assert.Contains("git_publish", jobs.Keys);
        Assert.Contains("resume_guard", jobs.Keys);

        var stranded = new List<string>();
        foreach (var (name, job) in jobs)
        {
            // A job is at risk when any transitive dependency declares an `if:` and this job does not.
            var risky = TransitiveNeeds(jobs, name)
                .Any(dep => jobs[dep].Condition is not null);
            if (risky && job.Condition is null)
            {
                stranded.Add(name);
            }
        }

        Assert.True(
            stranded.Count == 0,
            $"These resume jobs can be skipped by an ancestor's skip while the run reports success: {string.Join(", ", stranded)}.");

        // The accepting form must actually neutralise a skip, not merely exist.
        foreach (var tail in new[] { "stable_promote", "latest_promote", "github_release" })
        {
            var condition = jobs[tail].Condition;
            Assert.NotNull(condition);
            Assert.Contains("always()", condition, StringComparison.Ordinal);
            Assert.Contains("success", condition, StringComparison.Ordinal);
        }
    }

    private sealed record WorkflowJob(string Name, IReadOnlyList<string> Needs, string? Condition);

    private static Dictionary<string, WorkflowJob> ParseJobs(string workflow)
    {
        var jobs = new Dictionary<string, WorkflowJob>(StringComparer.Ordinal);
        // Job headers are two-space indented keys under the top-level `jobs:` block; the body runs to
        // the next job header or the end of the file.
        var headers = Regex.Matches(
            workflow,
            @"(?m)^  (?<name>[a-zA-Z0-9_-]+):\s*$",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));

        for (var i = 0; i < headers.Count; i++)
        {
            var name = headers[i].Groups["name"].Value;
            if (name is "on" or "permissions" or "concurrency" or "env" or "jobs")
            {
                continue;
            }

            var start = headers[i].Index + headers[i].Length;
            var end = i + 1 < headers.Count ? headers[i + 1].Index : workflow.Length;
            var body = workflow[start..end];

            // `on:`/`workflow_dispatch:`/`inputs:` live above the jobs block; skip non-job sections by
            // requiring the body to declare a runner or a need.
            if (!body.Contains("runs-on:", StringComparison.Ordinal)
                && !body.Contains("needs:", StringComparison.Ordinal))
            {
                continue;
            }

            var needs = new List<string>();
            var needsMatch = Regex.Match(
                body,
                @"(?m)^    needs:\s*(?<inline>\[[^\]]*\])\s*$",
                RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(5));
            if (needsMatch.Success)
            {
                needs.AddRange(
                    needsMatch.Groups["inline"].Value
                        .Trim('[', ']')
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
            var needsListMatch = Regex.Match(
                body,
                @"(?m)^    needs:\s*$",
                RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(5));
            if (needsListMatch.Success)
            {
                // Parse the YAML sequence without a nested-quantifier regex: each dependency is a
                // six-space indented list item immediately following the `needs:` key.
                foreach (var line in body[needsListMatch.Index..].Split('\n').Skip(1))
                {
                    var item = line.TrimEnd('\r');
                    if (!item.StartsWith("      - ", StringComparison.Ordinal))
                    {
                        break;
                    }

                    needs.Add(item[8..].Trim());
                }
            }

            var conditionMatch = Regex.Match(
                body,
                @"(?m)^    if:\s*(?<condition>.+)$",
                RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(5));
            var condition = conditionMatch.Success ? conditionMatch.Groups["condition"].Value.Trim() : null;

            jobs[name] = new WorkflowJob(name, needs, condition);
        }

        return jobs;
    }

    private static IEnumerable<string> TransitiveNeeds(Dictionary<string, WorkflowJob> jobs, string name)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var queue = new Queue<string>(jobs[name].Needs);
        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!seen.Add(current))
            {
                continue;
            }

            if (!jobs.TryGetValue(current, out var job))
            {
                continue;
            }

            foreach (var next in job.Needs)
            {
                queue.Enqueue(next);
            }
        }

        return seen;
    }

    private static string Job(string workflow, string name)
    {
        var match = Regex.Match(
            workflow,
            $@"(?ms)^  {Regex.Escape(name)}:\s*\n(?<body>.*?)(?=^  [a-zA-Z0-9_-]+:\s*\n|\z)",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));
        Assert.True(match.Success, $"Workflow job '{name}' was not found.");
        return match.Groups["body"].Value;
    }
}
