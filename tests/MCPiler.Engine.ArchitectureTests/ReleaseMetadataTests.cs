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
            "eng/release-bundle.sh",
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
        Assert.Contains("docker/setup-qemu-action@", workflow, StringComparison.Ordinal);
        Assert.Contains("--platform linux/arm64", workflow, StringComparison.Ordinal);
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
    public void Private_engine_workflows_require_a_dedicated_unmetered_runner()
    {
        const string runner = "runs-on: [self-hosted, Linux, X64, mcpiler-engine-release]";
        foreach (var path in new[]
        {
            ".github/workflows/ci.yml",
            ".github/workflows/secret-scan.yml",
            ".github/workflows/release.yml",
            ".github/workflows/release-resume.yml",
        })
        {
            var workflow = Read(path);
            var requested = workflow.Split('\n').Select(line => line.Trim())
                .Where(line => line.StartsWith("runs-on:", StringComparison.Ordinal))
                .ToArray();

            Assert.NotEmpty(requested);
            Assert.All(requested, actual => Assert.Equal(runner, actual));
        }

        // A persistent self-hosted runner with Docker access must not execute fork PR code.
        Assert.Contains("github.event.pull_request.head.repo.full_name == github.repository",
            Read(".github/workflows/ci.yml"), StringComparison.Ordinal);
        Assert.Contains("github.event.pull_request.head.repo.full_name == github.repository",
            Read(".github/workflows/secret-scan.yml"), StringComparison.Ordinal);
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

    /// <summary>
    /// GitHub Actions artifact storage is unavailable for the release account (owner decision
    /// 2026-10-23), so no Engine workflow may upload or download an artifact. The prepared release
    /// commit travels as a base64 job output and as a marked prepare-job log block; the candidate
    /// SBOM travels as a base64 job output. This guard parses every <c>uses:</c> value in every
    /// workflow, and the fixture self-test proves the parser actually sees artifact actions.
    /// </summary>
    [Fact]
    public void No_engine_workflow_uses_artifact_storage()
    {
        var workflows = Directory
            .EnumerateFiles(EngineRepository.Absolute(".github/workflows"))
            .Where(path => path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();

        Assert.True(workflows.Length >= 6, $"Expected the Engine workflow set, found {workflows.Length} files.");

        var uses = workflows
            .SelectMany(path => UsesValues(File.ReadAllText(path)).Select(value => (File: Path.GetFileName(path), Value: value)))
            .ToArray();

        // Without this the two assertions below could pass because the parser returned nothing.
        Assert.Contains(uses, entry => entry.Value.StartsWith("actions/checkout@", StringComparison.Ordinal));

        var artifactActions = uses
            .Where(entry => entry.Value.StartsWith("actions/upload-artifact", StringComparison.Ordinal)
                || entry.Value.StartsWith("actions/download-artifact", StringComparison.Ordinal))
            .Select(entry => $"{entry.File}: {entry.Value}")
            .ToArray();
        Assert.True(
            artifactActions.Length == 0,
            $"Engine workflows must not use GitHub Actions artifact storage: {string.Join(", ", artifactActions)}");

        // Fixture self-test: the same detector must report artifact actions when they are present.
        const string fixture = """
            jobs:
              probe:
                steps:
                  - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
                  - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4
                  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
            """;
        var fixtureUses = UsesValues(fixture).ToArray();
        Assert.Equal(3, fixtureUses.Length);
        Assert.Contains(fixtureUses, value => value.StartsWith("actions/upload-artifact@", StringComparison.Ordinal));
        Assert.Contains(fixtureUses, value => value.StartsWith("actions/download-artifact@", StringComparison.Ordinal));
    }

    /// <summary>
    /// Every job that consumes the prepared release commit restores it through
    /// <c>eng/release-bundle.sh</c> from the reviewed base commit, and the restore proves the release
    /// commit identity before moving the working tree. Duplicating that logic in each job is what
    /// this guard exists to prevent.
    /// </summary>
    [Fact]
    public void Release_bundle_consumers_restore_through_the_release_bundle_helper()
    {
        var workflow = Read(".github/workflows/release.yml").Replace("\r\n", "\n");

        var prepareJob = Job(workflow, "prepare");
        Assert.Contains("release_bundle: ${{ steps.bundle.outputs.release_bundle }}", prepareJob, StringComparison.Ordinal);
        Assert.Contains("release_bundle_sha256: ${{ steps.bundle.outputs.release_bundle_sha256 }}", prepareJob, StringComparison.Ordinal);
        Assert.Contains("eng/release-bundle.sh write", prepareJob, StringComparison.Ordinal);
        Assert.Contains("--base-sha \"$BASE_SHA\"", prepareJob, StringComparison.Ordinal);
        Assert.Contains("--release-commit \"$RELEASE_COMMIT\"", prepareJob, StringComparison.Ordinal);
        // Consumers receive the payload as one step environment string, so the cap that matters is
        // the Linux MAX_ARG_STRLEN limit (131072 bytes for NAME + '=' + value + NUL), not the 1 MB
        // job-output limit. The producer must use the helper's single shared cap, not a local number.
        Assert.DoesNotContain("--max-bytes", prepareJob, StringComparison.Ordinal);
        // The failed-run resume path reads the marked block back from this job's log.
        Assert.Contains("eng/release-bundle.sh print-log", prepareJob, StringComparison.Ordinal);

        foreach (var name in new[] { "candidate_publish", "smoke_amd64", "smoke_arm64", "supply_chain" })
        {
            var job = Job(workflow, name);
            Assert.Contains("ref: ${{ needs.prepare.outputs.base_sha }}", job, StringComparison.Ordinal);
            Assert.Contains("persist-credentials: false", job, StringComparison.Ordinal);
            Assert.Contains("eng/release-bundle.sh restore", job, StringComparison.Ordinal);
            Assert.Contains("--base64-stdin", job, StringComparison.Ordinal);
            Assert.Contains("--sha256 \"$RELEASE_BUNDLE_SHA256\"", job, StringComparison.Ordinal);
            Assert.Contains("--base-sha \"$BASE_SHA\"", job, StringComparison.Ordinal);
            Assert.Contains("--release-commit \"$RELEASE_COMMIT\"", job, StringComparison.Ordinal);
        }

        // git_publish keeps the authenticated main checkout and only moves the working tree.
        var gitPublishJob = Job(workflow, "git_publish");
        Assert.Contains("ref: main", gitPublishJob, StringComparison.Ordinal);
        Assert.Contains("persist-credentials: true", gitPublishJob, StringComparison.Ordinal);
        Assert.Contains("eng/release-bundle.sh restore", gitPublishJob, StringComparison.Ordinal);
        Assert.Contains("--release-commit \"$RELEASE_COMMIT\"", gitPublishJob, StringComparison.Ordinal);

        // The SBOM generator stays in its own job and hands the document over as a base64 output.
        var sbomJob = Job(workflow, "sbom");
        Assert.Contains("sbom_gz_base64:", sbomJob, StringComparison.Ordinal);
        Assert.Contains("sbom_sha256:", sbomJob, StringComparison.Ordinal);
        Assert.Contains("eng/release-bundle.sh sbom-encode", sbomJob, StringComparison.Ordinal);
        Assert.DoesNotContain("--max-bytes", sbomJob, StringComparison.Ordinal);
        Assert.Contains("upload-artifact: false", sbomJob, StringComparison.Ordinal);

        var supplyChainJob = Job(workflow, "supply_chain");
        Assert.Contains("eng/release-bundle.sh sbom-restore", supplyChainJob, StringComparison.Ordinal);
        Assert.Contains("--sha256 \"$SBOM_SHA256\"", supplyChainJob, StringComparison.Ordinal);
    }

    /// <summary>
    /// Both payload producers share one encoded-size cap in <c>eng/release-bundle.sh</c>. The cap
    /// exists because a consumer receives the payload as a single step environment string, and Linux
    /// rejects any one such string above MAX_ARG_STRLEN = 131072 bytes with E2BIG at step start. A cap
    /// derived only from the 1 MB job-output limit would let prepare succeed and every consumer fail.
    /// </summary>
    [Fact]
    public void Payload_cap_is_one_shared_constant_below_the_linux_argument_limit()
    {
        var script = Read("eng/release-bundle.sh");
        var linuxArgumentLimit = 131072;
        var longEnvironmentName = "RELEASE_BUNDLE_SHA256"; // longest payload variable used by the workflows

        Assert.Contains("PAYLOAD_MAX_ENCODED_BYTES=120000", script, StringComparison.Ordinal);
        var constant = Regex.Match(
            script,
            @"(?m)^PAYLOAD_MAX_ENCODED_BYTES=(?<value>\d+)$",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));
        Assert.True(constant.Success, "The shared payload cap constant is missing.");
        var cap = int.Parse(constant.Groups["value"].Value, System.Globalization.CultureInfo.InvariantCulture);

        // NAME + '=' + value + NUL must stay below the per-string ceiling with real headroom.
        Assert.True(
            cap + longEnvironmentName.Length + 2 < linuxArgumentLimit,
            $"PAYLOAD_MAX_ENCODED_BYTES={cap} plus the '{longEnvironmentName}' name does not fit under {linuxArgumentLimit} bytes.");

        // Neither producer may reintroduce a local number that only respects the 1 MB output cap.
        Assert.DoesNotContain("700000", script, StringComparison.Ordinal);
        Assert.DoesNotContain("900000", script, StringComparison.Ordinal);

        // The cap must be a real guard: a payload just above it is refused, not truncated.
        Assert.Contains("above the $max_bytes-byte payload budget", script, StringComparison.Ordinal);
        Assert.Contains("131072", script, StringComparison.Ordinal);
    }

    /// <summary>
    /// Moving the release payload out of artifact storage must not widen any job's token. The
    /// prepare job still needs read credentials for its origin-race and immutable-tag checks, and the
    /// SBOM job still only reads the package it scans.
    /// </summary>
    [Fact]
    public void Prepare_and_sbom_jobs_keep_their_read_only_permissions()
    {
        var workflow = Read(".github/workflows/release.yml");

        var prepareJob = Job(workflow, "prepare");
        Assert.Contains("contents: read", prepareJob, StringComparison.Ordinal);
        Assert.DoesNotContain("contents: write", prepareJob, StringComparison.Ordinal);
        Assert.DoesNotContain("packages: write", prepareJob, StringComparison.Ordinal);
        Assert.DoesNotContain("id-token: write", prepareJob, StringComparison.Ordinal);
        Assert.DoesNotContain("actions: write", prepareJob, StringComparison.Ordinal);

        var sbomJob = Job(workflow, "sbom");
        Assert.Contains("contents: read", sbomJob, StringComparison.Ordinal);
        Assert.Contains("packages: read", sbomJob, StringComparison.Ordinal);
        Assert.DoesNotContain("packages: write", sbomJob, StringComparison.Ordinal);
        Assert.DoesNotContain("contents: write", sbomJob, StringComparison.Ordinal);
        Assert.DoesNotContain("id-token: write", sbomJob, StringComparison.Ordinal);
        Assert.DoesNotContain("actions: write", sbomJob, StringComparison.Ordinal);
    }

    /// <summary>
    /// A failed run exposes neither artifacts nor job outputs to the resume run, so the visibility
    /// resume finds the prepare job logs through the Actions API, restores the bundle from the marked
    /// block, and republishes the same outputs so the downstream jobs restore exactly as they do
    /// inside a single run.
    /// </summary>
    [Fact]
    public void Resume_extracts_the_release_bundle_from_the_prepare_job_log()
    {
        var workflow = Read(".github/workflows/release-resume.yml").Replace("\r\n", "\n");

        var resolveJob = Job(workflow, "resolve");
        Assert.Contains("actions: read", resolveJob, StringComparison.Ordinal);
        Assert.Contains("GH_TOKEN: ${{ github.token }}", resolveJob, StringComparison.Ordinal);
        Assert.Contains("repos/$REPOSITORY/actions/runs/$RUN_ID/jobs", resolveJob, StringComparison.Ordinal);
        Assert.Contains("endswith(\"METADATA_PREPARED / RELEASE_COMMITTED\")", resolveJob, StringComparison.Ordinal);
        Assert.Contains("eng/release-bundle.sh extract-best-block", resolveJob, StringComparison.Ordinal);
        Assert.Contains("--input prepare-log-manifest.tsv", resolveJob, StringComparison.Ordinal);
        Assert.Contains("eng/release-bundle.sh restore", resolveJob, StringComparison.Ordinal);
        Assert.Contains("release_bundle:", resolveJob, StringComparison.Ordinal);
        Assert.Contains("release_bundle_sha256:", resolveJob, StringComparison.Ordinal);
        Assert.Contains("eng/release-bundle.sh encode", resolveJob, StringComparison.Ordinal);
        Assert.DoesNotContain("--max-bytes", resolveJob, StringComparison.Ordinal);

        // A re-run attempt can hide the valid block behind a prepare job that failed early, so the
        // query must include every attempt and the selection must walk candidates newest first.
        Assert.Contains("filter=all&per_page=100", resolveJob, StringComparison.Ordinal);
        Assert.Contains("sort -t$'\\t' -k1,1r -k2,2nr", resolveJob, StringComparison.Ordinal);
        Assert.Contains("while IFS=$'\\t' read -r started_at job_id", resolveJob, StringComparison.Ordinal);

        // The restored base must be live origin/main: that is the precondition --publish-git later
        // enforces, and comparing HEAD^ with the bundle prerequisite would only repeat the restore.
        Assert.Contains("git -C source rev-parse --verify --quiet 'origin/main^{commit}'", resolveJob, StringComparison.Ordinal);
        Assert.Contains("\"$bundle_base\" == \"$origin_main\"", resolveJob, StringComparison.Ordinal);
        Assert.Contains("\"$base_sha\" == \"$origin_main\"", resolveJob, StringComparison.Ordinal);
        Assert.DoesNotContain("drifted from the bundle prerequisite", resolveJob, StringComparison.Ordinal);

        var verifyJob = Job(workflow, "verify_candidate");
        Assert.Contains("eng/release-bundle.sh restore", verifyJob, StringComparison.Ordinal);
        Assert.Contains("--release-commit \"$RELEASE_COMMIT\"", verifyJob, StringComparison.Ordinal);

        var gitPublishJob = Job(workflow, "git_publish");
        Assert.Contains("eng/release-bundle.sh restore", gitPublishJob, StringComparison.Ordinal);
        Assert.Contains("ref: main", gitPublishJob, StringComparison.Ordinal);
        Assert.Contains("contents: write", gitPublishJob, StringComparison.Ordinal);
    }

    /// <summary>
    /// A resume takes a run ID from a manual input, so it must refuse any run that is not this
    /// repository's own stable release entry workflow dispatched from <c>main</c>. Without these
    /// checks a run from a fork, a feature branch, another workflow, or another trigger could supply
    /// the prepared commit the resume then verifies and publishes.
    /// </summary>
    [Fact]
    public void Resume_accepts_only_a_dispatched_stable_release_run_from_this_repository()
    {
        var workflow = Read(".github/workflows/release-resume.yml").Replace("\r\n", "\n");
        var resolveJob = Job(workflow, "resolve");

        Assert.Contains("repos/$REPOSITORY/actions/runs/$RUN_ID", resolveJob, StringComparison.Ordinal);
        Assert.Contains(".github/workflows/release-patch.yml|.github/workflows/release-minor.yml|.github/workflows/release-major.yml", resolveJob, StringComparison.Ordinal);
        Assert.Contains("[[ \"$run_event\" == 'workflow_dispatch' ]]", resolveJob, StringComparison.Ordinal);
        Assert.Contains("[[ \"$head_branch\" == 'main' ]]", resolveJob, StringComparison.Ordinal);
        Assert.Contains("(.head_repository.full_name // \"\")", resolveJob, StringComparison.Ordinal);
        Assert.Contains("[[ \"$head_repository\" == \"$REPOSITORY\" ]]", resolveJob, StringComparison.Ordinal);

        // Each dimension has its own fail-closed message; a silent fallback would hide the reject.
        foreach (var message in new[]
                 {
                     "was not started by a stable release entry workflow",
                     "was not dispatched manually",
                     "was not dispatched from main",
                     "belongs to repository"
                 })
        {
            Assert.Contains(message, resolveJob, StringComparison.Ordinal);
        }

        Assert.Contains("exit 1", resolveJob, StringComparison.Ordinal);
        Assert.Contains("exit 64", resolveJob, StringComparison.Ordinal);
    }

    /// <summary>
    /// Job logs contain terminal escape sequences in their echoed <c>run:</c> headers, and <c>gh api</c>
    /// refuses such a log unless the runner's gh supports <c>--allow-escape-sequences</c> — a version
    /// that is not pinned and whose flag an older preinstalled gh rejects. The resume therefore reads
    /// the log with curl: curl follows the redirect to the signed blob URL and drops the Authorization
    /// header on the cross-host hop, which is why <c>--location-trusted</c> must never appear.
    /// </summary>
    [Fact]
    public void Resume_downloads_job_logs_with_curl_and_never_with_gh_api()
    {
        var workflow = Read(".github/workflows/release-resume.yml").Replace("\r\n", "\n");
        var resolveJob = Job(workflow, "resolve");

        Assert.Contains("curl --fail --silent --show-error --location --retry 3", resolveJob, StringComparison.Ordinal);
        Assert.Contains("-H \"Authorization: Bearer ${GH_TOKEN}\"", resolveJob, StringComparison.Ordinal);
        Assert.Contains("-H \"Accept: application/vnd.github+json\"", resolveJob, StringComparison.Ordinal);
        Assert.Contains("-H \"X-GitHub-Api-Version: 2022-11-28\"", resolveJob, StringComparison.Ordinal);
        Assert.Contains("https://api.github.com/repos/${REPOSITORY}/actions/jobs/${job_id}/logs", resolveJob, StringComparison.Ordinal);
        Assert.Contains("-o \"$log\"", resolveJob, StringComparison.Ordinal);

        // No job-log download through the gh CLI, in either spelling, and no token forwarding.
        Assert.DoesNotContain("gh api \"repos/$REPOSITORY/actions/jobs", resolveJob, StringComparison.Ordinal);
        Assert.DoesNotContain("actions/jobs/$job_id/logs", resolveJob, StringComparison.Ordinal);
        Assert.DoesNotContain("actions/jobs/$JOB_ID/logs", resolveJob, StringComparison.Ordinal);
        var executableLocationTrusted = workflow
            .Split('\n')
            .Any(line => !line.TrimStart().StartsWith('#')
                && line.Contains("--location-trusted", StringComparison.Ordinal));
        Assert.False(executableLocationTrusted, "curl must not forward Authorization across hosts with --location-trusted.");

        // A failed or empty download stays visible and still lets an older attempt win.
        Assert.Contains("log download failed; treating it as an invalid candidate", resolveJob, StringComparison.Ordinal);
        Assert.Contains("returned an empty log; treating it as an invalid candidate", resolveJob, StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>printf 'name=%s' "$(helper)" &gt;&gt;"$GITHUB_OUTPUT"</c> hides a helper failure: a failing
    /// command substitution in argument position does not trigger <c>set -e</c>, so the job publishes
    /// an empty or truncated output and fails much later. Every output write therefore consumes an
    /// already-captured variable.
    /// </summary>
    [Fact]
    public void Workflow_outputs_never_embed_a_command_substitution()
    {
        var writes = 0;
        foreach (var path in Directory.EnumerateFiles(EngineRepository.Absolute(".github/workflows")).Where(IsWorkflow))
        {
            var lines = File.ReadAllLines(path);
            for (var index = 0; index < lines.Length; index++)
            {
                if (!lines[index].Contains("$GITHUB_OUTPUT", StringComparison.Ordinal))
                {
                    continue;
                }

                writes++;
                Assert.False(
                    lines[index].Contains("$(", StringComparison.Ordinal),
                    $"{Path.GetFileName(path)}:{index + 1} writes an output through an inline command substitution, which hides the failure from errexit.");
            }
        }

        Assert.True(writes >= 8, $"Expected the release output writes, found {writes}.");

        // Fixture self-test: the detector must report an inline substitution when one is present.
        const string fixture = "run: |\n  printf 'x=%s\\n' \"$(false)\" >>\"$GITHUB_OUTPUT\"\n";
        var offending = fixture
            .Split('\n')
            .Count(line => line.Contains("$GITHUB_OUTPUT", StringComparison.Ordinal) && line.Contains("$(", StringComparison.Ordinal));
        Assert.Equal(1, offending);
    }

    private static bool IsWorkflow(string path) =>
        path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase);

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
    public void Resume_requires_release_commit_ancestry_in_origin_main()
    {
        var release = Read("eng/release.sh");
        Assert.Contains("merge-base --is-ancestor", release, StringComparison.Ordinal);
        Assert.Contains("is not contained in origin/main", release, StringComparison.Ordinal);
    }

    [Fact]
    public void Engine_workflows_cannot_read_private_platform_state()
    {
        foreach (var path in Directory.EnumerateFiles(EngineRepository.Absolute(".github/workflows"), "*.yml"))
        {
            var source = File.ReadAllText(path);
            Assert.DoesNotContain("github.com/bartbaszt/mcpiler.git", source, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("github.com/bartbaszt/mcpiler/", source, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("github.com/bartbaszt/mcpiler\"", source, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("ENGINE_SUBMODULE_TOKEN", source, StringComparison.Ordinal);
        }
    }

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

    /// <summary>
    /// Every <c>uses:</c> value in a workflow: action references and reusable-workflow calls, with
    /// trailing comments removed. Quote and whitespace variants are tolerated so the guard cannot be
    /// bypassed by re-formatting a step.
    /// </summary>
    private static IEnumerable<string> UsesValues(string workflow)
    {
        var matches = Regex.Matches(
            workflow.Replace("\r\n", "\n"),
            @"(?m)^\s*(?:-\s*)?uses:\s*(?<value>[^\s#]+)",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));

        foreach (Match match in matches)
        {
            yield return match.Groups["value"].Value.Trim('\'', '"');
        }
    }
}
