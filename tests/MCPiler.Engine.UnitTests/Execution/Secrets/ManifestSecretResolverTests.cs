using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Secrets;

/// <summary>
/// Credential reference resolution: what is read, what is refused, and what a refusal is
/// allowed to say.
/// </summary>
/// <remarks>
/// The real environment and the real filesystem are used rather than substitutes. Reading them
/// is the whole behaviour under test, and a substituted environment would assert that a
/// dictionary lookup works. Each test uses a variable name and a directory nothing else
/// touches, so nothing here depends on execution order.
/// </remarks>
public sealed class ManifestSecretResolverTests : IDisposable
{
    private const string Canary = "CANARY-6f3a9d21-secret-material";

    private readonly List<string> _variables = [];
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-secret-" + Guid.NewGuid().ToString("N"));

    public ManifestSecretResolverTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public async Task An_environment_reference_resolves_to_the_variables_value()
    {
        var variable = SetVariable("token-value");

        var resolved = await Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable)));

        Assert.Equal("token-value", Assert.Single(resolved).Value);
    }

    [Fact]
    public async Task An_environment_value_is_used_verbatim_including_its_whitespace()
    {
        // A credential is an opaque string. Trimming it would send something other than what
        // the deployment supplied, and the upstream would answer with an authentication error
        // pointing nowhere near the cause.
        var variable = SetVariable("  spaced token\t");

        var resolved = await Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable)));

        Assert.Equal("  spaced token\t", Assert.Single(resolved).Value);
    }

    [Fact]
    public async Task An_unset_environment_variable_is_an_authentication_failure_naming_the_reference()
    {
        var variable = "MCPILER_TEST_UNSET_" + Guid.NewGuid().ToString("N");

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable))));

        Assert.Equal("api", failure.CredentialId);
        Assert.Contains($"fromEnv:{variable}", failure.Message, StringComparison.Ordinal);
        Assert.Contains("not set", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_empty_environment_value_is_a_distinct_failure_from_an_unset_one()
    {
        // Different mistakes with different corrections: one deployment forgot the variable,
        // the other believes it supplied it.
        var variable = SetVariable(string.Empty);

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable))));

        Assert.Contains("empty value", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("not set", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("secret-from-file", "secret-from-file")]
    [InlineData("secret-from-file\n", "secret-from-file")]
    [InlineData("secret-from-file\r\n", "secret-from-file")]
    [InlineData("secret-from-file\r", "secret-from-file")]
    [InlineData("secret-from-file\n\n", "secret-from-file\n")]
    [InlineData("  padded  \n", "  padded  ")]
    public async Task A_file_reference_drops_exactly_one_trailing_line_ending(string written, string expected)
    {
        // Editors and secret mounts terminate the last line, so one newline is an artifact of
        // how files are written. A second one, or any other whitespace, is content this code
        // has no basis for discarding.
        var path = WriteFile("token", written);

        var resolved = await Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.File(path)));

        Assert.Equal(expected, Assert.Single(resolved).Value);
    }

    [Fact]
    public async Task A_missing_file_is_an_authentication_failure_naming_the_reference()
    {
        var path = Path.Combine(_directory, "absent");

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.File(path))));

        Assert.Contains($"fromFile:{path}", failure.Message, StringComparison.Ordinal);
        Assert.Contains("does not exist", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_directory_is_a_distinct_failure_from_a_missing_file()
    {
        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.File(_directory))));

        Assert.Contains("directory", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("does not exist", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_empty_file_is_an_empty_value_failure()
    {
        var path = WriteFile("blank", "\n");

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.File(path))));

        Assert.Contains("empty value", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inline_material_is_refused_unless_it_is_explicitly_allowed()
    {
        var credential = Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Literal(Canary));

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => Resolve(credential));

        Assert.Contains("inline", failure.Message, StringComparison.Ordinal);

        // A manifest is copied, diffed, attached to an issue and committed. A secret inside one
        // has already been disclosed by the time it is executed, so the refusal is the default
        // and lifting it is deliberate.
        Assert.DoesNotContain(Canary, failure.Message, StringComparison.Ordinal);

        var allowed = await Resolve(new SecretResolutionOptions(AllowInlineCredentials: true), credential);
        Assert.Equal(Canary, Assert.Single(allowed).Value);
    }

    [Fact]
    public async Task Only_the_credentials_the_binding_references_are_read()
    {
        var referenced = SetVariable("used-token");

        // Four declarations pointing at variables nothing set. If the resolver read the
        // section rather than the reference list, this manifest could not execute at all.
        var section = new CredentialsSection(
        [
            Credential("unused-a", CredentialScheme.Header, "X-A", CredentialReference.Env("MCPILER_TEST_ABSENT_A")),
            Credential("unused-b", CredentialScheme.Header, "X-B", CredentialReference.Env("MCPILER_TEST_ABSENT_B")),
            Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(referenced)),
            Credential("unused-c", CredentialScheme.Header, "X-C", CredentialReference.File(Path.Combine(_directory, "absent-c"))),
            Credential("unused-d", CredentialScheme.Header, "X-D", CredentialReference.File(Path.Combine(_directory, "absent-d"))),
        ]);

        var resolved = await new ManifestSecretResolver()
            .ResolveAsync(section, ["api"], TestContext.Current.CancellationToken);

        Assert.Equal("api", Assert.Single(resolved).Id);
    }

    [Fact]
    public async Task The_same_reference_named_twice_resolves_once()
    {
        var variable = SetVariable("one-token");
        var section = new CredentialsSection(
            [Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable))]);

        var resolved = await new ManifestSecretResolver()
            .ResolveAsync(section, ["api", "api"], TestContext.Current.CancellationToken);

        Assert.Equal("api", Assert.Single(resolved).Id);
    }

    [Fact]
    public async Task A_reference_the_manifest_does_not_declare_is_an_authentication_failure()
    {
        var variable = SetVariable("one-token");
        var section = new CredentialsSection(
            [Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable))]);

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => new ManifestSecretResolver()
                .ResolveAsync(section, ["api", "ghost"], TestContext.Current.CancellationToken)
                .AsTask());

        Assert.Equal("ghost", failure.CredentialId);
        Assert.Contains("declares no credential", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Resolution_follows_declaration_order_regardless_of_reference_order()
    {
        var first = SetVariable("first-value");
        var second = SetVariable("second-value");

        var section = new CredentialsSection(
        [
            Credential("alpha", CredentialScheme.Header, "X-Alpha", CredentialReference.Env(first)),
            Credential("beta", CredentialScheme.Header, "X-Beta", CredentialReference.Env(second)),
        ]);

        var resolved = await new ManifestSecretResolver()
            .ResolveAsync(section, ["beta", "alpha"], TestContext.Current.CancellationToken);

        Assert.Equal(["alpha", "beta"], resolved.Select(entry => entry.Id).ToList());
    }

    [Fact]
    public async Task No_refusal_repeats_material_that_a_neighbouring_source_holds()
    {
        // Both sources hold the canary and both resolve. The failing reference is a third one,
        // and its message must describe the reference rather than reach for anything that
        // happened to be readable.
        var variable = SetVariable(Canary);
        var path = WriteFile("canary", Canary);
        var absent = "MCPILER_TEST_UNSET_" + Guid.NewGuid().ToString("N");

        var section = new CredentialsSection(
        [
            Credential("env-canary", CredentialScheme.Header, "X-Env", CredentialReference.Env(variable)),
            Credential("file-canary", CredentialScheme.Header, "X-File", CredentialReference.File(path)),
            Credential("broken", CredentialScheme.Header, "X-Broken", CredentialReference.Env(absent)),
        ]);

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(
            () => new ManifestSecretResolver()
                .ResolveAsync(section, ["env-canary", "file-canary", "broken"], TestContext.Current.CancellationToken)
                .AsTask());

        Assert.DoesNotContain(Canary, failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Canary, failure.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_empty_reference_list_resolves_nothing()
    {
        var resolved = await new ManifestSecretResolver()
            .ResolveAsync(CredentialsSection.Empty, [], TestContext.Current.CancellationToken);

        Assert.Empty(resolved);
    }

    [Fact]
    public async Task A_resolved_credential_describes_its_reference_without_its_value()
    {
        var variable = SetVariable(Canary);

        var resolved = await Resolve(Credential("api", CredentialScheme.Bearer, "Authorization", CredentialReference.Env(variable)));
        var credential = Assert.Single(resolved);

        Assert.Equal($"fromEnv:{variable}", credential.ReferenceDescription);
        Assert.DoesNotContain(Canary, credential.ReferenceDescription, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        foreach (var variable in _variables)
        {
            Environment.SetEnvironmentVariable(variable, null);
        }

        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static ManifestCredential Credential(
        string id,
        CredentialScheme scheme,
        string slot,
        CredentialReference value,
        CredentialLocation? location = null)
        => new(id, scheme, slot, value, location);

    private Task<IReadOnlyList<ResolvedCredential>> Resolve(ManifestCredential credential)
        => Resolve(SecretResolutionOptions.Default, credential);

    private Task<IReadOnlyList<ResolvedCredential>> Resolve(
        SecretResolutionOptions options,
        ManifestCredential credential)
        => new ManifestSecretResolver(options)
            .ResolveAsync(new CredentialsSection([credential]), [credential.Id], TestContext.Current.CancellationToken)
            .AsTask();

    private string SetVariable(string value)
    {
        var name = "MCPILER_TEST_SECRET_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(name, value);
        _variables.Add(name);
        return name;
    }

    private string WriteFile(string name, string contents)
    {
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, contents);
        return path;
    }
}
