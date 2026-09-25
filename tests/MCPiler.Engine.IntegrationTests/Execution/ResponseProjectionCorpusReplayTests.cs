using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Projection;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Mcp.Navigator;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Transform;
using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// Replays the authored cross-repository response-projection corpus against the Engine runtime.
/// </summary>
/// <remarks>
/// <para>
/// The corpus at <c>tests/fixtures/response-projection/cases.json</c> is one contract with two
/// consumers. Its expected values were authored rather than generated, so replaying it here is
/// evidence about the product instead of a recording of it. This suite reads the Engine-local
/// copy only: Engine must build and test from a standalone checkout and must never reach into
/// the Platform tree for a fixture.
/// </para>
/// <para>
/// The transport is substituted rather than driven over a socket, so the declared final
/// effective URI in each case is exactly what the projection sees. A loopback host would rebind
/// the port and silently change the URI the corpus fixes, and a relative <c>Link</c> resolves
/// against that URI.
/// </para>
/// <para>
/// Loading and validation are part of every case: a case whose Manifest must be refused proves
/// that first, and a case whose Manifest loads is served from it. Nothing here duplicates the
/// projection logic; the comparison is between the authored expectation and what the runtime
/// produced.
/// </para>
/// </remarks>
public sealed class ResponseProjectionCorpusReplayTests
{
    /// <summary>The connector-specific sensitive names; the corpus declares none.</summary>
    private static readonly HashSet<string> NoSensitiveNames = new(StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void Every_metadata_case_replays_to_its_authored_expectation()
    {
        List<string> failures = [];

        foreach (JsonObject @case in Cases("metadata."))
        {
            if (Replay(@case) is { } failure)
            {
                failures.Add(failure);
            }
        }

        AssertEmpty(failures);
    }

    [Fact]
    public void Every_pagination_case_replays_to_its_authored_expectation()
    {
        List<string> failures = [];

        foreach (JsonObject @case in Cases("pagination."))
        {
            if (Replay(@case) is { } failure)
            {
                failures.Add(failure);
            }
        }

        AssertEmpty(failures);
    }

    [Fact]
    public void Every_legacy_case_replays_to_its_authored_expectation()
    {
        List<string> failures = [];

        foreach (JsonObject @case in Cases("legacy."))
        {
            if (Replay(@case) is { } failure)
            {
                failures.Add(failure);
            }
        }

        AssertEmpty(failures);
    }

    /// <summary>
    /// Fails with every disagreement in full, because a truncated collection message hides
    /// the very difference a corpus replay exists to report.
    /// </summary>
    private static void AssertEmpty(IReadOnlyList<string> failures)
    {
        if (failures.Count > 0)
        {
            Assert.Fail(string.Join(Environment.NewLine, failures));
        }
    }

    /// <summary>
    /// Replays one case, returning a description of the first disagreement or null on agreement.
    /// </summary>
    private static string? Replay(JsonObject @case)
    {
        string id = @case["id"]!.GetValue<string>();
        JsonObject manifestNode = Corpus()["manifests"]![@case["manifest"]!.GetValue<string>()]!.AsObject();
        JsonObject expected = @case["expected"]!.AsObject();

        ManifestReadResult read = ManifestReader.Read(
            InMemoryManifestSource.FromText(manifestNode.ToJsonString()));

        if (expected["loadRefusal"]?.GetValue<bool>() == true)
        {
            if (read.Succeeded)
            {
                return $"{id}: the Manifest loaded, but the corpus expects a refusal.";
            }

            string[] expectedRefusalCodes = [.. (expected["loadRefusalCodes"]?.AsArray() ?? [])
                .Select(static code => code!.GetValue<string>())];
            string[] actualRefusalCodes = [.. read.Diagnostics
                .Where(static diagnostic => diagnostic.IsError)
                .Select(static diagnostic => diagnostic.Code)];
            return expectedRefusalCodes.Length == 0
                || expectedRefusalCodes.SequenceEqual(actualRefusalCodes, StringComparer.Ordinal)
                ? null
                : $"{id}: the refusal codes were [{string.Join(", ", actualRefusalCodes)}], "
                    + $"but the corpus expects [{string.Join(", ", expectedRefusalCodes)}].";
        }

        if (!read.Succeeded)
        {
            return $"{id}: the Manifest was refused: "
                + Errors(read.Diagnostics);
        }

        ManifestDocument manifest = read.Manifest!;

        // Validation is part of the replay too: a policy the static checks refuse must never
        // reach extraction, and a case expecting a runtime answer proves the static checks pass.
        IReadOnlyList<ManifestDiagnostic> validation = ManifestValidator.Validate(manifest);

        if (validation.Any(static diagnostic => diagnostic.IsError))
        {
            return $"{id}: the Manifest failed validation: " + Errors(validation);
        }

        JsonObject invoke = @case["invoke"]!.AsObject();
        string surfaceSlug = invoke["surface"]!.GetValue<string>();
        string operationSlug = invoke["operation"]!.GetValue<string>();
        JsonObject arguments = invoke["arguments"] is JsonObject declaredArguments
            ? Resolve(declaredArguments)!.AsObject()
            : [];

        if (manifest.Server.Surfaces.SingleOrDefault(surface => surface.Slug == surfaceSlug) is not { } surface)
        {
            return $"{id}: the Manifest declares no surface '{surfaceSlug}'.";
        }

        if (manifest.AgentSurface.Operation(operationSlug) is not { } operation)
        {
            return $"{id}: the Manifest declares no operation '{operationSlug}'.";
        }

        JsonObject responseSpec = @case["response"]!.AsObject();
        CorpusBody body = ResolveBody(responseSpec["body"]);
        JsonObject response = Resolve(responseSpec)!.AsObject();
        response["body"] = body.Value;

        if (operation.OutputProjection is not { } projection)
        {
            // A case without a projection is a legacy case: the runtime returns the body it read
            // and nothing else, exactly as it did before projection existed.
            JsonNode? legacy = body.Value?.DeepClone();
            JsonNode expectedLegacy = expected["result"]!;

            return CanonicalJson.Serialize(legacy).AsSpan().SequenceEqual(CanonicalJson.Serialize(expectedLegacy))
                ? null
                : $"{id}: the legacy result was '{legacy?.ToJsonString()}', "
                    + $"but the corpus expects '{expectedLegacy.ToJsonString()}'.";
        }

        List<ManifestDiagnostic> derivation = [];
        MountedSurface mounted = SurfaceCatalogue.Build(manifest, surface, derivation);
        var mount = new MountedManifest(
            "/api",
            "(in memory)",
            manifest,
            manifest.Policy,
            [mounted],
            NavigatorIndex.Resolve(manifest, derivation));

        // The final body is whatever the operation's own output program produced. Applying the
        // real stage rather than assuming the raw body is the point of the transform-coexistence
        // cases: a presentation transform may remove or reshape the agent body while pagination
        // still reads the bounded raw response.
        var execution = new EngineExecutionResult
        {
            StatusCode = response["status"]!.GetValue<int>(),
            ResponseHeaders = Headers(response),
            ResponseMediaType = "application/json",
            ResponseEffectiveUri = response["effectiveUri"]?.GetValue<string>() is { } effective
                ? new Uri(effective)
                : null,
            ResponseBody = body.Bytes,
        };

        if (!TransformStage.TryOutput(manifest, operation, execution, out byte[]? transformed, out string? transformFailure))
        {
            return $"{id}: the output transformation failed: {transformFailure}";
        }

        JsonNode? finalBody = transformed is null
            ? body.Value?.DeepClone()
            : ParseBody(transformed);
        bool hasFinalBody = transformed is not null
            ? transformed.Length > 0
            : body.HasBody;

        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection,
            response["status"]!.GetValue<int>(),
            Headers(response),
            response["effectiveUri"]?.GetValue<string>() is { } uri ? new Uri(uri) : null,
            finalBody: finalBody?.DeepClone(),
            rawBody: body.Value?.DeepClone(),
            currentArguments: arguments,
            sensitiveHeaderNames: NoSensitiveNames,
            resolveTarget: new SurfaceContinuationResolver(manifest, mount, mounted, operationSlug),
            hasFinalBody: hasFinalBody);

        JsonNode expectedValue = Resolve(expected["result"]!)!;
        string[] expectedDiagnostics = [.. (expected["diagnostics"]?.AsArray() ?? [])
            .Select(static code => code!.GetValue<string>())];

        if (!CanonicalJson.Serialize(outcome.Value).AsSpan().SequenceEqual(CanonicalJson.Serialize(expectedValue)))
        {
            string observed = string.Join(", ", outcome.Diagnostics.Select(static diagnostic => diagnostic.Code));

            return $"{id}: the projected value was '{outcome.Value?.ToJsonString()}', "
                + $"but the corpus expects '{expectedValue.ToJsonString()}'; "
                + $"final body was '{finalBody?.ToJsonString()}'; "
                + $"observed diagnostics: [{observed}].";
        }

        string[] actualDiagnostics = [.. outcome.Diagnostics.Select(static diagnostic => diagnostic.Code)];

        return actualDiagnostics.SequenceEqual(expectedDiagnostics, StringComparer.Ordinal)
            ? null
            : $"{id}: the diagnostics were [{string.Join(", ", actualDiagnostics)}], "
                + $"but the corpus expects [{string.Join(", ", expectedDiagnostics)}].";
    }

    /// <summary>
    /// Resolves the corpus directive vocabulary into the value it declares.
    /// </summary>
    /// <remarks>
    /// The corpus authored large boundary values with directives so a 16 KiB fixture stays
    /// readable and a reviewer can see the intended byte count instead of counting characters.
    /// Both consumers resolve the same vocabulary, so the resolved value is the contract.
    /// </remarks>
    private static JsonNode? Resolve(JsonNode? node) => node switch
    {
        JsonObject root when root["$repeatUtf8"] is JsonObject directive =>
            JsonValue.Create(RepeatUtf8(
                directive["text"]!.GetValue<string>(),
                directive["bytes"]!.GetValue<int>())),
        JsonObject root when root["$repeatArray"] is JsonObject directive =>
            RepeatArray(
                directive["value"]!.DeepClone(),
                directive["count"]!.GetValue<int>()),
        JsonObject root when root["$concatUtf8"] is JsonArray parts =>
            JsonValue.Create(string.Concat(parts.Select(part => Resolve(part)!.GetValue<string>()))),
        JsonObject root => Resolved(root),
        JsonArray array => ResolvedArray(array),
        _ => node?.DeepClone(),
    };

    private static CorpusBody ResolveBody(JsonNode? node)
    {
        if (node is not JsonObject root || root["$rawBody"] is not JsonObject directive)
        {
            JsonNode? value = Resolve(node);
            byte[]? bytes = value is null
                ? null
                : System.Text.Encoding.UTF8.GetBytes(value.ToJsonString());
            return new CorpusBody(value, bytes, bytes is { Length: > 0 });
        }

        string text = Resolve(directive["text"])!.GetValue<string>();
        byte[] rawBytes = System.Text.Encoding.UTF8.GetBytes(text);
        return new CorpusBody(ParseBody(rawBytes), rawBytes, rawBytes.Length > 0);
    }

    private static JsonNode? ParseBody(byte[]? body)
    {
        if (body is null || body.Length == 0)
        {
            return null;
        }

        try
        {
            return JsonNode.Parse(body);
        }
        catch (JsonException)
        {
            return JsonValue.Create(System.Text.Encoding.UTF8.GetString(body));
        }
    }

    private static JsonObject Resolved(JsonObject root)
    {
        var resolved = new JsonObject();

        foreach ((string key, JsonNode? value) in root)
        {
            resolved[key] = Resolve(value);
        }

        return resolved;
    }

    private static JsonArray ResolvedArray(JsonArray array)
    {
        var resolved = new JsonArray();

        foreach (JsonNode? item in array)
        {
            resolved.Add(Resolve(item));
        }

        return resolved;
    }

    private static string RepeatUtf8(string text, int bytes)
    {
        var builder = new System.Text.StringBuilder(bytes + text.Length);

        while (System.Text.Encoding.UTF8.GetByteCount(builder.ToString()) < bytes)
        {
            builder.Append(text);
        }

        // A multi-character text repeats as a whole; a boundary case therefore uses a
        // single-character text when it needs the exact declared length.
        string candidate = builder.ToString();
        int actual = System.Text.Encoding.UTF8.GetByteCount(candidate);

        return actual == bytes
            ? candidate
            : throw new InvalidOperationException(
                $"The corpus directive cannot produce exactly {bytes} UTF-8 bytes from '{text}'.");
    }

    private static JsonArray RepeatArray(JsonNode? value, int count)
    {
        var array = new JsonArray();

        for (var index = 0; index < count; index++)
        {
            array.Add(value?.DeepClone());
        }

        return array;
    }

    /// <summary>The declared response headers as the ordered multi-value map the runtime builds.</summary>
    private static Dictionary<string, string[]> Headers(JsonObject response)
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        foreach (JsonObject header in (response["headers"]?.AsArray() ?? []).OfType<JsonObject>())
        {
            string name = header["name"]!.GetValue<string>();
            string[] values = [.. (header["values"]?.AsArray() ?? [])
                .Select(static value => value!.GetValue<string>())];

            headers[name] = headers.TryGetValue(name, out string[]? existing)
                ? [.. existing, .. values]
                : values;
        }

        return headers;
    }

    private static string Errors(IReadOnlyList<ManifestDiagnostic> diagnostics) =>
        string.Join("; ", diagnostics
            .Where(static diagnostic => diagnostic.IsError)
            .Select(static diagnostic => diagnostic.Code + " " + diagnostic.Message));

    /// <summary>Every corpus case whose id starts with <paramref name="prefix"/>.</summary>
    private static IEnumerable<JsonObject> Cases(string prefix) =>
        Corpus()["cases"]!.AsArray()
            .OfType<JsonObject>()
            .Where(@case => @case["id"]!.GetValue<string>().StartsWith(prefix, StringComparison.Ordinal));

    private static JsonObject Corpus() =>
        JsonNode.Parse(File.ReadAllText(Fixture("response-projection", "cases.json")))!.AsObject();

    /// <summary>
    /// The absolute path of a file under this repository's <c>tests/fixtures</c>.
    /// </summary>
    /// <remarks>
    /// Resolved from this file's compile-time path rather than the test output directory, so the
    /// corpus cannot silently drop out of the suite because a content-copy item was forgotten.
    /// The fallback from the output directory keeps a deterministic CI build working, where a
    /// mapped source path may not be an accessible checkout.
    /// </remarks>
    private static string Fixture(params string[] segments)
    {
        var source = Path.GetDirectoryName(SourceFile());

        var root = source is null ? null : FindRoot(source);

        root ??= FindRoot(AppContext.BaseDirectory)
            ?? throw new InvalidOperationException(
                "Could not locate MCPiler.Engine.slnx above the test source or output directory.");

        return Path.Combine([root, "tests", "fixtures", .. segments]);
    }

    private static string? FindRoot(string directory)
    {
        var current = new DirectoryInfo(directory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "MCPiler.Engine.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        return null;
    }

    private static string SourceFile([System.Runtime.CompilerServices.CallerFilePath] string path = "") => path;

    private sealed record CorpusBody(JsonNode? Value, byte[]? Bytes, bool HasBody);
}
