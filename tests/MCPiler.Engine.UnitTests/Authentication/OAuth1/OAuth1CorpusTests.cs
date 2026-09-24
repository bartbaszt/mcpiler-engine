using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using MCPiler.Engine.Authentication.Signing;
using MCPiler.Engine.UnitTests;
using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication.OAuth1;

/// <summary>Completeness and failure-first checks for the authored OAuth1 corpus in this repository.</summary>
public sealed class OAuth1CorpusTests
{
    private static readonly string[] ExpectedCoverage =
    [
        "already-encoded-octets",
        "default-port",
        "delimiter-question-mark",
        "duplicate-names",
        "empty-names",
        "empty-path",
        "empty-values",
        "non-default-port",
        "plus-versus-percent20",
        "unicode",
    ];

    [Fact]
    public void Corpus_declared_counts_and_coverage_match_the_authored_rows()
    {
        var root = ReadCorpus();
        var vectors = root["signatureVectors"]!.AsArray().Select(static item => item!.AsObject()).ToList();
        var parameterCases = root["parameterCases"]!.AsArray().Select(static item => item!.AsObject()).ToList();
        var counts = root["declaredCounts"]!.AsObject();

        Assert.Equal(1, root["formatVersion"]!.GetValue<int>());
        Assert.Equal(vectors.Count, counts["signatureVectors"]!.GetValue<int>());
        Assert.Equal(parameterCases.Count, counts["parameterCases"]!.GetValue<int>());
        Assert.Equal(root["signatureMethods"]!.AsArray().Count, counts["signatureMethods"]!.GetValue<int>());
        Assert.Equal(root["parameterTransports"]!.AsArray().Count, counts["parameterTransports"]!.GetValue<int>());

        var ids = vectors.Select(static item => item["id"]!.GetValue<string>()).ToList();
        Assert.Equal(vectors.Count, ids.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(
            root["signatureMethods"]!.AsArray().Select(static item => item!.GetValue<string>()).Order(StringComparer.Ordinal),
            vectors.Select(static item => item["signatureMethod"]!.GetValue<string>()).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
        Assert.Equal(
            root["parameterTransports"]!.AsArray().Select(static item => item!.GetValue<string>()).Order(StringComparer.Ordinal),
            vectors.Select(static item => item["parameterTransport"]!.GetValue<string>()).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));

        var actualCoverage = parameterCases
            .SelectMany(static item => item["covers"]!.AsArray().Select(static coverage => coverage!.GetValue<string>()))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);
        Assert.Equal(ExpectedCoverage, actualCoverage);

        var providerScenarios = vectors
            .Where(static item => item["id"]!.GetValue<string>() is
                "flickr-style-hmac-sha1-query"
                or "jira-style-rsa-sha1-oob-header"
                or "netsuite-style-hmac-sha256-header-preprovisioned")
            .ToList();
        Assert.Equal(counts["providerScenarios"]!.GetValue<int>(), providerScenarios.Count);
        Assert.Equal(3, providerScenarios.Count);
        Assert.All(vectors, static item => Assert.Null(item["expectedRequest"]));
    }

    [Fact]
    public void Jira_RSA_vector_signature_verifies_with_the_committed_test_public_key()
    {
        var vector = SignatureVector("jira-style-rsa-sha1-oob-header");
        var expected = vector["expected"]!.AsObject();
        var publicKey = File.ReadAllText(Path.Combine(CorpusRoot, "jira-rsa-test-public.pem"));
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKey);

        Assert.True(rsa.VerifyData(
            Encoding.UTF8.GetBytes(expected["signatureBaseString"]!.GetValue<string>()),
            Convert.FromBase64String(expected["signature"]!.GetValue<string>()),
            HashAlgorithmName.SHA1,
            RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void Engine_production_signing_vectors_match_the_authored_protocol_values()
    {
        var assembly = typeof(SignableRequest).Assembly;
        var canonicalizer = OAuth1ProductionReflectionSeam.RequireType(assembly, "OAuth1Canonicalizer");
        var signer = OAuth1ProductionReflectionSeam.RequireType(assembly, "OAuth1Signer");

        foreach (var vector in ReadCorpus()["signatureVectors"]!.AsArray().Select(static item => item!.AsObject()))
        {
            var request = vector["request"]!.AsObject();
            var expected = vector["expected"]!.AsObject();
            var method = request["method"]!.GetValue<string>();
            var uri = new Uri(request["uri"]!.GetValue<string>(), UriKind.Absolute);
            var parameters = ReadPairs(vector["signatureParameters"]!.AsArray());

            var normalized = OAuth1ProductionReflectionSeam.InvokeString(canonicalizer, "NormalizeParameters", parameters);
            var baseStringUri = OAuth1ProductionReflectionSeam.InvokeString(canonicalizer, "BaseStringUri", uri);
            var baseString = OAuth1ProductionReflectionSeam.InvokeString(
                canonicalizer,
                "BuildSignatureBaseString",
                method,
                baseStringUri,
                normalized);

            Assert.Equal(expected["normalizedParameters"]!.GetValue<string>(), normalized);
            Assert.Equal(expected["baseStringUri"]!.GetValue<string>(), baseStringUri);
            Assert.Equal(expected["signatureBaseString"]!.GetValue<string>(), baseString);
            Assert.Equal(expected["signature"]!.GetValue<string>(), Sign(signer, vector, baseString));
        }
    }

    [Fact]
    public void Engine_production_pair_parser_and_normalizer_match_adversarial_cases()
    {
        var assembly = typeof(SignableRequest).Assembly;
        var canonicalizer = OAuth1ProductionReflectionSeam.RequireType(assembly, "OAuth1Canonicalizer");

        foreach (var item in ReadCorpus()["parameterCases"]!.AsArray().Select(static node => node!.AsObject()))
        {
            if (item["wireEncoded"] is JsonValue wireValue)
            {
                var parsed = OAuth1ProductionReflectionSeam.InvokePairs(
                    canonicalizer,
                    "ParseFormEncodedPairs",
                    wireValue.GetValue<string>());
                Assert.Equal(ReadPairs(item["decodedPairs"]!.AsArray()), parsed);
                Assert.Equal(
                    item["expectedNormalizedParameters"]!.GetValue<string>(),
                    OAuth1ProductionReflectionSeam.InvokeString(canonicalizer, "NormalizeParameters", parsed.ToArray()));
            }

            if (item["uri"] is JsonValue uriValue)
            {
                var uri = new Uri(uriValue.GetValue<string>(), UriKind.Absolute);
                Assert.Equal(
                    item["expectedBaseStringUri"]!.GetValue<string>(),
                    OAuth1ProductionReflectionSeam.InvokeString(canonicalizer, "BaseStringUri", uri));

                if (item["decodedPairs"] is JsonArray queryPairs)
                {
                    var parsedFromQuery = OAuth1ProductionReflectionSeam.InvokePairs(
                        canonicalizer,
                        "ParseQueryPairs",
                        uri);
                    Assert.Equal(ReadPairs(queryPairs), parsedFromQuery);

                    if (item["expectedNormalizedParameters"] is JsonValue expectedNormalized)
                    {
                        Assert.Equal(
                            expectedNormalized.GetValue<string>(),
                            OAuth1ProductionReflectionSeam.InvokeString(
                                canonicalizer,
                                "NormalizeParameters",
                                parsedFromQuery.ToArray()));
                    }
                }
            }
        }
    }

    private static string Sign(Type signer, JsonObject vector, string signatureBaseString)
    {
        var material = vector["material"]!.AsObject();
        return vector["signatureMethod"]!.GetValue<string>() switch
        {
            "HMAC-SHA1" => OAuth1ProductionReflectionSeam.InvokeString(
                signer,
                "SignHmacSha1",
                signatureBaseString,
                material["consumerSecret"]!.GetValue<string>(),
                material["tokenSecret"]!.GetValue<string>()),
            "RSA-SHA1" => OAuth1ProductionReflectionSeam.InvokeString(
                signer,
                "SignRsaSha1",
                signatureBaseString,
                File.ReadAllText(Path.Combine(CorpusRoot, material["privateKeyFile"]!.GetValue<string>()))),
            "PLAINTEXT" => OAuth1ProductionReflectionSeam.InvokeString(
                signer,
                "SignPlaintext",
                material["consumerSecret"]!.GetValue<string>(),
                material["tokenSecret"]!.GetValue<string>()),
            "HMAC-SHA256" => OAuth1ProductionReflectionSeam.InvokeString(
                signer,
                "SignHmacSha256",
                signatureBaseString,
                material["consumerSecret"]!.GetValue<string>(),
                material["tokenSecret"]!.GetValue<string>()),
            var method => throw new InvalidOperationException($"Unclassified OAuth1 signature method '{method}'."),
        };
    }

    private static JsonObject ReadCorpus()
        => JsonNode.Parse(File.ReadAllText(Path.Combine(CorpusRoot, "vectors.json")))!.AsObject();

    private static JsonObject SignatureVector(string id)
        => ReadCorpus()["signatureVectors"]!.AsArray()
            .Select(static item => item!.AsObject())
            .Single(item => string.Equals(item["id"]!.GetValue<string>(), id, StringComparison.Ordinal));

    private static KeyValuePair<string, string>[] ReadPairs(JsonArray array)
        => array.Select(static item => new KeyValuePair<string, string>(
                item![0]!.GetValue<string>(),
                item[1]!.GetValue<string>()))
            .ToArray();

    private static string CorpusRoot => TestRepository.Fixture("oauth1");
}
