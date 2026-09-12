using System;
using System.Collections.Generic;

using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// Builds the smallest manifest that can drive one execution against a loopback server.
/// </summary>
/// <remarks>
/// Assembled in code rather than loaded from a fixture, because what varies between these
/// tests is the port the server happened to bind, the limits under test and the credentials
/// referenced — none of which a committed document can carry. The shape is otherwise the
/// ordinary one: a policy with a base URL and limits, one operation, one agent surface entry
/// bound to it.
/// </remarks>
internal static class ExecutionManifests
{
    internal const string Slug = "get-thing";

    internal static ManifestDocument For(
        Uri baseUrl,
        ExecutionLimits? limits = null,
        IReadOnlyList<string>? allowedOrigins = null,
        ManifestOperation? operation = null,
        ManifestBinding? binding = null,
        CredentialsSection? credentials = null)
    {
        var declared = operation ?? Operation();

        return new ManifestDocument(
            ManifestFormatSupport.Maximum,
            new ServerSection("test-server", Version: "1.0.0"),
            new PolicySection(baseUrl, allowedOrigins!, limits),
            new OperationsSection([declared]),
            new AgentSurfaceSection(
            [
                new AgentOperationEntry(
                    Slug,
                    "Get thing",
                    binding ?? new HttpBinding(declared.Key)),
            ]),
            credentials);
    }

    internal static ManifestOperation Operation(
        string method = "GET",
        string path = "/thing",
        IReadOnlyList<ManifestParameter>? parameters = null,
        IReadOnlyDictionary<string, ManifestResponse>? responses = null)
        => new(
            ManifestOperation.BuildKey(method, path),
            method,
            path,
            UpstreamId: "getThing",
            Parameters: parameters!,
            Responses: responses!);

    /// <summary>A response declaration naming one media type under one status.</summary>
    internal static IReadOnlyDictionary<string, ManifestResponse> Declares(string status, string mediaType)
        => new Dictionary<string, ManifestResponse>(StringComparer.Ordinal)
        {
            [status] = new(new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal)
            {
                [mediaType] = new(mediaType),
            }),
        };
}
