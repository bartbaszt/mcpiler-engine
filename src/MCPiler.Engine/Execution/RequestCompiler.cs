using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution.Serialization;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution;

/// <summary>
/// Compiles a request from an operation, a governing base URL, and an argument object.
/// </summary>
/// <remarks>
/// <para>
/// The compiled value is a deterministic function of its inputs: identical inputs produce identical
/// bytes, which is what makes a recorded request a usable contract. An unsupported construct fails
/// compilation instead of producing a request that is legal and wrong.
/// </para>
/// <para>
/// Compilation reads nothing but the operation and the arguments. There is no source document, no
/// intermediate model, and no store to consult — the operation model carries every value the request
/// needs, including the style and explode defaults, which is the property that makes serving from a
/// compiled artifact possible at all.
/// </para>
/// </remarks>
public static class RequestCompiler
{
    /// <summary>Compiles one request.</summary>
    /// <param name="operation">The operation to invoke.</param>
    /// <param name="baseUri">
    /// The governing base URL. It must carry neither a query nor a fragment, because the operation's
    /// own path and query are appended rather than resolved against it.
    /// </param>
    /// <param name="arguments">Argument values by parameter name, plus an optional <c>body</c> member.</param>
    /// <param name="files">Raw bytes for file-carrying body members.</param>
    /// <param name="fileNames">File names for file-carrying body members.</param>
    /// <param name="fileMediaTypes">Media types for file-carrying body members.</param>
    /// <param name="partHeaderValues">Values for headers a multipart part declares.</param>
    /// <param name="boundaryProvider">
    /// Supplies the multipart delimiter. Left null when serving, so each request gets a fresh one.
    /// </param>
    public static CompiledRequest Compile(
        ManifestOperation operation,
        Uri baseUri,
        JsonObject arguments,
        IReadOnlyDictionary<string, byte[]>? files = null,
        IReadOnlyDictionary<string, string>? fileNames = null,
        IReadOnlyDictionary<string, string>? fileMediaTypes = null,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? partHeaderValues = null,
        IBoundaryProvider? boundaryProvider = null)
    {
        var decisions = new List<SerializationDecision>();
        var headers = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var cookies = new List<string>();
        var query = new List<string>();
        var path = operation.Path;
        var missing = new List<string>();

        foreach (var parameter in operation.Parameters)
        {
            var arg = arguments[parameter.Name];

            if (arg is null)
            {
                if (parameter.Required && !parameter.AllowEmptyValue)
                {
                    missing.Add(parameter.Name);
                }

                continue;
            }

            switch (parameter.In)
            {
                case ParameterLocation.Path:
                    var replacement = ParameterSerializer.PathValue(parameter, arg);
                    path = path.Replace("{" + parameter.Name + "}", replacement, StringComparison.Ordinal);
                    decisions.Add(Decision(parameter, replacement));
                    break;

                case ParameterLocation.Query:
                    var q = ParameterSerializer.QueryValue(parameter, arg);
                    query.Add(q);
                    decisions.Add(Decision(parameter, q));
                    break;

                case ParameterLocation.Header:
                    var h = ParameterSerializer.HeaderValue(parameter, arg);
                    headers[parameter.Name] = [h];
                    decisions.Add(Decision(parameter, h));
                    break;

                case ParameterLocation.Cookie:
                    var c = ParameterSerializer.CookieValue(parameter, arg);
                    cookies.Add(c);
                    decisions.Add(Decision(parameter, c));
                    break;

                default:
                    // The location vocabulary is closed and every member is handled above. This arm
                    // exists so the switch is exhaustive, not as a refusal: a location a reader
                    // cannot produce needs no runtime diagnostic, and one that looked like a
                    // refusal would suggest the vocabulary is open.
                    throw new UnreachableException(
                        $"Parameter location '{parameter.In}' is outside the closed vocabulary.");
            }
        }

        if (missing.Count > 0)
        {
            throw new ArgumentValidationException(
                missing[0],
                $"Required parameter(s) missing: {string.Join(", ", missing)}.");
        }

        // An unfilled placeholder is a contract violation when its parameter is required or unknown.
        // An optional parameter simply absent from the arguments collapses to an empty substitution,
        // which is what makes an optional path segment expressible at all.
        var residual = FindPlaceholders(path);

        if (residual.Count > 0)
        {
            var unresolved = new List<string>();

            foreach (var name in residual)
            {
                var parameter = operation.Parameters.FirstOrDefault(
                    p => string.Equals(p.Name, name, StringComparison.Ordinal) && p.In == ParameterLocation.Path);

                if (parameter is null || parameter.Required)
                {
                    unresolved.Add(name);
                }
                else
                {
                    path = path.Replace("{" + name + "}", string.Empty, StringComparison.Ordinal);
                }
            }

            if (unresolved.Count > 0)
            {
                throw new ArgumentValidationException(
                    unresolved[0],
                    $"Path template '{operation.Path}' has unfilled required parameter(s): {string.Join(", ", unresolved)}.");
            }
        }

        if (!string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
        {
            throw new InvalidBaseUrlException(
                "The base URL must not contain a query or fragment.");
        }

        // Append semantics, not relative resolution. RFC 3986 resolution would discard a configured
        // path prefix the moment an operation path begins with a slash, which every operation path
        // does. Only the slash at the join is normalized; the already-serialized suffix is preserved
        // byte-for-byte, because re-normalizing it would undo deliberate percent-encoding.
        var authority = baseUri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        var basePath = baseUri.AbsolutePath == "/" ? string.Empty : baseUri.AbsolutePath.TrimEnd('/');
        var operationPath = "/" + path.TrimStart('/');
        var url = authority + basePath + operationPath;

        if (query.Count > 0)
        {
            url += "?" + string.Join("&", query);
        }

        var uri = new Uri(url);

        byte[]? body = null;
        string? bodyMediaType = null;

        if (operation.RequestBody is { } requestBody && requestBody.Content.Count > 0)
        {
            var (selected, ambiguous) = BodySerializer.SelectMediaType(requestBody.Content, arguments["body"]);

            // The media type to send comes back from the writer, not from the selected key: writing a
            // multipart body decides the mandatory delimiter, and only the writer knows it.
            (body, bodyMediaType) = BodySerializer.Serialize(
                selected,
                requestBody.Content[selected],
                arguments["body"],
                files,
                fileNames,
                fileMediaTypes,
                partHeaderValues,
                boundaryProvider);

            if (ambiguous)
            {
                decisions.Add(new SerializationDecision
                {
                    ParameterName = "body",
                    Location = "body",
                    Style = "media-type",
                    Explode = null,
                    EncodedValue = $"defaulted to {selected}",
                });
            }
        }

        if (cookies.Count > 0)
        {
            headers["Cookie"] = [string.Join("; ", cookies)];
        }

        if (body is not null && bodyMediaType is not null)
        {
            headers["Content-Type"] = [bodyMediaType];
        }

        return new CompiledRequest
        {
            Method = operation.Method.ToUpperInvariant(),
            Uri = uri,
            ExactUrl = url,
            Headers = headers.ToDictionary(
                static kv => kv.Key,
                static kv => kv.Value.ToArray(),
                StringComparer.OrdinalIgnoreCase),
            Body = body,
            BodyMediaType = bodyMediaType,
            Decisions = decisions,
        };
    }

    // The recorded style and explode are the effective ones rather than the declared ones. A reader
    // of a compiled request wants to know what was applied; what the document happened to spell out
    // is visible in the document.
    private static SerializationDecision Decision(ManifestParameter parameter, string encoded) => new()
    {
        ParameterName = parameter.Name,
        Location = Vocabulary.Write(parameter.In),
        Style = Vocabulary.Write(parameter.EffectiveStyle),
        Explode = parameter.EffectiveExplode,
        EncodedValue = encoded,
    };

    private static List<string> FindPlaceholders(string path)
    {
        var found = new List<string>();
        var sb = new StringBuilder();
        var inBrace = false;

        foreach (var ch in path)
        {
            if (ch == '{')
            {
                inBrace = true;
                sb.Clear();
            }
            else if (ch == '}')
            {
                if (inBrace)
                {
                    found.Add(sb.ToString());
                }

                inBrace = false;
            }
            else if (inBrace)
            {
                sb.Append(ch);
            }
        }

        return found;
    }
}
