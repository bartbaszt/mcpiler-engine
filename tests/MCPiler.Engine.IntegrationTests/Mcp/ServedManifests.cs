using System.Globalization;
using System.IO;
using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// Manifests written to disk for the wire tests.
/// </summary>
/// <remarks>
/// <para>
/// Written as JSON text rather than assembled from the model, so what the tests serve is what
/// the readers accept. A fixture built by calling the model's constructors would skip the
/// readers entirely and could describe a document no operator could author.
/// </para>
/// <para>
/// These documents state <c>"authenticationRequired": false</c> explicitly. They exercise the
/// protocol surface — listing, invocation, exposure, identity, Navigator — against a process
/// that trusts no issuer, and a mount that requires a token cannot start without one. Stating
/// the opt-out here is what keeps this suite about the wire rather than about authorization,
/// and unlike the absent member it is a statement a reader can see. The authorization suite
/// carries its own protected manifests and its own issuer.
/// </para>
/// </remarks>
internal static class ServedManifests
{
    /// <summary>One surface, one operation, one declared input schema.</summary>
    public const string OneSurface = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "authenticationRequired": false,
                "surfaces": [
                  {
                    "slug": "full",
                    "isDefault": true,
                    "operations": [ { "operation": "list-pets" }, { "operation": "add-pet" } ]
                  }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": {
                "operations": [
                  { "key": "GET /pets", "method": "GET", "path": "/pets" },
                  { "key": "POST /pets", "method": "POST", "path": "/pets" }
                ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "list-pets",
                    "name": "List pets",
                    "summary": "Lists every pet.",
                    "inputSchema": {
                      "type": "object",
                      "properties": { "limit": { "type": "integer" } }
                    },
                    "binding": { "type": "http", "operation": "GET /pets" }
                  },
                  {
                    "slug": "add-pet",
                    "name": "Add pet",
                    "binding": { "type": "http", "operation": "POST /pets" }
                  }
                ]
              }
            }
          }
        }
        """;

    /// <summary>The one-surface wire fixture with the protected-mount default made explicit.</summary>
    public static string ProtectedOneSurface
        => OneSurface.Replace(
            "\"authenticationRequired\": false",
            "\"authenticationRequired\": true",
            StringComparison.Ordinal);

    /// <summary>
    /// A protected, same-named probe whose definition, upstream and managed secret identify one
    /// generation. The two generations used by activation tests differ only in those observable
    /// values, so a mixed request cannot pass by returning a generic success.
    /// </summary>
    public static string ProtectedGeneration(
        Uri upstream,
        string generation,
        string secretVariable,
        string toolSlug = "probe")
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentException.ThrowIfNullOrWhiteSpace(generation);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretVariable);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolSlug);

        return $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": {
                  "name": "Generation API",
                  "authenticationRequired": true,
                  "surfaces": [
                    { "slug": "full", "isDefault": true,
                      "operations": [ { "operation": "{{toolSlug}}" } ] }
                  ]
                } },
                "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}" } },
                "operations": { "inline": { "operations": [
                  { "key": "GET /generation", "method": "GET", "path": "/generation",
                    "responses": { "200": { "content": {
                      "application/json": { "schema": { "type": "object" } }
                    } } } }
                ] } },
                "agentSurface": { "inline": { "operations": [
                  { "slug": "{{toolSlug}}", "name": "{{generation}} probe",
                    "summary": "{{generation}} definition",
                    "binding": { "type": "http", "operation": "GET /generation",
                      "credentialRef": ["generation-secret"] } }
                ] } },
                "credentials": { "inline": { "formatVersion": 3, "credentials": [
                  { "id": "generation-secret", "scheme": "apiKey", "slot": "X-Generation-Secret",
                    "location": "header", "value": { "fromEnv": "{{secretVariable}}" } }
                ] } }
              }
            }
            """;
    }

    /// <summary>
    /// Two protected sibling surfaces whose advertised tools and executable paths are distinct.
    /// Stateful-session tests use this to prove a session id cannot move one surface binding onto
    /// a different HTTP resource.
    /// </summary>
    public static string ProtectedSiblingSurfaces(Uri upstream)
    {
        ArgumentNullException.ThrowIfNull(upstream);

        return $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": {
                  "name": "Sibling API",
                  "authenticationRequired": true,
                  "surfaces": [
                    { "slug": "read", "isDefault": true,
                      "operations": [ { "operation": "read-probe" } ] },
                    { "slug": "write", "operations": [ { "operation": "write-probe" } ] }
                  ]
                } },
                "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}" } },
                "operations": { "inline": { "operations": [
                  { "key": "GET /read-probe", "method": "GET", "path": "/read-probe" },
                  { "key": "GET /write-probe", "method": "GET", "path": "/write-probe" }
                ] } },
                "agentSurface": { "inline": { "operations": [
                  { "slug": "read-probe", "name": "Read probe",
                    "binding": { "type": "http", "operation": "GET /read-probe" } },
                  { "slug": "write-probe", "name": "Write probe",
                    "binding": { "type": "http", "operation": "GET /write-probe" } }
                ] } }
              }
            }
            """;
    }

    /// <summary>Three surfaces over one operation set, the middle one default.</summary>
    public const string ThreeSurfaces = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "authenticationRequired": false,
                "surfaces": [
                  { "slug": "read", "operations": [ { "operation": "list-pets" } ] },
                  {
                    "slug": "full",
                    "isDefault": true,
                    "operations": [ { "operation": "list-pets" }, { "operation": "add-pet" } ]
                  },
                  { "slug": "write", "operations": [ { "operation": "add-pet" } ] }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": {
                "operations": [
                  { "key": "GET /pets", "method": "GET", "path": "/pets" },
                  { "key": "POST /pets", "method": "POST", "path": "/pets" }
                ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "list-pets",
                    "name": "List pets",
                    "binding": { "type": "http", "operation": "GET /pets" }
                  },
                  {
                    "slug": "add-pet",
                    "name": "Add pet",
                    "binding": { "type": "http", "operation": "POST /pets" }
                  }
                ]
              }
            }
          }
        }
        """;

    /// <summary>
    /// Hybrid exposure with nothing curated for direct advertisement, which is Navigator.
    /// </summary>
    /// <remarks>
    /// Every operation carries navigator exposure, so the surface has a full catalogue behind
    /// it and publishes none of it. What a client sees is the degenerate case the exposure
    /// requirement names: the Navigator trio and nothing else.
    /// </remarks>
    public const string NavigatorOnly = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "authenticationRequired": false,
                "surfaces": [
                  {
                    "slug": "full",
                    "isDefault": true,
                    "navigator": { "enabled": true },
                    "operations": [
                      { "operation": "list-pets", "exposure": "navigator" },
                      { "operation": "add-pet", "exposure": "navigator" }
                    ]
                  }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": {
                "operations": [
                  { "key": "GET /pets", "method": "GET", "path": "/pets" },
                  { "key": "POST /pets", "method": "POST", "path": "/pets" }
                ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  { "slug": "list-pets", "name": "List pets", "binding": { "type": "http", "operation": "GET /pets" } },
                  { "slug": "add-pet", "name": "Add pet", "binding": { "type": "http", "operation": "POST /pets" } }
                ]
              }
            }
          }
        }
        """;

    /// <summary>
    /// A fully identified server: name, version, description, and one named surface of two.
    /// </summary>
    /// <remarks>
    /// The second surface is deliberately left unnamed so one document answers both halves of
    /// the title question - what a client is told when the Manifest authored a surface name,
    /// and what it is told when the surface has only the slug that is already in the address.
    /// </remarks>
    public const string Identified = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "authenticationRequired": false,
                "description": "Everything about pets.",
                "version": "3.1.4",
                "surfaces": [
                  { "slug": "read", "name": "Read only", "operations": [ { "operation": "list-pets" } ] },
                  { "slug": "full", "isDefault": true, "operations": [ { "operation": "list-pets" } ] }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": { "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ] }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  { "slug": "list-pets", "name": "List pets", "binding": { "type": "http", "operation": "GET /pets" } }
                ]
              }
            }
          }
        }
        """;

    /// <summary>A second server whose one tool name collides with the first's.</summary>
    public const string CollidingNames = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": {
              "inline": {
                "name": "Weather API",
                "authenticationRequired": false,
                "surfaces": [
                  { "slug": "full", "isDefault": true, "operations": [ { "operation": "list-pets" } ] }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://weather.example.com" } },
            "operations": {
              "inline": {
                "operations": [ { "key": "GET /forecast", "method": "GET", "path": "/forecast" } ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "list-pets",
                    "name": "List forecasts",
                    "binding": { "type": "http", "operation": "GET /forecast" }
                  }
                ]
              }
            }
          }
        }
        """;

    /// <summary>Two surfaces and no default, which no address could resolve.</summary>
    public const string NoDefaultSurface = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "authenticationRequired": false,
                "surfaces": [
                  { "slug": "read", "operations": [ { "operation": "list-pets" } ] },
                  { "slug": "write", "operations": [ { "operation": "list-pets" } ] }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": { "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ] }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  { "slug": "list-pets", "name": "List pets", "binding": { "type": "http", "operation": "GET /pets" } }
                ]
              }
            }
          }
        }
        """;

    /// <summary>Two surfaces both claiming the bare mount address.</summary>
    public const string TwoDefaultSurfaces = """
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "authenticationRequired": false,
                "surfaces": [
                  { "slug": "read", "isDefault": true, "operations": [ { "operation": "list-pets" } ] },
                  { "slug": "write", "isDefault": true, "operations": [ { "operation": "list-pets" } ] }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": { "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ] }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  { "slug": "list-pets", "name": "List pets", "binding": { "type": "http", "operation": "GET /pets" } }
                ]
              }
            }
          }
        }
        """;

    /// <summary>
    /// Two surfaces over one loopback upstream, for the tests that observe a real request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Built at call time because the port is chosen by the operating system, which no
    /// committed document can carry. <c>list-pets</c> declares a required argument so a
    /// refusal before any request is observable; <c>get-pet</c> puts one in the path so
    /// compilation is exercised rather than only query serialization.
    /// </para>
    /// <para>
    /// The exposure cases are all here so one document answers them: <c>hidden-pet</c> is
    /// reachable by nothing, <c>quiet-pet</c> only by the Navigator, and the <c>read</c>
    /// surface excludes <c>get-pet</c> while <c>full</c> serves it. The Navigator is enabled
    /// on <c>full</c> because a surface that declares navigator exposure with the Navigator
    /// off describes an operation nothing can ever reach, which is a different fixture.
    /// </para>
    /// </remarks>
    public static string Upstream(Uri address, int? concurrency = null)
    {
        ArgumentNullException.ThrowIfNull(address);

        string limits = concurrency is null
            ? string.Empty
            : ", \"limits\": { \"concurrency\": "
                + concurrency.Value.ToString(CultureInfo.InvariantCulture)
                + " }";

        return UpstreamTemplate
            .Replace("{BASE_URL}", address.AbsoluteUri, StringComparison.Ordinal)
            .Replace("{LIMITS}", limits, StringComparison.Ordinal);
    }

    private const string UpstreamTemplate = """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": {
                  "inline": {
                    "name": "Pet API",
                    "authenticationRequired": false,
                    "surfaces": [
                      {
                        "slug": "full",
                        "isDefault": true,
                        "navigator": { "enabled": true },
                        "operations": [
                          { "operation": "list-pets" },
                          { "operation": "get-pet" },
                          { "operation": "hidden-pet", "exposure": "hidden" },
                          { "operation": "quiet-pet", "exposure": "navigator" }
                        ]
                      },
                      {
                        "slug": "read",
                        "operations": [ { "operation": "list-pets" } ]
                      }
                    ]
                  }
                },
                "policy": { "inline": { "baseUrl": "{BASE_URL}"{LIMITS} } },
                "operations": {
                  "inline": {
                    "operations": [
                      {
                        "key": "GET /pets",
                        "method": "GET",
                        "path": "/pets",
                        "parameters": [ { "name": "status", "in": "query", "required": true, "schema": { "type": "string" } } ]
                      },
                      {
                        "key": "GET /pets/{petId}",
                        "method": "GET",
                        "path": "/pets/{petId}",
                        "parameters": [ { "name": "petId", "in": "path", "required": true, "schema": { "type": "string" } } ]
                      },
                      { "key": "DELETE /pets", "method": "DELETE", "path": "/pets" },
                      { "key": "GET /pets/quiet", "method": "GET", "path": "/pets/quiet" }
                    ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "list-pets",
                        "name": "List pets",
                        "summary": "Lists every pet.",
                        "inputSchema": {
                          "type": "object",
                          "required": ["status"],
                          "properties": { "status": { "type": "string" }, "limit": { "type": "integer" } }
                        },
                        "binding": { "type": "http", "operation": "GET /pets" }
                      },
                      {
                        "slug": "get-pet",
                        "name": "Get pet",
                        "inputSchema": {
                          "type": "object",
                          "required": ["petId"],
                          "properties": { "petId": { "type": "string" } }
                        },
                        "binding": { "type": "http", "operation": "GET /pets/{petId}" }
                      },
                      {
                        "slug": "hidden-pet",
                        "name": "Purge pets",
                        "binding": { "type": "http", "operation": "DELETE /pets" }
                      },
                      {
                        "slug": "quiet-pet",
                        "name": "Quiet pets",
                        "binding": { "type": "http", "operation": "GET /pets/quiet" }
                      }
                    ]
                  }
                }
              }
            }
            """;

    /// <summary>The operation slugs the derived lexical index carries, in its order.</summary>
    /// <remarks>
    /// Ordinal by slug, and every agent operation is here including the ones no surface
    /// exposes: the index documents what the Manifest describes, and a surface decides what
    /// it shows at the moment it is asked. A vector matrix has to line up with this list, not
    /// with any surface's.
    /// </remarks>
    public static IReadOnlyList<string> IndexedOperations { get; } =
        ["get-pet", "hidden-pet", "list-pets", "quiet-pet"];

    /// <summary>Writes <paramref name="manifest"/> into a fresh bundle directory.</summary>
    public static string Write(string root, string name, string manifest)
    {
        string directory = Path.Combine(root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), manifest);
        return directory;
    }

    /// <summary>Writes the bundle with an external <c>vectors</c> section carrying these bytes.</summary>
    /// <param name="dimension">
    /// The dimension the section index declares, which is a second statement of what the
    /// matrix header says. Omitted when the test is about the header alone.
    /// </param>
    public static string Write(string root, string name, string manifest, byte[] vectors, int? dimension = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(vectors);

        const string Anchor = "\"sections\": {";
        string declared = dimension is { } value
            ? string.Create(CultureInfo.InvariantCulture, $"\"vectors\": {{ \"path\": \"{PayloadFile}\", \"dimension\": {value} }},")
            : $"\"vectors\": {{ \"path\": \"{PayloadFile}\" }},";

        Assert.Equal(1, Occurrences(manifest, Anchor));

        string directory = Write(root, name, manifest.Replace(Anchor, Anchor + "\n" + declared, StringComparison.Ordinal));
        File.WriteAllBytes(Path.Combine(directory, PayloadFile), vectors);
        return directory;
    }

    private const string PayloadFile = "vectors.bin";

    private static int Occurrences(string text, string value)
    {
        int found = 0;

        for (int index = text.IndexOf(value, StringComparison.Ordinal); index >= 0;
             index = text.IndexOf(value, index + value.Length, StringComparison.Ordinal))
        {
            found++;
        }

        return found;
    }
}
