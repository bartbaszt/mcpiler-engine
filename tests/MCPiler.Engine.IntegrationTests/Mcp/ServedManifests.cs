using System.IO;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// Manifests written to disk for the wire tests.
/// </summary>
/// <remarks>
/// Written as JSON text rather than assembled from the model, so what the tests serve is what
/// the readers accept. A fixture built by calling the model's constructors would skip the
/// readers entirely and could describe a document no operator could author.
/// </remarks>
internal static class ServedManifests
{
    /// <summary>One surface, one operation, one declared input schema.</summary>
    public const string OneSurface = """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
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

    /// <summary>Three surfaces over one operation set, the middle one default.</summary>
    public const string ThreeSurfaces = """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
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
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
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

    /// <summary>A second server whose one tool name collides with the first's.</summary>
    public const string CollidingNames = """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Weather API",
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
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
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
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
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
    public static string Upstream(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);

        return UpstreamTemplate.Replace("{BASE_URL}", address.AbsoluteUri, StringComparison.Ordinal);
    }

    private const string UpstreamTemplate = """
            {
              "manifestFormatVersion": "0.2",
              "sections": {
                "server": {
                  "inline": {
                    "name": "Pet API",
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
                "policy": { "inline": { "baseUrl": "{BASE_URL}" } },
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

    /// <summary>Writes <paramref name="manifest"/> into a fresh bundle directory.</summary>
    public static string Write(string root, string name, string manifest)
    {
        string directory = Path.Combine(root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), manifest);
        return directory;
    }
}
