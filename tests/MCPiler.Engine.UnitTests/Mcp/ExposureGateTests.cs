using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>
/// The exposure table, read the way an invocation reads it.
/// </summary>
/// <remarks>
/// Stated as a closed table rather than as the cases that happen to be reachable today. The
/// direct path cannot currently present an excluded operation, because the advertised listing
/// is derived from the same exposure the gate reads and a Manifest whose declared listing
/// disagrees is refused at startup. The Navigator arrives with no listing behind it at all, so
/// every cell here becomes reachable the moment it exists, and a cell first exercised then would
/// be a cell first specified then.
/// </remarks>
public sealed class ExposureGateTests
{
    [Theory]
    [InlineData(OperationExposure.Direct, InvocationPath.Direct, true)]
    [InlineData(OperationExposure.Direct, InvocationPath.Navigator, true)]
    [InlineData(OperationExposure.Navigator, InvocationPath.Direct, false)]
    [InlineData(OperationExposure.Navigator, InvocationPath.Navigator, true)]
    [InlineData(OperationExposure.Hidden, InvocationPath.Direct, false)]
    [InlineData(OperationExposure.Hidden, InvocationPath.Navigator, false)]
    internal void Exposure_and_the_way_in_decide_together(
        OperationExposure exposure,
        InvocationPath path,
        bool permitted)
    {
        var surface = new ManifestSurface("full", [new SurfaceOperation("list-pets", exposure)]);

        Assert.Equal(permitted, ExposureGate.Permits(surface, "list-pets", path));
    }

    [Theory]
    [InlineData(InvocationPath.Direct)]
    [InlineData(InvocationPath.Navigator)]
    internal void An_operation_the_surface_does_not_list_is_refused(InvocationPath path)
    {
        var surface = new ManifestSurface("full", [new SurfaceOperation("list-pets", OperationExposure.Direct)]);

        // Not "hidden" and not "navigator". The surface simply has nothing to say about it,
        // and a table consulted for an absent key must answer no rather than nothing.
        Assert.False(ExposureGate.Permits(surface, "add-pet", path));
    }

    [Fact]
    public void The_same_operation_is_decided_per_surface()
    {
        var open = new ManifestSurface("full", [new SurfaceOperation("add-pet", OperationExposure.Direct)]);
        var closed = new ManifestSurface("read", [new SurfaceOperation("add-pet", OperationExposure.Hidden)]);

        Assert.True(ExposureGate.Permits(open, "add-pet", InvocationPath.Direct));
        Assert.False(ExposureGate.Permits(closed, "add-pet", InvocationPath.Direct));
    }

    [Fact]
    public void A_mounted_surface_is_decided_against_the_declaration_it_was_built_from()
    {
        ManifestDocument manifest = Load(TwoSurfaces);
        MountedManifest mount = Mount(manifest, "read");

        Assert.True(ExposureGate.Permits(mount, mount.Surfaces[0], "list-pets", InvocationPath.Direct));
        Assert.False(ExposureGate.Permits(mount, mount.Surfaces[0], "add-pet", InvocationPath.Direct));
    }

    [Theory]
    [InlineData(InvocationPath.Direct)]
    [InlineData(InvocationPath.Navigator)]
    internal void A_mounted_surface_with_no_declaration_behind_it_permits_nothing(InvocationPath path)
    {
        ManifestDocument manifest = Load(TwoSurfaces);
        MountedManifest mount = Mount(manifest, "invented");

        // The projection and the document disagreeing about which surfaces exist is not a
        // state this build can produce. It is the state the gate has to survive anyway,
        // because the alternative to refusing an unresolvable surface is running on one.
        Assert.False(ExposureGate.Permits(mount, mount.Surfaces[0], "list-pets", path));
    }

    private static MountedManifest Mount(ManifestDocument manifest, string surfaceSlug)
        => new(
            "/api",
            "bundle",
            manifest,
            manifest.Policy,
            [new MountedSurface(surfaceSlug, surfaceSlug, IsDefault: true, [], [], "fingerprint")]);

    private static ManifestDocument Load(string manifestText)
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(manifestText));
        Assert.True(result.Succeeded);
        return result.Manifest!;
    }

    private const string TwoSurfaces = """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "surfaces": [
                  { "slug": "read", "isDefault": true, "operations": [ { "operation": "list-pets" } ] },
                  {
                    "slug": "full",
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
                  { "slug": "list-pets", "name": "List pets", "binding": { "type": "http", "operation": "GET /pets" } },
                  { "slug": "add-pet", "name": "Add pet", "binding": { "type": "http", "operation": "POST /pets" } }
                ]
              }
            }
          }
        }
        """;
}
