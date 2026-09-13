using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>The host's operator-facing liveness and readiness endpoints.</summary>
internal static class HealthEndpoints
{
    internal const string ReadyPath = "/health/ready";
    internal const string LivePath = "/health/live";

    /// <summary>Maps health onto the serving listener after atomic startup has succeeded.</summary>
    internal static void Map(
        WebApplication app,
        string fileStoreRoot,
        DrainCoordinator drain)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentException.ThrowIfNullOrEmpty(fileStoreRoot);
        ArgumentNullException.ThrowIfNull(drain);

        app.MapGet(LivePath, static () => Results.Text("alive\n", statusCode: StatusCodes.Status200OK));

        app.MapGet(ReadyPath, () => Ready(fileStoreRoot, drain));
    }

    /// <summary>Whether a path remains observable while ordinary request admission is closed.</summary>
    internal static bool IsHealthPath(PathString path)
        => path.Equals(ReadyPath) || path.Equals(LivePath);

    private static IResult Ready(string fileStoreRoot, DrainCoordinator drain)
    {
        if (drain.IsDraining)
        {
            return Results.Text(
                "not ready: shutdown drain is in progress\n",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        if (FileStoreInspection.Open(fileStoreRoot, out StartupRefusal? refusal) is null)
        {
            return Results.Text(
                "not ready: " + refusal!.Message + "\n",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        return Results.Text("ready\n", statusCode: StatusCodes.Status200OK);
    }
}
