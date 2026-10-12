using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>The host's operator-facing liveness and readiness endpoints.</summary>
internal static class HealthEndpoints
{
    internal const string ReadyPath = "/health/ready";
    internal const string LivePath = "/health/live";

    /// <summary>
    /// The managed-only health surface (owner decision R16-A): it reports 503 while the managed confirmation
    /// journal is integrity-failed and 200 otherwise, so an orchestrator can alert on the stalled managed
    /// recovery without taking a functional Engine out of traffic. <see cref="ReadyPath"/> and
    /// <see cref="LivePath"/> are deliberately unaffected.
    /// </summary>
    internal const string ManagedPath = "/health/managed";

    /// <summary>Maps health onto the serving listener after atomic startup has succeeded.</summary>
    /// <param name="app">The serving application.</param>
    /// <param name="fileStoreRoot">The file store root readiness validates.</param>
    /// <param name="drain">The drain coordinator readiness observes.</param>
    /// <param name="managedJournalDegraded">
    /// A read-only probe answering whether the managed confirmation journal is currently integrity-failed.
    /// Null in file mode, where managed synchronization is not configured (R16.7).
    /// </param>
    internal static void Map(
        WebApplication app,
        string fileStoreRoot,
        DrainCoordinator drain,
        Func<bool>? managedJournalDegraded = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentException.ThrowIfNullOrEmpty(fileStoreRoot);
        ArgumentNullException.ThrowIfNull(drain);

        app.MapGet(LivePath, static () => Results.Text("alive\n", statusCode: StatusCodes.Status200OK));

        app.MapGet(ReadyPath, () => Ready(fileStoreRoot, drain));

        app.MapGet(ManagedPath, () => Managed(managedJournalDegraded));
    }

    /// <summary>Whether a path remains observable while ordinary request admission is closed.</summary>
    internal static bool IsHealthPath(PathString path)
        => path.Equals(ReadyPath) || path.Equals(LivePath) || path.Equals(ManagedPath);

    /// <summary>
    /// Reports the managed confirmation journal's integrity. A null probe means file mode, where managed
    /// synchronization is not configured and the surface is healthy. The bodies are fixed text and name
    /// neither the journal path nor any slot/secret material (R16.7).
    /// </summary>
    private static IResult Managed(Func<bool>? managedJournalDegraded)
    {
        if (managedJournalDegraded is null)
        {
            return Results.Text(
                "ok: managed synchronization is not configured\n",
                statusCode: StatusCodes.Status200OK);
        }

        if (managedJournalDegraded())
        {
            return Results.Text(
                "degraded: the managed confirmation journal failed its integrity check; managed reconciliation "
                + "is stalled until an operator runs 'confirmed-revisions reset'\n",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        return Results.Text("ok\n", statusCode: StatusCodes.Status200OK);
    }

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
