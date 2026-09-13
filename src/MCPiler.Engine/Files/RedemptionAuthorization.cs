using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;

namespace MCPiler.Engine.Files;

/// <summary>Why one presented capability could not be redeemed.</summary>
public enum FileRedemptionRefusalKind
{
    /// <summary>No capability is available to this invocation under the presented value.</summary>
    Unknown,

    /// <summary>The capability belonged to this scope and its lifetime has passed.</summary>
    Expired,
}

/// <summary>The outcome of presenting a file capability for redemption.</summary>
public sealed class FileRedemption
{
    private FileRedemption(FileHandleReference? reference, ExecutionFile? file, FileRedemptionRefusalKind? refusal)
    {
        Reference = reference;
        File = file;
        Refusal = refusal;
    }

    /// <summary>The internal file reference, present only when redemption succeeded.</summary>
    public FileHandleReference? Reference { get; }

    /// <summary>The replayable file value, present only when redemption succeeded.</summary>
    public ExecutionFile? File { get; }

    /// <summary>Why redemption was refused, present only when it was.</summary>
    public FileRedemptionRefusalKind? Refusal { get; }

    public bool Succeeded => Reference is not null;

    public static FileRedemption Redeemed(FileHandleReference reference, ExecutionFile file)
        => new(reference, file, null);

    public static FileRedemption Refused(FileRedemptionRefusalKind kind)
        => new(null, null, kind);
}

/// <summary>
/// Authorizes every redemption against the invocation presenting the capability.
/// </summary>
/// <remarks>
/// Metadata is resolved first. Content is opened only after the stored scope matches the
/// presenting invocation, so a cross-scope probe neither obtains bytes nor leaves a stream open.
/// Unknown and cross-scope values deliberately share one result; expiry remains distinct only
/// for a capability whose scope matches the caller.
/// </remarks>
public static class RedemptionAuthorization
{
    /// <summary>The diagnostic for an unavailable capability. It never echoes the presented value.</summary>
    public const string UnknownMessage = "No file handle is available under that reference.";

    public static async Task<FileRedemption> RedeemAsync(
        FileHandleStore store,
        string wire,
        string scope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrEmpty(scope);

        FileHandleLookup described = await store
            .TryResolveWire(wire, cancellationToken)
            .ConfigureAwait(false);

        if (described.Status == FileHandleStatus.NotFound
            || described.Reference is not { } reference
            || !string.Equals(reference.Scope, scope, StringComparison.Ordinal))
        {
            return FileRedemption.Refused(FileRedemptionRefusalKind.Unknown);
        }

        if (described.Status == FileHandleStatus.Expired)
        {
            return FileRedemption.Refused(FileRedemptionRefusalKind.Expired);
        }

        // The authorization decision deliberately does not open the content. The replayable
        // source opens it only while an outbound request is being serialized, and opens it again
        // for a body-preserving redirect. A cross-scope probe therefore never touches payload
        // bytes at all.
        return FileRedemption.Redeemed(
            reference,
            new ExecutionFile(
                wire,
                reference.FileName,
                reference.MediaType,
                reference.Length,
                new StoreBackedBodySource(store, reference)));
    }
}
