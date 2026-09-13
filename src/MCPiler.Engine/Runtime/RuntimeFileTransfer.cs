namespace MCPiler.Engine.Runtime;

/// <summary>The result of admitting one transfer upload.</summary>
public sealed record RuntimeFileUploadResult
{
    private RuntimeFileUploadResult(
        bool succeeded,
        string? capability,
        string? fileName,
        string? mediaType,
        long? length,
        string? failureReason)
    {
        Succeeded = succeeded;
        Capability = capability;
        FileName = fileName;
        MediaType = mediaType;
        Length = length;
        FailureReason = failureReason;
    }

    public bool Succeeded { get; }

    public string? Capability { get; }

    public string? FileName { get; }

    public string? MediaType { get; }

    public long? Length { get; }

    public string? FailureReason { get; }

    internal static RuntimeFileUploadResult Issued(
        string capability,
        string fileName,
        string mediaType,
        long length)
        => new(true, capability, fileName, mediaType, length, null);

    internal static RuntimeFileUploadResult Refused(string reason)
        => new(false, null, null, null, null, reason);
}

/// <summary>Why one transfer download did not produce content.</summary>
public enum RuntimeFileDownloadStatus
{
    Available,
    Unknown,
    Expired,
}

/// <summary>
/// One authorized transfer download. The caller owns this value and therefore the opened stream.
/// </summary>
public sealed class RuntimeFileDownload : IAsyncDisposable
{
    private RuntimeFileDownload(
        RuntimeFileDownloadStatus status,
        string? fileName,
        string? mediaType,
        long? length,
        Stream? content)
    {
        Status = status;
        FileName = fileName;
        MediaType = mediaType;
        Length = length;
        Content = content;
    }

    public RuntimeFileDownloadStatus Status { get; }

    public string? FileName { get; }

    public string? MediaType { get; }

    public long? Length { get; }

    public Stream? Content { get; }

    internal static RuntimeFileDownload Available(
        string fileName,
        string mediaType,
        long length,
        Stream content)
        => new(RuntimeFileDownloadStatus.Available, fileName, mediaType, length, content);

    internal static RuntimeFileDownload Unknown()
        => new(RuntimeFileDownloadStatus.Unknown, null, null, null, null);

    internal static RuntimeFileDownload Expired()
        => new(RuntimeFileDownloadStatus.Expired, null, null, null, null);

    public async ValueTask DisposeAsync()
    {
        if (Content is not null)
        {
            await Content.DisposeAsync().ConfigureAwait(false);
        }
    }
}
