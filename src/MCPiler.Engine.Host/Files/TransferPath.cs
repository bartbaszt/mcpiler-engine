namespace MCPiler.Engine.Host.Files;

/// <summary>Which transfer child a request path addresses.</summary>
internal enum TransferPathKind
{
    /// <summary>An upload to the parent MCP surface.</summary>
    Upload,

    /// <summary>A download of one capability issued by the parent MCP surface.</summary>
    Download,
}

/// <summary>
/// Parses a request path as a transfer child of an MCP surface.
/// </summary>
/// <remarks>
/// <para>
/// A managed listener maps one template because an activation may introduce a mount the process
/// has never seen. That template necessarily also matches the transfer children, and a catch-all
/// route may not carry a literal suffix, so the children cannot be mapped as their own routes.
/// They are recognised from the path instead, before the protocol handler would see them.
/// </para>
/// <para>
/// A transfer child is not a protected resource of its own: it inherits the parent surface's
/// resource identity, which is why the parse yields the parent address rather than the whole path.
/// </para>
/// </remarks>
/// <param name="ParentAddress">The MCP surface address the child belongs to.</param>
/// <param name="Kind">Whether the path addresses an upload or a download.</param>
/// <param name="Capability">The download capability, when the kind is a download.</param>
internal readonly record struct TransferPath(
    string ParentAddress,
    TransferPathKind Kind,
    string? Capability)
{
    internal const string UploadSuffix = "/files/upload";
    internal const string FilesSegment = "/files/";

    /// <summary>Recognises a transfer child path, or reports that the path is not one.</summary>
    internal static bool TryParse(string? path, out TransferPath parsed)
    {
        parsed = default;

        if (string.IsNullOrEmpty(path) || path[0] != '/')
        {
            return false;
        }

        // The upload suffix wins over the download shape: "upload" is a capability name a client
        // could otherwise be invited to guess, and a route that treated it as one would turn the
        // upload endpoint into a download of whatever happened to be named "upload".
        if (path.EndsWith(UploadSuffix, StringComparison.Ordinal))
        {
            string parent = path[..^UploadSuffix.Length];

            if (parent.Length == 0)
            {
                return false;
            }

            parsed = new TransferPath(parent, TransferPathKind.Upload, Capability: null);
            return true;
        }

        int marker = path.LastIndexOf(FilesSegment, StringComparison.Ordinal);

        if (marker <= 0)
        {
            return false;
        }

        string candidate = path[(marker + FilesSegment.Length)..];

        // A capability is one path segment. Anything longer is a deeper path that merely happens
        // to contain a "files" segment, and treating it as a download would invent a route.
        if (candidate.Length == 0 || candidate.Contains('/', StringComparison.Ordinal))
        {
            return false;
        }

        parsed = new TransferPath(
            path[..marker],
            TransferPathKind.Download,
            candidate);

        return true;
    }
}
