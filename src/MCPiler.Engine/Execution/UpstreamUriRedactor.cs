namespace MCPiler.Engine.Execution;

/// <summary>Redacts declared sensitive query values from diagnostic URIs.</summary>
internal static class UpstreamUriRedactor
{
    private const string RedactedValue = "%5BREDACTED%5D";

    public static Uri Redact(Uri uri, IReadOnlyCollection<string> sensitiveNames)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(sensitiveNames);

        if (uri.Query.Length <= 1 || sensitiveNames.Count == 0)
        {
            return uri;
        }

        var names = new HashSet<string>(sensitiveNames, StringComparer.OrdinalIgnoreCase);
        string[] parts = uri.Query[1..].Split('&');
        for (int index = 0; index < parts.Length; index++)
        {
            int separator = parts[index].IndexOf('=');
            string encodedName = separator < 0 ? parts[index] : parts[index][..separator];
            string name = Uri.UnescapeDataString(encodedName.Replace('+', ' '));
            if (names.Contains(name))
            {
                parts[index] = encodedName + "=" + RedactedValue;
            }
        }

        return new UriBuilder(uri) { Query = string.Join('&', parts) }.Uri;
    }
}
