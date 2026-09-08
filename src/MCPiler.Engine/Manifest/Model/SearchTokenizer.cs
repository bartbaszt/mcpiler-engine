using System.Text;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The deterministic, culture-invariant tokenizer used for both indexing and querying.
/// </summary>
/// <remarks>
/// <para>
/// Tokens are maximal runs of ASCII letters and digits, lower-cased with the invariant
/// culture and deduplicated in first-seen order. Indexing and querying must use the same
/// function: if they diverged, a term present in the index could be unreachable by the query
/// that produced it, which reads as a relevance bug rather than a tokenizer bug.
/// </para>
/// <para>
/// Culture invariance is deliberate. A culture-sensitive lower-casing would make the same
/// manifest index differently depending on the host locale, and a manifest is supposed to be
/// portable.
/// </para>
/// </remarks>
public static class SearchTokenizer
{
    /// <summary>Maximum length of a single token. Longer runs are dropped, not truncated.</summary>
    public const int MaxTokenLength = SearchScoring.MaxTokenLength;

    /// <summary>Maximum number of input characters examined.</summary>
    public const int MaxInputLength = SearchScoring.MaxInputLength;

    /// <summary>Tokenizes text into distinct terms in first-seen order.</summary>
    /// <param name="text">The text to tokenize. Null and empty yield no tokens.</param>
    public static List<string> Tokenize(string? text)
    {
        var tokens = new List<string>();

        if (string.IsNullOrEmpty(text))
        {
            return tokens;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var builder = new StringBuilder();

        foreach (var character in text.AsSpan(0, Math.Min(text.Length, MaxInputLength)))
        {
            if (char.IsAsciiLetterOrDigit(character))
            {
                builder.Append(char.ToLowerInvariant(character));
                continue;
            }

            Flush(tokens, seen, builder);
        }

        Flush(tokens, seen, builder);

        return tokens;
    }

    /// <remarks>
    /// An over-long run is discarded rather than cut to the limit: a truncated token is a
    /// term nobody wrote, and it would match queries for a prefix that does not exist in the
    /// source text.
    /// </remarks>
    private static void Flush(List<string> tokens, HashSet<string> seen, StringBuilder builder)
    {
        if (builder.Length == 0 || builder.Length > MaxTokenLength)
        {
            builder.Clear();
            return;
        }

        var token = builder.ToString();
        builder.Clear();

        if (seen.Add(token))
        {
            tokens.Add(token);
        }
    }
}
