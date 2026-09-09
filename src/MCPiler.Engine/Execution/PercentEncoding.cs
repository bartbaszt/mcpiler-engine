using System.Globalization;
using System.Text;

namespace MCPiler.Engine.Execution;

/// <summary>
/// RFC 3986 percent-encoding with the reserved-character allowance a parameter may request.
/// Unreserved = A-Za-z0-9-._~. Reserved = :/?#[]@!$&amp;'()*+,;= and is preserved only when the
/// parameter declares <c>allowReserved</c>.
/// </summary>
/// <remarks>
/// A character outside the unreserved set is encoded per UTF-8 byte, so a non-ASCII value expands to
/// one triplet per byte rather than one per character. The hexadecimal digits are upper case and
/// culture-invariant, because the output is compared byte-for-byte against a recorded request.
///
/// Iteration is over runes, not UTF-16 code units. A character above the basic multilingual plane is
/// stored as a surrogate pair, and encoding each half on its own hands the UTF-8 encoder an unpaired
/// surrogate, which it substitutes with U+FFFD. That silently replaced the caller's character with a
/// replacement marker instead of encoding it, and the corruption was unrecoverable because it happened
/// before the bytes were emitted.
/// </remarks>
public static class PercentEncoding
{
    private static readonly bool[] IsUnreserved = BuildTable();

    private const string Reserved = ":/?#[]@!$&'()*+,;=";

    private static bool[] BuildTable()
    {
        var table = new bool[128];
        for (var c = 'a'; c <= 'z'; c++) table[c] = true;
        for (var c = 'A'; c <= 'Z'; c++) table[c] = true;
        for (var c = '0'; c <= '9'; c++) table[c] = true;
        table['-'] = table['.'] = table['_'] = table['~'] = true;
        return table;
    }

    /// <summary>Encodes a single value for placement in a URL, header, or cookie.</summary>
    public static string Encode(string value, bool allowReserved)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(value.Length + 16);
        Span<byte> utf8 = stackalloc byte[4];

        foreach (var rune in value.EnumerateRunes())
        {
            if (rune.IsAscii && (IsUnreserved[rune.Value] || (allowReserved && Reserved.Contains((char)rune.Value, StringComparison.Ordinal))))
            {
                sb.Append((char)rune.Value);
                continue;
            }

            var written = rune.EncodeToUtf8(utf8);
            for (var i = 0; i < written; i++)
            {
                sb.Append('%').Append(utf8[i].ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return sb.ToString();
    }
}
