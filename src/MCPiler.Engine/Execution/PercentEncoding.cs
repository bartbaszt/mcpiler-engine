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

        foreach (var ch in value)
        {
            if (ch < 128 && (IsUnreserved[ch] || (allowReserved && Reserved.Contains(ch, StringComparison.Ordinal))))
            {
                sb.Append(ch);
            }
            else
            {
                foreach (var b in Encoding.UTF8.GetBytes(ch.ToString()))
                {
                    sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
                }
            }
        }

        return sb.ToString();
    }
}
