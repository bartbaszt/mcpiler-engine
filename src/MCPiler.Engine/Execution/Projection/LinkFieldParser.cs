using System.Text;

namespace MCPiler.Engine.Execution.Projection;

/// <summary>
/// One parsed link-value of an RFC 8288 <c>Link</c> field.
/// </summary>
/// <param name="Target">The URI reference exactly as it appeared between angle brackets.</param>
/// <param name="Relations">The relation types named by <c>rel</c>, lower-cased, in order.</param>
/// <param name="Anchor">The raw <c>anchor</c> parameter, when one was present.</param>
internal sealed record ParsedLinkValue(string Target, IReadOnlyList<string> Relations, string? Anchor);

/// <summary>How one configured Link field parsed.</summary>
internal enum LinkParseOutcome
{
    /// <summary>Every value was consumed under the ceiling.</summary>
    Parsed,

    /// <summary>The field did not follow the link grammar.</summary>
    Malformed,

    /// <summary>The field carried more link-values than the policy ceiling allows.</summary>
    OverLimit,
}

/// <summary>The outcome of parsing every value of a configured Link field.</summary>
/// <param name="Values">The parsed link-values when parsing succeeded.</param>
/// <param name="Outcome">Whether the field parsed, was malformed, or breached the ceiling.</param>
internal sealed record LinkParseResult(IReadOnlyList<ParsedLinkValue> Values, LinkParseOutcome Outcome)
{
    internal static LinkParseResult MalformedField { get; } = new([], LinkParseOutcome.Malformed);

    internal static LinkParseResult OverLimit { get; } = new([], LinkParseOutcome.OverLimit);
}

/// <summary>
/// A bounded, standards-compatible parser for RFC 8288 <c>Link</c> field values.
/// </summary>
/// <remarks>
/// <para>
/// The grammar is consumed rather than approximated. Splitting on commas corrupts a quoted
/// parameter that contains one and splitting on semicolons corrupts an extension relation URI
/// that contains one, so this parser walks the field once, tracking whether it is inside a
/// quoted string and honouring backslash escapes inside one.
/// </para>
/// <para>
/// It is deliberately total: anything it cannot recognize is reported as malformed rather than
/// guessed at, because the caller's alternative to "this is not a Link field I understand" is a
/// fallback split, and a fallback split is the defect this parser exists to prevent.
/// </para>
/// <para>
/// The parser consumes the field it is given and enforces the parsed-value count ceiling, so an
/// adversarial field cannot make an unbounded number of link-values reachable. It performs no
/// resolution and no policy: a resolved target is resolved by the caller against the effective
/// response URI, and whether a relation is usable is the caller's decision.
/// </para>
/// </remarks>
internal static class LinkFieldParser
{
    /// <summary>Parses every field value of one configured Link header.</summary>
    internal static LinkParseResult Parse(IReadOnlyList<string> fieldValues)
    {
        ArgumentNullException.ThrowIfNull(fieldValues);

        var values = new List<ParsedLinkValue>();
        var count = 0;

        foreach (string fieldValue in fieldValues)
        {
            var cursor = new Cursor(fieldValue);

            while (true)
            {
                cursor.SkipWhitespaceAndCommas();

                if (cursor.AtEnd)
                {
                    break;
                }

                if (count == ResponseProjectionLimits.MaxLinkValues)
                {
                    // Over the ceiling is a refusal rather than a truncation: a partial list
                    // could hide the very candidate a duplicate check exists to notice.
                    return LinkParseResult.OverLimit;
                }

                if (ParseValue(cursor) is not { } parsed)
                {
                    return LinkParseResult.MalformedField;
                }

                values.Add(parsed);
                count++;
            }
        }

        return new LinkParseResult(values, LinkParseOutcome.Parsed);
    }

    /// <summary>Parses one <c>&lt;target&gt; *( ";" parameter )</c> production.</summary>
    private static ParsedLinkValue? ParseValue(Cursor cursor)
    {
        if (!cursor.TryReadDelimited('<', '>', out string target) || target.Length == 0)
        {
            return null;
        }

        if (cursor.TryPeekOutsideQuotes() is not (null or ';' or ','))
        {
            // Anything other than a parameter list or the next link-value is not this grammar.
            return null;
        }

        List<string> relations = [];
        string? anchor = null;

        while (true)
        {
            cursor.SkipWhitespace();

            if (cursor.AtEnd || cursor.Peek is ',')
            {
                break;
            }

            if (cursor.Peek != ';')
            {
                return null;
            }

            cursor.Advance();

            // Whitespace around the parameter separator is legal and common, so the token
            // reader is entered only after the insignificant space is consumed.
            cursor.SkipWhitespace();

            if (!cursor.TryReadToken(out string name))
            {
                return null;
            }

            string? value = null;
            cursor.SkipWhitespace();

            if (cursor.Peek is '=')
            {
                cursor.Advance();
                cursor.SkipWhitespace();

                value = cursor.Peek is '"' ? cursor.ReadQuotedValue() : cursor.ReadTokenValue();

                if (value is null)
                {
                    return null;
                }
            }

            switch (name.ToLowerInvariant())
            {
                case "rel":
                    if (value is null)
                    {
                        return null;
                    }

                    foreach (string relation in value.Split(
                        ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        relations.Add(relation.ToLowerInvariant());
                    }

                    break;

                case "anchor":
                    anchor = value;
                    break;

                default:
                    break;
            }
        }

        return relations.Count == 0 ? null : new ParsedLinkValue(target, relations, anchor);
    }

    /// <summary>A position in one field value, with quote awareness.</summary>
    private sealed class Cursor(string text)
    {
        private int _index;

        internal bool AtEnd => _index >= text.Length;

        internal char? Peek => AtEnd ? null : text[_index];

        internal void Advance() => _index++;

        internal void SkipWhitespace()
        {
            while (!AtEnd && (Peek is ' ' or '\t'))
            {
                _index++;
            }
        }

        internal void SkipWhitespaceAndCommas()
        {
            while (!AtEnd && (Peek is ' ' or '\t' or ','))
            {
                _index++;
            }
        }

        /// <summary>The next character that is not inside a quoted string, or null at the end.</summary>
        internal char? TryPeekOutsideQuotes()
        {
            for (var probe = _index; probe < text.Length; probe++)
            {
                if (text[probe] is not (' ' or '\t'))
                {
                    return text[probe];
                }
            }

            return null;
        }

        internal bool TryReadDelimited(char open, char close, out string content)
        {
            content = string.Empty;

            if (Peek != open)
            {
                return false;
            }

            var start = ++_index;

            while (!AtEnd && Peek != close)
            {
                _index++;
            }

            if (AtEnd)
            {
                return false;
            }

            content = text[start.._index];
            _index++;
            return true;
        }

        internal bool TryReadToken(out string token)
        {
            token = string.Empty;

            var start = _index;

            while (!AtEnd && Peek is not (' ' or '\t' or '=' or ';' or ','))
            {
                _index++;
            }

            token = text[start.._index];
            return token.Length > 0;
        }

        /// <summary>Reads a quoted string, honouring backslash escapes, without the quotes.</summary>
        internal string? ReadQuotedValue()
        {
            if (Peek != '"')
            {
                return null;
            }

            _index++;
            var builder = new StringBuilder();

            while (!AtEnd)
            {
                char current = text[_index++];

                if (current == '\\')
                {
                    if (AtEnd)
                    {
                        return null;
                    }

                    builder.Append(text[_index++]);
                    continue;
                }

                if (current == '"')
                {
                    return builder.ToString();
                }

                builder.Append(current);
            }

            return null;
        }

        /// <summary>Reads an unquoted parameter value.</summary>
        internal string? ReadTokenValue()
        {
            var start = _index;

            while (!AtEnd && Peek is not (' ' or '\t' or ';' or ','))
            {
                _index++;
            }

            return start == _index ? null : text[start.._index];
        }
    }
}
