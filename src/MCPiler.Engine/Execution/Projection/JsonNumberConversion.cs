using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.Execution.Projection;

internal static class JsonNumberConversion
{
    private const int ExponentCap = 1_000_000;

    public static bool TryGetLexeme(JsonValue value, out string lexeme)
    {
        lexeme = string.Empty;
        if (value.GetValueKind() != JsonValueKind.Number)
        {
            return false;
        }

        try
        {
            lexeme = value.ToJsonString();
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        return IsValid(lexeme);
    }

    public static JsonNode? ParseNumber(string lexeme)
    {
        if (!IsValid(lexeme))
        {
            return null;
        }

        try
        {
            return JsonNode.Parse(lexeme);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static JsonNode? ParseInteger(string lexeme)
        => TryParseInt64(lexeme, out var value) ? JsonValue.Create(value) : null;

    private static bool TryParseInt64(string lexeme, out long result)
    {
        result = 0;
        if (!TryDecompose(lexeme, out var negative, out var digits, out var scale))
        {
            return false;
        }

        var firstNonZero = 0;
        while (firstNonZero < digits.Length && digits[firstNonZero] == '0')
        {
            firstNonZero++;
        }

        if (firstNonZero == digits.Length)
        {
            return true;
        }

        digits = digits[firstNonZero..];
        if (scale > 0)
        {
            if (scale >= digits.Length)
            {
                return false;
            }

            var trailingZeros = 0;
            while (trailingZeros < scale && digits[digits.Length - 1 - trailingZeros] == '0')
            {
                trailingZeros++;
            }

            if (trailingZeros < scale)
            {
                return false;
            }

            digits = digits[..(digits.Length - scale)];
        }
        else
        {
            var expansion = -scale;
            if (digits.Length + expansion > 19)
            {
                return false;
            }

            digits += new string('0', expansion);
        }

        if (digits.Length > 19)
        {
            return false;
        }

        return long.TryParse(
            negative ? "-" + digits : digits,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out result);
    }

    private static bool TryDecompose(
        string lexeme,
        out bool negative,
        out string digits,
        out int scale)
    {
        negative = false;
        digits = string.Empty;
        scale = 0;
        if (!IsValid(lexeme))
        {
            return false;
        }

        var index = 0;
        if (lexeme[index] == '-')
        {
            negative = true;
            index++;
        }

        var integerStart = index;
        while (index < lexeme.Length && lexeme[index] != '.' && lexeme[index] != 'e' && lexeme[index] != 'E')
        {
            index++;
        }

        var integerPart = lexeme[integerStart..index];
        var fractionPart = string.Empty;
        if (index < lexeme.Length && lexeme[index] == '.')
        {
            index++;
            var fractionStart = index;
            while (index < lexeme.Length && lexeme[index] != 'e' && lexeme[index] != 'E')
            {
                index++;
            }
            fractionPart = lexeme[fractionStart..index];
        }

        var exponent = 0;
        if (index < lexeme.Length)
        {
            index++;
            var exponentNegative = false;
            if (index < lexeme.Length && (lexeme[index] == '+' || lexeme[index] == '-'))
            {
                exponentNegative = lexeme[index] == '-';
                index++;
            }

            while (index < lexeme.Length)
            {
                if (exponent < ExponentCap)
                {
                    exponent = Math.Min(ExponentCap, exponent * 10 + lexeme[index] - '0');
                }
                index++;
            }

            if (exponentNegative)
            {
                exponent = -exponent;
            }
        }

        digits = integerPart + fractionPart;
        scale = fractionPart.Length - exponent;
        return true;
    }

    private static bool IsValid(string lexeme)
    {
        if (lexeme.Length == 0)
        {
            return false;
        }

        var index = 0;
        if (lexeme[index] == '-')
        {
            index++;
        }

        if (index >= lexeme.Length)
        {
            return false;
        }

        if (lexeme[index] == '0')
        {
            index++;
            if (index < lexeme.Length && char.IsAsciiDigit(lexeme[index]))
            {
                return false;
            }
        }
        else
        {
            if (lexeme[index] is < '1' or > '9')
            {
                return false;
            }

            while (index < lexeme.Length && char.IsAsciiDigit(lexeme[index]))
            {
                index++;
            }
        }

        if (index < lexeme.Length && lexeme[index] == '.')
        {
            index++;
            var fractionStart = index;
            while (index < lexeme.Length && char.IsAsciiDigit(lexeme[index]))
            {
                index++;
            }

            if (index == fractionStart)
            {
                return false;
            }
        }

        if (index < lexeme.Length && lexeme[index] is 'e' or 'E')
        {
            index++;
            if (index < lexeme.Length && lexeme[index] is '+' or '-')
            {
                index++;
            }

            var exponentStart = index;
            while (index < lexeme.Length && char.IsAsciiDigit(lexeme[index]))
            {
                index++;
            }

            if (index == exponentStart)
            {
                return false;
            }
        }

        return index == lexeme.Length;
    }
}
