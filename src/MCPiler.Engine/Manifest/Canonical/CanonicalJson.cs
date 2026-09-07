using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Canonical;

/// <summary>
/// The canonical JSON representation used whenever a manifest is sealed, hashed or compared.
/// </summary>
/// <remarks>
/// <para>
/// Canonicalization is deliberately NOT a constraint on authored input. A hand-written
/// manifest may be indented, may order members freely, and is never required to be
/// canonical. The canonical form exists only so that two independent producers can agree
/// on a hash for the same semantic document.
/// </para>
/// <para>
/// The rules are fixed by the manifest format version, because changing any of them
/// changes every previously computed hash:
/// </para>
/// <list type="number">
///   <item>object members are sorted by UTF-16 code-unit ordinal at every depth, which is
///     the member ordering RFC 8785 (JSON Canonicalization Scheme) specifies;</item>
///   <item>array order is preserved, because it is semantic;</item>
///   <item>no insignificant whitespace is emitted;</item>
///   <item>numbers are re-emitted with their original lexical token. This is an intentional
///     divergence from RFC 8785 number canonicalization: manifest schemas carry upstream
///     numeric bounds whose exact spelling must survive a round trip, and adopting ES6
///     number formatting would silently change the hash of every already-sealed
///     document;</item>
///   <item>output is UTF-8 without a byte-order mark, with the default
///     <see cref="Utf8JsonWriter"/> escaping. Non-ASCII and HTML-sensitive characters are
///     therefore emitted as <c>\uXXXX</c> escapes rather than as raw UTF-8. This is a second
///     intentional divergence from RFC 8785, which requires minimal escaping; it is kept
///     because byte agreement with the existing MCPiler canonical writer is a hard
///     requirement and that writer has always escaped this way;</item>
///   <item>the maximum document depth is <see cref="MaximumDocumentDepth"/>.</item>
/// </list>
/// <para>
/// No <see cref="JsonSerializerOptions"/> is passed on the write path, so no ambient
/// converter and no environment-dependent formatting can influence the bytes.
/// </para>
/// </remarks>
public static class CanonicalJson
{
    /// <summary>
    /// Maximum nesting depth accepted when parsing and enforced when writing.
    /// </summary>
    public const int MaximumDocumentDepth = 1000;

    /// <summary>Serializes any JSON value to its canonical UTF-8 bytes.</summary>
    /// <param name="node">The value to serialize. <c>null</c> is serialized as JSON <c>null</c>.</param>
    public static byte[] Serialize(JsonNode? node)
    {
        using var buffer = new ArrayPoolBufferWriter();

        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
        {
            MaxDepth = MaximumDocumentDepth,
            SkipValidation = false,
        }))
        {
            Write(writer, node, depth: 0);
        }

        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Parses UTF-8 JSON using the same depth contract as <see cref="Serialize"/>.
    /// </summary>
    /// <exception cref="JsonException">The input is not valid JSON, or exceeds the depth limit.</exception>
    public static JsonNode? Parse(ReadOnlySpan<byte> utf8Json)
        => JsonNode.Parse(
            utf8Json,
            nodeOptions: null,
            documentOptions: new JsonDocumentOptions { MaxDepth = MaximumDocumentDepth });

    /// <summary>Computes the lowercase SHA-256 hex digest of already-canonical bytes.</summary>
    public static string ComputeHash(ReadOnlySpan<byte> canonicalBytes)
        => Convert.ToHexString(SHA256.HashData(canonicalBytes)).ToLowerInvariant();

    /// <summary>Canonicalizes <paramref name="node"/> and returns its SHA-256 hex digest.</summary>
    public static string Hash(JsonNode? node) => ComputeHash(Serialize(node));

    private static void Write(Utf8JsonWriter writer, JsonNode? node, int depth)
    {
        if (depth > MaximumDocumentDepth)
        {
            throw new JsonException(string.Create(
                CultureInfo.InvariantCulture,
                $"The document exceeds the maximum canonical depth of {MaximumDocumentDepth}."));
        }

        switch (node)
        {
            case null:
                writer.WriteNullValue();
                break;

            case JsonObject obj:
                writer.WriteStartObject();

                // Ordinal ordering over UTF-16 code units is exactly the RFC 8785 member
                // ordering rule. Do not substitute a culture-aware or UTF-8 byte comparer.
                foreach (var member in obj.OrderBy(static m => m.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(member.Key);
                    Write(writer, member.Value, depth + 1);
                }

                writer.WriteEndObject();
                break;

            case JsonArray array:
                writer.WriteStartArray();

                foreach (var item in array)
                {
                    Write(writer, item, depth + 1);
                }

                writer.WriteEndArray();
                break;

            case JsonValue value:
                WriteValue(writer, value);
                break;

            default:
                throw new JsonException(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Unsupported JSON node type: {node.GetType().Name}."));
        }
    }

    private static void WriteValue(Utf8JsonWriter writer, JsonValue value)
    {
        // JsonNode retains the raw token for values parsed from text, so writing the
        // underlying JsonElement preserves the original lexical form of numbers and
        // strings without consulting any serializer options.
        if (value.TryGetValue<JsonElement>(out var element))
        {
            element.WriteTo(writer);
            return;
        }

        value.WriteTo(writer);
    }

    /// <summary>
    /// A minimal pooled <see cref="IBufferWriter{T}"/> so canonicalization does not pay for a
    /// <see cref="MemoryStream"/> copy on every section of a large bundle.
    /// </summary>
    private sealed class ArrayPoolBufferWriter : IBufferWriter<byte>, IDisposable
    {
        private byte[] _buffer = ArrayPool<byte>.Shared.Rent(4096);
        private int _written;

        public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _written);

        public void Advance(int count) => _written += count;

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            Ensure(sizeHint);
            return _buffer.AsMemory(_written);
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            Ensure(sizeHint);
            return _buffer.AsSpan(_written);
        }

        public void Dispose()
        {
            var buffer = _buffer;
            _buffer = [];
            _written = 0;

            if (buffer.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private void Ensure(int sizeHint)
        {
            if (sizeHint <= 0)
            {
                sizeHint = 1;
            }

            var available = _buffer.Length - _written;
            if (available >= sizeHint)
            {
                return;
            }

            var required = _written + sizeHint;
            var grown = ArrayPool<byte>.Shared.Rent(Math.Max(required, _buffer.Length * 2));
            _buffer.AsSpan(0, _written).CopyTo(grown);
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = grown;
        }
    }
}
