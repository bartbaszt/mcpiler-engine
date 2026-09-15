namespace MCPiler.Engine.Execution.Secrets;

/// <summary>
/// The provider values one active managed generation carries in memory.
/// </summary>
/// <remarks>
/// <para>
/// A managed generation delivers the values its <c>fromProvider</c> references name alongside
/// the Manifest bytes, and nothing about them is durable: they exist for the lifetime of the
/// generation that received them and are cleared when it is disposed. There is deliberately no
/// file, environment or store fallback. A fallback would mean a value surviving the generation
/// it was authorized for, which is exactly the authorization boundary the managed channel
/// exists to draw.
/// </para>
/// <para>
/// Matching is exact and ordinal. A provider key is an opaque identity, not a prefix or a
/// pattern: resolving a near miss would let one generation's value satisfy a reference written
/// for another, so a key that differs by a character, a case or surrounding whitespace is a
/// different key and fails as one.
/// </para>
/// <para>
/// Values are held as strings because that is what a credential reference resolves to; the
/// source does not decide what a value means. Disposal clears every held value so a retired
/// generation cannot leave its secrets reachable through an object graph, and reading after
/// disposal fails as a missing key rather than answering from a stale buffer.
/// </para>
/// </remarks>
public sealed class GenerationSecretSource : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _values;
    private bool _disposed;

    /// <summary>Creates a source over exactly the delivered provider values.</summary>
    /// <param name="values">Provider key to value; every key is required to be non-empty.</param>
    public GenerationSecretSource(IReadOnlyDictionary<string, string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        _values = new Dictionary<string, string>(values.Count, StringComparer.Ordinal);

        foreach (var pair in values)
        {
            if (string.IsNullOrEmpty(pair.Key))
            {
                throw new ArgumentException(
                    "A provider key must be non-empty. An empty key could never be named by a reference.",
                    nameof(values));
            }

            _values[pair.Key] = pair.Value;
        }
    }

    /// <summary>An empty source, for a generation that delivers no provider values.</summary>
    public static GenerationSecretSource Empty { get; } = new(new Dictionary<string, string>(StringComparer.Ordinal));

    /// <summary>How many values the generation currently holds.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _values.Count;
            }
        }
    }

    /// <summary>The held keys, ordinally ordered. Diagnostics and tests only; never values.</summary>
    public IReadOnlyList<string> Keys
    {
        get
        {
            lock (_gate)
            {
                return [.. _values.Keys.Order(StringComparer.Ordinal)];
            }
        }
    }

    /// <summary>
    /// Resolves exactly the key a <c>fromProvider</c> reference names.
    /// </summary>
    /// <param name="key">The provider key, matched ordinally and in full.</param>
    /// <param name="value">The held value when the key is present.</param>
    public bool TryResolve(string key, out string value)
    {
        ArgumentNullException.ThrowIfNull(key);

        lock (_gate)
        {
            value = string.Empty;

            return !_disposed && _values.TryGetValue(key, out value!);
        }
    }

    /// <summary>Clears every held value. Idempotent.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _values.Clear();
        }
    }
}
