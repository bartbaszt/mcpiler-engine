using System.Globalization;

namespace MCPiler.Engine.Runtime;

/// <summary>One metadata-only finding emitted while a mounted Manifest is serving.</summary>
/// <param name="Code">Stable machine-readable classification.</param>
/// <param name="Message">Operator-facing explanation containing no request or response value.</param>
/// <param name="Manifest">The mounted Manifest bundle path.</param>
/// <param name="Surface">The addressed surface slug.</param>
/// <param name="Operation">The invoked operation slug.</param>
/// <param name="SchemaLocation">The failing location in the advertised schema.</param>
public sealed record RuntimeDiagnostic(
    string Code,
    string Message,
    string Manifest,
    string Surface,
    string Operation,
    string SchemaLocation)
{
    /// <summary>Renders one line suitable for the host's normal operational output.</summary>
    public override string ToString()
        => string.Create(
            CultureInfo.InvariantCulture,
            $"warning [{Code}] {Message} manifest={Manifest} surface={Surface} "
            + $"operation={Operation} schemaLocation={SchemaLocation}");
}
