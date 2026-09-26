using System.Globalization;

using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.JmesPath;

/// <summary>
/// Maps an unchanged-package <c>JMESPathException</c> message to a stable failure class.
/// </summary>
/// <remarks>
/// <para>
/// The taxonomy was measured, not guessed: the package raises a single exception type for
/// lexing, parsing and evaluation, and the families are distinguishable by message prefix.
/// Compile families are <c>Unexpected token</c>, <c>Unexpected character</c>,
/// <c>Unterminated quoted identifier</c>, <c>Expected identifier</c>, <c>Unknown function</c>,
/// <c>invalid-arity</c> and <c>Unsupported AST node type</c>; the runtime family is the
/// <c>invalid-type</c> prefix.
/// </para>
/// <para>
/// Two consequences are normative. First, a compile family is a validity finding and a
/// runtime family is not, so load-time validation must not run an expression against a
/// placeholder body and treat its <c>invalid-type</c> failure as invalid — a legitimate
/// <c>keys(@)</c> or <c>sort(@)</c> would be refused. Second, a family this classifier does
/// not recognise is an <see cref="JmesPathFailureClass.InternalEvaluatorDefect"/>, never a
/// silent success: an evaluator upgrade that changes its message shape must be a visible
/// failure reviewed against the profile, not a quiet reclassification.
/// </para>
/// </remarks>
internal static class JmesPathFailureClassifier
{
    /// <summary>Function and grammar families, checked before the general syntax families.</summary>
    private static readonly string[] UnknownFunctionPrefixes = ["Unknown function:"];

    private static readonly string[] InvalidArityPrefixes = ["invalid-arity:"];

    private static readonly string[] UnsupportedNodePrefixes = ["Unsupported AST node type:"];

    private static readonly string[] InvalidTypePrefixes = ["invalid-type:"];

    /// <summary>
    /// The data-dependent value family, distinct from a type failure. The package reports it
    /// without a keyword prefix: measured, a zero slice step raises
    /// <c>Slice step cannot be 0.</c> only once the slice is actually evaluated.
    /// </summary>
    private static readonly string[] InvalidValuePrefixes = ["Slice step cannot be 0"];

    private static readonly string[] SyntaxPrefixes =
    [
        "Unexpected token",
        "Unexpected character",
        "Unexpected Eof",
        "Unexpected number token",
        "Unexpected '",
        "Invalid unicode escape",
        "Expected token",
        "Expected",
        "Unterminated quoted identifier",
        "Unterminated",
        "Expected identifier",
    ];

    /// <summary>Classifies one evaluator exception message.</summary>
    internal static JmesPathFailureClass Classify(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return JmesPathFailureClass.InternalEvaluatorDefect;
        }

        if (HasAnyPrefix(message, UnknownFunctionPrefixes))
        {
            return JmesPathFailureClass.CompileUnknownFunction;
        }

        if (HasAnyPrefix(message, InvalidArityPrefixes))
        {
            return JmesPathFailureClass.CompileInvalidArity;
        }

        if (HasAnyPrefix(message, UnsupportedNodePrefixes))
        {
            return JmesPathFailureClass.CompileUnsupportedNode;
        }

        if (HasAnyPrefix(message, InvalidTypePrefixes))
        {
            return JmesPathFailureClass.RuntimeInvalidType;
        }

        if (HasAnyPrefix(message, InvalidValuePrefixes))
        {
            return JmesPathFailureClass.RuntimeInvalidValue;
        }

        if (HasAnyPrefix(message, SyntaxPrefixes))
        {
            return JmesPathFailureClass.CompileSyntax;
        }

        return JmesPathFailureClass.InternalEvaluatorDefect;
    }

    /// <summary>Whether a class is a compile-phase validity finding.</summary>
    internal static bool IsCompileFamily(JmesPathFailureClass failureClass)
        => failureClass is
            JmesPathFailureClass.CompileSyntax
            or JmesPathFailureClass.CompileUnknownFunction
            or JmesPathFailureClass.CompileInvalidArity
            or JmesPathFailureClass.CompileUnsupportedNode;

    /// <summary>Builds the failure record for one evaluator message.</summary>
    internal static JmesPathFailure FromEvaluatorMessage(string? message)
    {
        JmesPathFailureClass failureClass = Classify(message);

        string summary = failureClass == JmesPathFailureClass.InternalEvaluatorDefect
            ? string.Create(
                CultureInfo.InvariantCulture,
                $"The JMESPath evaluator failed in an unrecognised family: {Sanitize(message)}")
            : string.Create(
                CultureInfo.InvariantCulture,
                $"The JMESPath evaluation failed ({failureClass}): {Sanitize(message)}");

        return new JmesPathFailure(failureClass, summary);
    }

    /// <summary>
    /// Keeps message text single-line and bounded so diagnostics cannot smuggle payload.
    /// </summary>
    internal static string Sanitize(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "(no evaluator message)";
        }

        string flattened = message.Replace('\r', ' ').Replace('\n', ' ').Trim();

        return flattened.Length <= 300 ? flattened : flattened[..300];
    }

    private static bool HasAnyPrefix(string message, string[] prefixes)
    {
        foreach (string prefix in prefixes)
        {
            if (message.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
