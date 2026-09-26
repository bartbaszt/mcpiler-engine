using MCPiler.Engine.JmesPath;
using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.UnitTests.JmesPath;

/// <summary>
/// The measured failure taxonomy: every family the unchanged package produces, classified.
/// </summary>
/// <remarks>
/// <para>
/// The driver messages are the ones produced by the pinned 5.6.1 package and recorded during
/// research. They are duplicated here rather than generated, because a generated expectation
/// would record whatever the current build happens to say and the point of the classifier is
/// that a message shape change is a visible failure.
/// </para>
/// <para>
/// The last group matters most: a family the classifier does not know is a defect, and the tests
/// below would fail if a new family silently joined an existing one.
/// </para>
/// </remarks>
public sealed class JmesPathFailureClassifierTests
{
    [Theory]
    [InlineData("Unexpected token 'RightBracket' at position 5.")]
    [InlineData("Unexpected token 'Eof' at position 10.")]
    [InlineData("Unexpected character '\\' at position 0.")]
    [InlineData("Unterminated quoted identifier starting at position 3.")]
    [InlineData("Expected identifier at position 3.")]
    [InlineData("Expected 'RightBracket' but found 'Colon' at position 9.")]
    [InlineData("Expected identifier, '*', '[', or '{' after '.' at position 7.")]
    [InlineData("Expected identifier for hash key at position 13.")]
    [InlineData("Unexpected number token at position 5.")]
    [InlineData("Unexpected '=' at position 1. Did you mean '=='?")]
    [InlineData("Invalid unicode escape at position 1.")]
    public void A_syntax_family_is_a_compile_failure(string message)
        => Assert.Equal(JmesPathFailureClass.CompileSyntax, JmesPathFailureClassifier.Classify(message));

    [Theory]
    [InlineData("Unknown function: bar()")]
    public void An_unknown_function_is_a_compile_failure(string message)
        => Assert.Equal(JmesPathFailureClass.CompileUnknownFunction, JmesPathFailureClassifier.Classify(message));

    [Theory]
    [InlineData("invalid-arity: sort_by() takes exactly 2 argument(s), got 1.")]
    [InlineData("invalid-arity: starts_with() takes exactly 2 argument(s), got 1.")]
    public void An_invalid_arity_is_a_compile_failure(string message)
        => Assert.Equal(JmesPathFailureClass.CompileInvalidArity, JmesPathFailureClassifier.Classify(message));

    [Theory]
    [InlineData("Unsupported AST node type: SomethingNew")]
    public void An_unsupported_node_is_a_compile_failure(string message)
        => Assert.Equal(JmesPathFailureClass.CompileUnsupportedNode, JmesPathFailureClassifier.Classify(message));

    [Theory]
    [InlineData("invalid-type: sort() expects an array argument.")]
    [InlineData("invalid-type: length() expects a string, array, or object argument.")]
    [InlineData("invalid-type: max() expects an array argument.")]
    public void A_runtime_type_failure_is_not_a_compile_failure(string message)
    {
        // The distinction is normative: this family is what a legitimate keys(@) or sort(@)
        // produces against a placeholder body, and treating it as invalid would refuse them.
        JmesPathFailureClass classified = JmesPathFailureClassifier.Classify(message);

        Assert.Equal(JmesPathFailureClass.RuntimeInvalidType, classified);
        Assert.False(JmesPathFailureClassifier.IsCompileFamily(classified));
    }

    [Theory]
    [InlineData("Slice step cannot be 0.")]
    public void A_runtime_value_failure_is_not_a_compile_failure(string message)
    {
        // Measured on the official corpus: this family is data-dependent like invalid-type, and
        // the very same expression succeeds against a body whose slice is not evaluated.
        JmesPathFailureClass classified = JmesPathFailureClassifier.Classify(message);

        Assert.Equal(JmesPathFailureClass.RuntimeInvalidValue, classified);
        Assert.False(JmesPathFailureClassifier.IsCompileFamily(classified));
    }

    [Fact]
    public void Every_compile_family_is_reported_as_a_compile_family()
    {
        Assert.True(JmesPathFailureClassifier.IsCompileFamily(JmesPathFailureClass.CompileSyntax));
        Assert.True(JmesPathFailureClassifier.IsCompileFamily(JmesPathFailureClass.CompileUnknownFunction));
        Assert.True(JmesPathFailureClassifier.IsCompileFamily(JmesPathFailureClass.CompileInvalidArity));
        Assert.True(JmesPathFailureClassifier.IsCompileFamily(JmesPathFailureClass.CompileUnsupportedNode));
    }

    [Fact]
    public void Every_runtime_and_operational_family_is_not_a_compile_family()
    {
        JmesPathFailureClass[] notCompile =
        [
            JmesPathFailureClass.RuntimeInvalidType,
            JmesPathFailureClass.RuntimeInvalidValue,
            JmesPathFailureClass.ExpressionTooManyBytes,
            JmesPathFailureClass.InputTooManyNodes,
            JmesPathFailureClass.InputTooDeep,
            JmesPathFailureClass.InputNotJson,
            JmesPathFailureClass.InputFileOrBinary,
            JmesPathFailureClass.ResultTooManyNodes,
            JmesPathFailureClass.ResultTooDeep,
            JmesPathFailureClass.OutputTooManyBytes,
            JmesPathFailureClass.InternalEvaluatorDefect,
            JmesPathFailureClass.OperationalTimeout,
            JmesPathFailureClass.OperationalCancelled,
            JmesPathFailureClass.OperationalMemoryExceeded,
            JmesPathFailureClass.OperationalConfinementUnavailable,
            JmesPathFailureClass.OperationalBusy,
            JmesPathFailureClass.OperationalWorkerFailure,
        ];

        Assert.All(notCompile, failureClass => Assert.False(JmesPathFailureClassifier.IsCompileFamily(failureClass)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("something the package never said")]
    [InlineData("NullReferenceException")]
    public void An_unrecognised_message_is_an_internal_defect_never_a_language_failure(string? message)
    {
        // Silence and novelty both mean the same thing: this classifier cannot account for what
        // happened, so the outcome is a defect rather than a refusal the author caused.
        Assert.Equal(JmesPathFailureClass.InternalEvaluatorDefect, JmesPathFailureClassifier.Classify(message));
    }

    [Fact]
    public void The_classifier_never_returns_a_compile_family_for_a_non_message()
        => Assert.False(JmesPathFailureClassifier.IsCompileFamily(JmesPathFailureClassifier.Classify(null)));

    [Fact]
    public void From_evaluator_message_preserves_the_class_and_bounds_the_text()
    {
        string longMessage = "invalid-type: " + new string('x', 5000);
        JmesPathFailure failure = JmesPathFailureClassifier.FromEvaluatorMessage(longMessage);

        Assert.Equal(JmesPathFailureClass.RuntimeInvalidType, failure.FailureClass);
        Assert.Contains("invalid-type:", failure.Message, StringComparison.Ordinal);
        Assert.True(failure.Message.Length <= 400, "diagnostic text must stay bounded");
    }

    [Fact]
    public void An_unrecognised_family_says_so_in_its_message()
    {
        JmesPathFailure failure = JmesPathFailureClassifier.FromEvaluatorMessage("brand new failure");

        Assert.Equal(JmesPathFailureClass.InternalEvaluatorDefect, failure.FailureClass);
        Assert.Contains("unrecognised", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Sanitize_flattens_newlines_so_one_message_stays_one_line()
    {
        string sanitized = JmesPathFailureClassifier.Sanitize("first\r\nsecond\nthird");

        Assert.DoesNotContain('\r', sanitized);
        Assert.DoesNotContain('\n', sanitized);
        Assert.Contains("first  second third", sanitized, StringComparison.Ordinal);
    }

    [Fact]
    public void Operational_classes_are_marked_operational_and_language_classes_are_not()
    {
        Assert.False(new JmesPathFailure(JmesPathFailureClass.CompileSyntax, "x").IsOperational);
        Assert.False(new JmesPathFailure(JmesPathFailureClass.RuntimeInvalidType, "x").IsOperational);
        Assert.False(new JmesPathFailure(JmesPathFailureClass.OutputTooManyBytes, "x").IsOperational);
        Assert.False(new JmesPathFailure(JmesPathFailureClass.InternalEvaluatorDefect, "x").IsOperational);

        Assert.True(new JmesPathFailure(JmesPathFailureClass.OperationalTimeout, "x").IsOperational);
        Assert.True(new JmesPathFailure(JmesPathFailureClass.OperationalCancelled, "x").IsOperational);
        Assert.True(new JmesPathFailure(JmesPathFailureClass.OperationalMemoryExceeded, "x").IsOperational);
        Assert.True(new JmesPathFailure(JmesPathFailureClass.OperationalConfinementUnavailable, "x").IsOperational);
        Assert.True(new JmesPathFailure(JmesPathFailureClass.OperationalBusy, "x").IsOperational);
        Assert.True(new JmesPathFailure(JmesPathFailureClass.OperationalWorkerFailure, "x").IsOperational);
    }

    [Fact]
    public void Every_class_has_a_stable_code_that_round_trips_back_to_it()
    {
        // The code is what crosses a process and a frame boundary. A class without a code, or a
        // code that maps back to a different class, would silently reclassify a worker failure
        // on the parent side — the one place the class cannot be re-derived.
        foreach (JmesPathFailureClass failureClass in Enum.GetValues<JmesPathFailureClass>())
        {
            string code = JmesPathFailure.CodeOf(failureClass);

            Assert.False(string.IsNullOrWhiteSpace(code));
            Assert.Equal(failureClass, JmesPathFailure.ClassFromCode(code));
        }

        Assert.Equal(
            JmesPathFailureClass.InternalEvaluatorDefect,
            JmesPathFailure.ClassFromCode("a code no build ever emitted"));
    }
}
