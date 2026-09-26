using System.Globalization;

using Corvus.Text.Json.JMESPath;

using MCPiler.Engine.Runtime.Projection;

using CorvusElement = Corvus.Text.Json.JsonElement;

namespace MCPiler.Engine.JmesPath;

/// <summary>
/// Runs the unchanged Corvus evaluator over one already-normalized body.
/// </summary>
/// <remarks>
/// <para>
/// This is the worker side of an evaluation and the only place in Engine that calls the
/// evaluator. It is reached exclusively from a worker entry: the serving process, the library's
/// execution path and the Platform's Blazor process never invoke it, because an evaluation that
/// cannot be interrupted cannot be run where the product answers.
/// </para>
/// <para>
/// Every evaluation gets a fresh <see cref="JMESPathEvaluator"/>. The package caches compiled
/// expressions per instance with no bound, so a shared instance would let one long-running host
/// accumulate compiled plans for every expression it had ever seen. A fresh instance makes the
/// evaluator's own cache a per-worker fact rather than a process-wide one.
/// </para>
/// </remarks>
internal static class CorvusJmesPathRuntime
{
    /// <summary>Evaluates <paramref name="expression"/> against an evaluator-ready body.</summary>
    /// <param name="normalizedJson">
    /// The body with members already in the profile's canonical order, as UTF-8 JSON.
    /// </param>
    /// <param name="expression">The authored expression.</param>
    /// <param name="limits">The effective limits; the output bound is the serialization cap.</param>
    /// <remarks>
    /// An allocation refused by the enforced limit is operational evidence, not a language
    /// result: the expression was never given the chance to finish. The small classified frame
    /// is written before the worker exits, so the parent can report the memory class precisely
    /// instead of inferring it from a dead process; if even that frame cannot be produced, the
    /// exit without a response is still classified as an operational worker failure.
    /// </remarks>
    internal static JmesPathEvaluationResult Evaluate(
        ReadOnlyMemory<byte> normalizedJson,
        string expression,
        JmesPathLimits limits)
    {
        try
        {
            return EvaluateCore(normalizedJson, expression, limits);
        }
        catch (OutOfMemoryException)
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.OperationalMemoryExceeded,
                "The projection worker reached its enforced memory limit."));
        }
    }

    private static JmesPathEvaluationResult EvaluateCore(
        ReadOnlyMemory<byte> normalizedJson,
        string expression,
        JmesPathLimits limits)
    {
        CorvusElement body;

        try
        {
            body = Corvus.Text.Json.ParsedJsonDocument<CorvusElement>
                .Parse(normalizedJson, default)
                .RootElement;
        }
        catch (Exception parseFailure) when (
            parseFailure is Corvus.Text.Json.JsonException
            || parseFailure is FormatException
            || parseFailure is ArgumentException)
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.InputNotJson,
                $"The normalized body could not be parsed by the evaluator: {JmesPathFailureClassifier.Sanitize(parseFailure.Message)}"));
        }

        CorvusElement result;

        try
        {
            var evaluator = new JMESPathEvaluator();

            result = evaluator.Search(expression, body);
        }
        catch (JMESPathException evaluatorFailure)
        {
            return JmesPathEvaluationResult.Failed(
                JmesPathFailureClassifier.FromEvaluatorMessage(evaluatorFailure.Message));
        }
        catch (OutOfMemoryException)
        {
            // Re-thrown to the wrapper, which classifies it as the operational memory class.
            // Catching it here would let the generic defect arm below swallow an allocation
            // refusal and report it as a dependency defect.
            throw;
        }
        catch (Exception unexpected)
        {
            // The package raises one exception type for language failures. Anything else is a
            // defect in the dependency, and it is reported as such rather than reclassified as
            // a language result a caller could mistake for a refusal they caused.
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.InternalEvaluatorDefect,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The JMESPath evaluator threw {unexpected.GetType().Name}: {JmesPathFailureClassifier.Sanitize(unexpected.Message)}")));
        }

        if (result.ValueKind is Corvus.Text.Json.JsonValueKind.Undefined)
        {
            // Measured: this evaluator resolves a no-match to JSON null rather than Undefined,
            // and the profile's semantics are "no value is null". Should a future patch reach
            // here, the conversion keeps that promise explicit rather than serializing a kind
            // no JMESPath consumer defines.
            result = Corvus.Text.Json.ParsedJsonDocument<CorvusElement>
                .Parse((ReadOnlyMemory<byte>)"null"u8.ToArray(), default)
                .RootElement;
        }

        using var buffer = new BoundedJsonBuffer(limits.MaxOutputBytes);

        try
        {
            using (var writer = new Corvus.Text.Json.Utf8JsonWriter(
                buffer,
                new Corvus.Text.Json.JsonWriterOptions { Indented = false }))
            {
                result.WriteTo(writer);
            }
        }
        catch (BoundedJsonBuffer.BufferFullException)
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.OutputTooManyBytes,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The projected value is larger than maxOutputBytes={limits.MaxOutputBytes} bytes.")));
        }
        catch (Exception writeFailure) when (
            writeFailure is Corvus.Text.Json.JsonException
            || writeFailure is InvalidOperationException
            || writeFailure is ObjectDisposedException)
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.InternalEvaluatorDefect,
                $"The projected value could not be serialized: {JmesPathFailureClassifier.Sanitize(writeFailure.Message)}"));
        }

        // The evaluator's own serialization follows its internal construction order for objects
        // the expression created (`merge`, multi-select). Profile 1 canonicalizes the completed
        // result's member order, so two evaluations that reached the same value cannot differ in
        // bytes. Arrays keep the order the evaluator produced, because that order is semantic and
        // is what `sort`/wildcard semantics promise.
        if (!JmesPathDocument.TryParse(buffer.WrittenSpan.ToArray(), out var produced, out JmesPathFailure? reserializationFailure))
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.InternalEvaluatorDefect,
                $"The projected value could not be read back for canonicalization: {reserializationFailure!.Message}"));
        }

        using (produced)
        {
            if (!JmesPathCanonicalizer.TryCanonicalize(
                    produced.RootElement,
                    JmesPathBudget.Result,
                    limits.MaxResultNodes,
                    limits.MaxResultDepth,
                    limits.MaxOutputBytes,
                    out byte[]? canonical,
                    out _,
                    out JmesPathFailure? resultFailure))
            {
                return JmesPathEvaluationResult.Failed(resultFailure!);
            }

            return JmesPathEvaluationResult.Produced(canonical!);
        }
    }
}
