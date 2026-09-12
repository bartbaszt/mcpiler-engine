using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution.Files;

namespace MCPiler.Engine.Transform;

/// <summary>
/// Runs a validated transformation program over one document.
/// </summary>
/// <remarks>
/// <para>
/// There is no expression language, no regular expression, no arithmetic beyond
/// <c>convert</c>, no host or user function, no clock, no randomness and no ambient
/// identifier — and, more to the point, no registration point where one could be added. The
/// nineteen operations are the whole of what a program can do, and they are reached by a
/// closed switch rather than by a lookup a caller could extend.
/// </para>
/// <para>
/// Every comparison and conversion is invariant-culture, and values travel as JSON nodes
/// rather than as .NET primitives, so a number's token survives a program that merely moves
/// it. An evaluation is therefore a pure function of the program, the document and the
/// effective limits: the same three inputs produce the same bytes on any machine, under any
/// host culture, in any process.
/// </para>
/// <para>
/// Limits are enforced while running and independently of the static worst case Tier 1
/// computed. The static estimate proves a program <em>could</em> stay inside its bounds; only
/// this proves it did, because the estimate has no access to the document. A breach aborts
/// with its own code and the step index and yields no document at all.
/// </para>
/// </remarks>
internal static class TransformEvaluator
{
    /// <summary>Evaluates <paramref name="program"/> against <paramref name="document"/>.</summary>
    /// <param name="program">A program Tier 1 has already accepted.</param>
    /// <param name="document">The starting document, cloned before anything is written.</param>
    /// <param name="ceiling">
    /// The governing ceiling. Every bound applied is the smaller of the program's value and
    /// this one, so a program can never widen what the manifest's policy allows.
    /// </param>
    internal static TransformEvaluation Evaluate(
        TransformProgram program,
        JsonObject document,
        TransformCeilingValues ceiling)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(ceiling);

        TransformLimits limits = program.Limits.ClampTo(ceiling);
        var state = new EvaluationState(limits);
        var root = new RootHolder(
            program.Base == TransformBase.Empty ? new JsonObject() : document.DeepClone());

        if (RunSteps(program.Steps, root, state) is { } failure)
        {
            return failure;
        }

        // Measured in bytes, because the bound is named in bytes. Counting UTF-16 units would
        // let a document of multi-byte text pass a limit it exceeds on the wire by a factor of
        // three, which is the direction that matters for a bound whose job is refusal.
        long produced = Encoding.UTF8.GetByteCount(Serialize(root.Node));

        if (produced > limits.MaxOutputBytes)
        {
            return TransformEvaluation.AbortedWholly(
                TransformCodes.LimitOutputBytes,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The transformed document is {produced} bytes, exceeding maxOutputBytes={limits.MaxOutputBytes}."));
        }

        return TransformEvaluation.Produced(root.Node);
    }

    /// <summary>Serializes a node the way every comparison in this change reads it.</summary>
    /// <remarks>
    /// Member order is insertion order, not sorted order. The transformed document is a request
    /// or a response body, where order is the author's and a canonicalizing writer would rewrite
    /// it. Determinism comes from the program being deterministic, not from re-sorting.
    /// </remarks>
    internal static string Serialize(JsonNode? node) => JsonSerializer.Serialize(node);

    /// <summary>Runs one step list, returning the abort or <c>null</c> when all steps ran.</summary>
    private static TransformEvaluation? RunSteps(
        IReadOnlyList<TransformStep> steps,
        RootHolder root,
        EvaluationState state)
    {
        for (int index = 0; index < steps.Count; index++)
        {
            TransformStep step = steps[index];
            string operation = StepVocabulary.WireName(step.Op);

            if (!state.ConsumeStep())
            {
                return TransformEvaluation.Aborted(
                    TransformCodes.LimitSteps,
                    index,
                    operation,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The evaluation executed more than maxSteps={state.Limits.MaxSteps} steps."));
            }

            try
            {
                if (Apply(step, root, state) is { } nested)
                {
                    return nested.Failure.Within(index, operation, nested.Place);
                }
            }
            catch (StepFailure failure)
            {
                return TransformEvaluation.Aborted(failure.Code, index, operation, failure.Message);
            }

            if (state.NodesTouched > state.Limits.MaxNodes)
            {
                return TransformEvaluation.Aborted(
                    TransformCodes.LimitNodes,
                    index,
                    operation,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The evaluation touched more than maxNodes={state.Limits.MaxNodes} nodes."));
            }

            if (Depth(root.Node) > state.Limits.MaxDepth)
            {
                return TransformEvaluation.Aborted(
                    TransformCodes.LimitDepth,
                    index,
                    operation,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The document nested deeper than maxDepth={state.Limits.MaxDepth}."));
            }

            if (state.FanoutProcessed > state.Limits.MaxArrayFanout)
            {
                return TransformEvaluation.Aborted(
                    TransformCodes.LimitFanout,
                    index,
                    operation,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The evaluation iterated more than maxArrayFanout={state.Limits.MaxArrayFanout} items."));
            }
        }

        return null;
    }

    /// <summary>Applies one step, returning a nested abort when one happened inside it.</summary>
    private static NestedAbort? Apply(TransformStep step, RootHolder root, EvaluationState state)
    {
        switch (step)
        {
            case WhenStep conditional:
            {
                bool holds = Holds(conditional.Condition, root.Node, state);
                IReadOnlyList<TransformStep> branch = holds ? conditional.Steps : conditional.ElseSteps;

                if (branch.Count == 0)
                {
                    return null;
                }

                return RunSteps(branch, root, state) is { } failure
                    ? new NestedAbort(failure, holds ? "the then-branch" : "the else-branch")
                    : null;
            }

            case MapArrayStep mapArray:
                return Iterate(mapArray, root, state);

            case MapObjectStep mapObject:
                return Iterate(mapObject, root, state);

            default:
                ApplySimple(step, root, state);
                return null;
        }
    }

    private static NestedAbort? Iterate(MapArrayStep step, RootHolder root, EvaluationState state)
    {
        JsonNode? source = Read(root.Node, step.Source);

        if (source is null)
        {
            Missing(step.OnMissing, step.Source, root, step.Target, state);
            return null;
        }

        if (source is not JsonArray array)
        {
            throw new StepFailure(
                TransformCodes.StepFailed,
                $"The source at '{step.Source}' is not an array.");
        }

        var processed = new JsonArray();
        int count = Math.Min(array.Count, step.MaxItems);

        for (int item = 0; item < count; item++)
        {
            state.ConsumeFanout();
            var holder = new RootHolder(array[item]?.DeepClone() ?? new JsonObject());

            if (RunSteps(step.Steps, holder, state) is { } failure)
            {
                return new NestedAbort(
                    failure,
                    string.Create(CultureInfo.InvariantCulture, $"item {item}"));
            }

            processed.Add(holder.Node);
        }

        Write(root, step.Target, processed, state);
        return null;
    }

    private static NestedAbort? Iterate(MapObjectStep step, RootHolder root, EvaluationState state)
    {
        JsonNode? source = Read(root.Node, step.Source);

        if (source is null)
        {
            Missing(step.OnMissing, step.Source, root, step.Target, state);
            return null;
        }

        if (source is not JsonObject members)
        {
            throw new StepFailure(
                TransformCodes.StepFailed,
                $"The source at '{step.Source}' is not an object.");
        }

        var processed = new JsonObject();
        KeyValuePair<string, JsonNode?>[] entries = [.. members];
        int count = Math.Min(entries.Length, step.MaxEntries);

        for (int entry = 0; entry < count; entry++)
        {
            state.ConsumeFanout();
            var holder = new RootHolder(entries[entry].Value?.DeepClone() ?? new JsonObject());

            if (RunSteps(step.Steps, holder, state) is { } failure)
            {
                return new NestedAbort(failure, $"entry '{entries[entry].Key}'");
            }

            processed[entries[entry].Key] = holder.Node;
        }

        Write(root, step.Target, processed, state);
        return null;
    }

    /// <summary>Applies every non-iterating, non-conditional operation.</summary>
    private static void ApplySimple(TransformStep step, RootHolder root, EvaluationState state)
    {
        switch (step)
        {
            case CopyStep copy:
            {
                if (Require(copy.Source, copy.OnMissing, root.Node, state) is { } value)
                {
                    Write(root, copy.Target, value.DeepClone(), state);
                }
                else
                {
                    Absent(copy.OnMissing, root, copy.Target, state);
                }

                break;
            }

            case MoveStep move:
            {
                if (Require(move.Source, move.OnMissing, root.Node, state) is { } value)
                {
                    Write(root, move.Target, value.DeepClone(), state);
                    Remove(root.Node, move.Source, state);
                }
                else
                {
                    Absent(move.OnMissing, root, move.Target, state);
                }

                break;
            }

            case OmitStep omit:
                Remove(root.Node, omit.Target, state);
                break;

            case PickStep pick:
            {
                JsonNode? source = Read(root.Node, pick.Source);

                if (source is null)
                {
                    Missing(pick.OnMissing, pick.Source, root, pick.Target, state);
                    break;
                }

                if (source is not JsonObject members)
                {
                    throw new StepFailure(
                        TransformCodes.StepFailed,
                        $"The source at '{pick.Source}' is not an object.");
                }

                var projected = new JsonObject();

                foreach (string member in pick.Members)
                {
                    if (members.TryGetPropertyValue(member, out JsonNode? picked) && picked is not null)
                    {
                        projected[member] = picked.DeepClone();
                        state.Touch();
                    }
                }

                Write(root, pick.Target, projected, state);
                break;
            }

            case NestStep nest:
            {
                if (Require(nest.Source, nest.OnMissing, root.Node, state) is { } value)
                {
                    Write(root, Join(nest.Target, nest.Name), value.DeepClone(), state);
                }
                else
                {
                    Absent(nest.OnMissing, root, Join(nest.Target, nest.Name), state);
                }

                break;
            }

            case FlattenStep flatten:
            {
                JsonNode? source = Read(root.Node, flatten.Source);

                if (source is null)
                {
                    Missing(flatten.OnMissing, flatten.Source, root, flatten.Target, state);
                    break;
                }

                if (source is not JsonObject members)
                {
                    throw new StepFailure(
                        TransformCodes.StepFailed,
                        $"The source at '{flatten.Source}' is not an object.");
                }

                foreach ((string name, JsonNode? value) in members)
                {
                    if (value is not null)
                    {
                        Write(root, Join(flatten.Target, name), value.DeepClone(), state);
                    }
                }

                break;
            }

            case FlattenArrayStep flattenArray:
            {
                JsonNode? source = Read(root.Node, flattenArray.Source);

                if (source is null)
                {
                    Missing(flattenArray.OnMissing, flattenArray.Source, root, flattenArray.Target, state);
                    break;
                }

                if (source is not JsonArray outer)
                {
                    throw new StepFailure(
                        TransformCodes.StepFailed,
                        $"The source at '{flattenArray.Source}' is not an array.");
                }

                var combined = new JsonArray();

                foreach (JsonNode? inner in outer)
                {
                    if (inner is JsonArray nested)
                    {
                        foreach (JsonNode? item in nested)
                        {
                            combined.Add(item?.DeepClone());
                            state.Touch();
                        }
                    }
                    else
                    {
                        combined.Add(inner?.DeepClone());
                        state.Touch();
                    }
                }

                Write(root, flattenArray.Target, combined, state);
                break;
            }

            case MergeStep merge:
            {
                var merged = new JsonObject();

                foreach (string pointer in merge.Sources)
                {
                    JsonNode? source = Read(root.Node, pointer);

                    if (source is null && merge.OnMissing == TransformOnMissing.Error)
                    {
                        throw new StepFailure(
                            TransformCodes.MissingSource,
                            $"The source '{pointer}' is missing.");
                    }

                    if (source is not JsonObject members)
                    {
                        continue;
                    }

                    foreach ((string name, JsonNode? value) in members)
                    {
                        merged[name] = value?.DeepClone();
                        state.Touch();
                    }
                }

                Write(root, merge.Target, merged, state);
                break;
            }

            case SetConstantStep constant:
                Write(root, constant.Target, constant.Value.DeepClone(), state);
                break;

            case DefaultStep fallback:
            {
                if (Read(root.Node, fallback.Target) is null)
                {
                    Write(root, fallback.Target, fallback.Value.DeepClone(), state);
                }

                break;
            }

            case ConvertStep convert:
            {
                if (Require(convert.Source, convert.OnMissing, root.Node, state) is { } value)
                {
                    Write(root, convert.Target, Coerce(value, convert.To), state);
                }
                else
                {
                    Absent(convert.OnMissing, root, convert.Target, state);
                }

                break;
            }

            case TemplateStep template:
            {
                if (Render(template, root.Node, state) is { } rendered)
                {
                    Write(root, template.Target, JsonValue.Create(rendered), state);
                }
                else
                {
                    Missing(template.OnMissing, "a template argument", root, template.Target, state);
                }

                break;
            }

            case CoalesceStep coalesce:
            {
                foreach (string pointer in coalesce.Sources)
                {
                    if (Read(root.Node, pointer) is { } candidate)
                    {
                        Write(root, coalesce.Target, candidate.DeepClone(), state);
                        break;
                    }
                }

                break;
            }

            case EnumMapStep enumMap:
            {
                JsonNode? value = Require(enumMap.Source, enumMap.OnMissing, root.Node, state);

                if (value is null)
                {
                    Absent(enumMap.OnMissing, root, enumMap.Target, state);
                    break;
                }

                string token = Serialize(value);

                foreach (EnumMapping mapping in enumMap.Mappings)
                {
                    if (string.Equals(Serialize(mapping.From), token, StringComparison.Ordinal))
                    {
                        Write(root, enumMap.Target, mapping.To.DeepClone(), state);
                        break;
                    }
                }

                break;
            }

            case LimitArrayStep limit:
            {
                JsonNode? source = Read(root.Node, limit.Source);

                if (source is null)
                {
                    Missing(limit.OnMissing, limit.Source, root, limit.Target, state);
                    break;
                }

                if (source is not JsonArray array)
                {
                    throw new StepFailure(
                        TransformCodes.StepFailed,
                        $"The source at '{limit.Source}' is not an array.");
                }

                var truncated = new JsonArray();

                for (int index = 0; index < Math.Min(array.Count, limit.MaxItems); index++)
                {
                    truncated.Add(array[index]?.DeepClone());
                    state.Touch();
                }

                Write(root, limit.Target, truncated, state);
                break;
            }

            case FileRefStep fileRef:
            {
                JsonNode? value = Require(fileRef.Source, fileRef.OnMissing, root.Node, state);

                if (value is null)
                {
                    Absent(fileRef.OnMissing, root, fileRef.Target, state);
                    break;
                }

                // A handle, and nothing that merely resembles one. The only thing this
                // operation may move is an identifier the caller already holds; accepting an
                // arbitrary string here would turn fileRef into a way to name a file by
                // guessing, which is the one escape the exclusion list exists to close.
                if (value is not JsonValue candidate
                    || !candidate.TryGetValue(out string? handle)
                    || handle is null
                    || !FileHandleStore.IsWellFormedId(handle))
                {
                    throw new StepFailure(
                        TransformCodes.FileHandle,
                        $"The value at '{fileRef.Source}' is not a file handle; only handles move through fileRef.");
                }

                Write(root, fileRef.Target, JsonValue.Create(handle), state);
                Remove(root.Node, fileRef.Source, state);
                break;
            }

            default:
                // Unreachable: the iterating and conditional operations are dispatched before
                // this method is called, and the vocabulary is closed. Stated as a failure
                // rather than an assertion so a nineteenth-plus operation added without an arm
                // here aborts with a code instead of silently doing nothing.
                throw new StepFailure(
                    TransformCodes.StepFailed,
                    $"Operation '{StepVocabulary.WireName(step.Op)}' has no evaluation arm.");
        }
    }

    // ---- missing-source handling -------------------------------------------------------

    /// <summary>Reads a source, honouring <c>onMissing: error</c>, returning null to skip.</summary>
    private static JsonNode? Require(
        string pointer,
        TransformOnMissing onMissing,
        JsonNode root,
        EvaluationState state)
    {
        if (Read(root, pointer) is { } value)
        {
            state.Touch();
            return value;
        }

        if (onMissing == TransformOnMissing.Error)
        {
            throw new StepFailure(TransformCodes.MissingSource, $"The source '{pointer}' is missing.");
        }

        return null;
    }

    /// <summary>What a step does once its source is known to be absent.</summary>
    private static void Absent(
        TransformOnMissing onMissing,
        RootHolder root,
        string target,
        EvaluationState state)
    {
        if (onMissing == TransformOnMissing.Null)
        {
            Write(root, target, null, state);
        }
    }

    /// <summary>The same decision for a step that reads its source without <see cref="Require"/>.</summary>
    private static void Missing(
        TransformOnMissing onMissing,
        string pointer,
        RootHolder root,
        string target,
        EvaluationState state)
    {
        if (onMissing == TransformOnMissing.Error)
        {
            throw new StepFailure(TransformCodes.MissingSource, $"The source '{pointer}' is missing.");
        }

        Absent(onMissing, root, target, state);
    }

    // ---- predicates ---------------------------------------------------------------------

    private static bool Holds(TransformPredicate predicate, JsonNode root, EvaluationState state)
        => predicate switch
        {
            ExistsPredicate exists => Read(root, exists.Pointer) is not null,
            ComparePredicate compare => Compare(root, compare, state),
            InPredicate member => Contains(root, member, state),
            NotPredicate negated => !Holds(negated.Inner, root, state),
            GroupPredicate group => string.Equals(group.Operator, "and", StringComparison.Ordinal)
                ? group.Children.All(child => Holds(child, root, state))
                : group.Children.Any(child => Holds(child, root, state)),
            _ => false,
        };

    private static bool Compare(JsonNode root, ComparePredicate compare, EvaluationState state)
    {
        if (Read(root, compare.Pointer) is not { } actual)
        {
            return false;
        }

        state.Touch();

        if (compare.Operator is "eq" or "neq")
        {
            bool equal = string.Equals(Serialize(actual), Serialize(compare.Value), StringComparison.Ordinal);
            return string.Equals(compare.Operator, "eq", StringComparison.Ordinal) ? equal : !equal;
        }

        if (Numeric(actual) is not { } left || Numeric(compare.Value) is not { } right)
        {
            return false;
        }

        return compare.Operator switch
        {
            "gt" => left > right,
            "lt" => left < right,
            "gte" => left >= right,
            "lte" => left <= right,
            _ => false,
        };
    }

    private static bool Contains(JsonNode root, InPredicate predicate, EvaluationState state)
    {
        if (Read(root, predicate.Pointer) is not { } actual)
        {
            return false;
        }

        state.Touch();
        string token = Serialize(actual);

        return predicate.Values.Any(value => string.Equals(Serialize(value), token, StringComparison.Ordinal));
    }

    /// <summary>The numeric reading of a node, or null when it has none.</summary>
    /// <remarks>
    /// A numeric string is read as a number so an ordering comparison against a value that
    /// arrived as text behaves the same as one against the same value as a number. The parse
    /// is invariant-culture, which is what keeps <c>"1.5"</c> from becoming fifteen on a host
    /// whose culture writes a decimal comma.
    /// </remarks>
    private static double? Numeric(JsonNode node)
    {
        if (node is not JsonValue value)
        {
            return null;
        }

        if (value.TryGetValue(out double number))
        {
            return number;
        }

        if (value.TryGetValue(out long integral))
        {
            return integral;
        }

        if (value.TryGetValue(out decimal exact))
        {
            return (double)exact;
        }

        if (value.TryGetValue(out string? text)
            && text is not null
            && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed))
        {
            return parsed;
        }

        return null;
    }

    // ---- conversion and templating ------------------------------------------------------

    private static JsonNode Coerce(JsonNode value, TransformConvertType to)
    {
        switch (to)
        {
            case TransformConvertType.String:
                if (value is JsonValue text && text.TryGetValue(out string? _))
                {
                    return value.DeepClone();
                }

                return JsonValue.Create(Text(value))!;

            case TransformConvertType.Number:
                if (value is JsonValue number)
                {
                    bool isText = number.TryGetValue(out string? literal);

                    if (!isText && number.TryGetValue(out double _))
                    {
                        // Already a number: the clone keeps the original token, so a value
                        // written 1.0 does not come back as 1.
                        return value.DeepClone();
                    }

                    if (isText
                        && literal is not null
                        && double.TryParse(literal, NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed))
                    {
                        return JsonValue.Create(parsed);
                    }

                    if (!isText && number.TryGetValue(out bool flag))
                    {
                        return JsonValue.Create(flag ? 1d : 0d);
                    }
                }

                throw new StepFailure(TransformCodes.ConvertFailed, "The value cannot be converted to a number.");

            case TransformConvertType.Boolean:
                if (value is JsonValue candidate)
                {
                    if (candidate.TryGetValue(out bool direct))
                    {
                        return JsonValue.Create(direct);
                    }

                    if (candidate.TryGetValue(out double numeric))
                    {
                        return JsonValue.Create(numeric != 0);
                    }

                    if (candidate.TryGetValue(out string? spelled))
                    {
                        if (string.Equals(spelled, "true", StringComparison.Ordinal))
                        {
                            return JsonValue.Create(true);
                        }

                        if (string.Equals(spelled, "false", StringComparison.Ordinal))
                        {
                            return JsonValue.Create(false);
                        }
                    }
                }

                throw new StepFailure(TransformCodes.ConvertFailed, "The value cannot be converted to a boolean.");

            default:
                throw new StepFailure(TransformCodes.ConvertFailed, "Unknown conversion target.");
        }
    }

    /// <summary>Renders a pattern, or null when a bound argument resolves to nothing.</summary>
    private static string? Render(TemplateStep template, JsonNode root, EvaluationState state)
    {
        var rendered = new StringBuilder();

        for (int index = 0; index < template.Pattern.Length; index++)
        {
            if (template.Pattern[index] != '{')
            {
                rendered.Append(template.Pattern[index]);
                continue;
            }

            int close = template.Pattern.IndexOf('}', index);

            if (close < 0)
            {
                // Tier 1 refuses this before a program is ever mounted. Reported rather than
                // thrown as an index error, because an evaluator that crashes on a pattern is
                // an evaluator whose behaviour depends on who validated it.
                throw new StepFailure(
                    TransformCodes.TemplatePattern,
                    "The pattern has an unterminated placeholder.");
            }

            string name = template.Pattern[(index + 1)..close];
            TemplateArgument? argument = template.Arguments
                .FirstOrDefault(declared => string.Equals(declared.Name, name, StringComparison.Ordinal));

            if (argument is null)
            {
                throw new StepFailure(
                    TransformCodes.TemplatePattern,
                    $"The placeholder '{{{name}}}' is not bound to a declared argument.");
            }

            if (Read(root, argument.Pointer) is not { } value)
            {
                return null;
            }

            rendered.Append(Text(value));
            state.Touch();
            index = close;
        }

        return rendered.ToString();
    }

    /// <summary>The textual reading of a scalar; the serialized form of a composite.</summary>
    private static string Text(JsonNode node)
    {
        if (node is JsonValue value)
        {
            return value.TryGetValue(out string? text) && text is not null
                ? text
                : value.ToJsonString().Trim('"');
        }

        return Serialize(node);
    }

    // ---- pointer mechanics ---------------------------------------------------------------

    private static string Join(string target, string name)
        => target + "/" + name.Replace("~", "~0", StringComparison.Ordinal).Replace("/", "~1", StringComparison.Ordinal);

    private static string[] Segments(string pointer)
        => pointer.Length == 0
            ? []
            : [.. pointer[1..]
                .Split('/')
                .Select(static segment => segment
                    .Replace("~1", "/", StringComparison.Ordinal)
                    .Replace("~0", "~", StringComparison.Ordinal))];

    /// <summary>Resolves a pointer, returning null when it addresses nothing.</summary>
    /// <remarks>
    /// A JSON null is nothing. An object member holding null and an array element holding null
    /// resolve the same way, because a caller asking whether a value is there gets one answer
    /// regardless of which container it sits in.
    /// </remarks>
    private static JsonNode? Read(JsonNode root, string pointer)
    {
        JsonNode current = root;

        foreach (string segment in Segments(pointer))
        {
            switch (current)
            {
                case JsonObject members:
                    if (!members.TryGetPropertyValue(segment, out JsonNode? next) || next is null)
                    {
                        return null;
                    }

                    current = next;
                    break;

                case JsonArray array when int.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, out int at):
                    if (at < 0 || at >= array.Count || array[at] is not { } element)
                    {
                        return null;
                    }

                    current = element;
                    break;

                default:
                    return null;
            }
        }

        return current;
    }

    /// <summary>
    /// Writes through the holder so the empty pointer replaces the working document.
    /// </summary>
    /// <remarks>
    /// Every write goes through here, including a write to the document root. The alternative —
    /// a parallel switch listing which operations may replace the root — decides the question
    /// per operation, and an operation added later is silently absent from that list rather
    /// than refused by it.
    /// </remarks>
    private static void Write(RootHolder root, string pointer, JsonNode? value, EvaluationState state)
    {
        string[] segments = Segments(pointer);
        state.Touch();

        if (segments.Length == 0)
        {
            root.Node = value ?? new JsonObject();
            return;
        }

        JsonNode current = root.Node;

        for (int index = 0; index < segments.Length - 1; index++)
        {
            string segment = segments[index];
            state.Touch();

            switch (current)
            {
                case JsonObject members:
                    if (!members.TryGetPropertyValue(segment, out JsonNode? child) || child is null)
                    {
                        child = new JsonObject();
                        members[segment] = child;
                        state.Touch();
                    }

                    current = child;
                    break;

                case JsonArray array
                    when int.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, out int at)
                        && at >= 0
                        && at < array.Count
                        && array[at] is { } element:
                    current = element;
                    break;

                default:
                    throw new StepFailure(
                        TransformCodes.StepFailed,
                        $"The target path '{pointer}' cannot be created: '{segment}' does not address a container.");
            }
        }

        string leaf = segments[^1];
        state.Touch();

        if (current is JsonObject target)
        {
            target[leaf] = value;
            return;
        }

        if (current is JsonArray sequence
            && int.TryParse(leaf, NumberStyles.None, CultureInfo.InvariantCulture, out int position)
            && position >= 0
            && position <= sequence.Count)
        {
            if (position == sequence.Count)
            {
                sequence.Add(value);
            }
            else
            {
                sequence[position] = value;
            }

            return;
        }

        throw new StepFailure(
            TransformCodes.StepFailed,
            $"The target path '{pointer}' does not address a writable container.");
    }

    private static void Remove(JsonNode root, string pointer, EvaluationState state)
    {
        string[] segments = Segments(pointer);

        if (segments.Length == 0)
        {
            return;
        }

        JsonNode current = root;

        for (int index = 0; index < segments.Length - 1; index++)
        {
            string segment = segments[index];
            state.Touch();

            switch (current)
            {
                case JsonObject members
                    when members.TryGetPropertyValue(segment, out JsonNode? child) && child is not null:
                    current = child;
                    break;

                case JsonArray array
                    when int.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, out int at)
                        && at >= 0
                        && at < array.Count
                        && array[at] is { } element:
                    current = element;
                    break;

                default:
                    return;
            }
        }

        string leaf = segments[^1];
        state.Touch();

        if (current is JsonObject owner && owner.ContainsKey(leaf))
        {
            owner.Remove(leaf);
            return;
        }

        if (current is JsonArray sequence
            && int.TryParse(leaf, NumberStyles.None, CultureInfo.InvariantCulture, out int position)
            && position >= 0
            && position < sequence.Count)
        {
            sequence.RemoveAt(position);
        }
    }

    // ---- accounting -----------------------------------------------------------------------

    private static int Depth(JsonNode node) => Depth(node, 0);

    private static int Depth(JsonNode node, int depth)
    {
        int worst = depth + 1;

        switch (node)
        {
            case JsonObject members:
                foreach ((string _, JsonNode? value) in members)
                {
                    if (value is not null)
                    {
                        worst = Math.Max(worst, Depth(value, depth + 1));
                    }
                }

                break;

            case JsonArray array:
                foreach (JsonNode? item in array)
                {
                    if (item is not null)
                    {
                        worst = Math.Max(worst, Depth(item, depth + 1));
                    }
                }

                break;
        }

        return worst;
    }

    /// <summary>Holds the working document so a root write can replace any kind of value.</summary>
    private sealed class RootHolder(JsonNode node)
    {
        internal JsonNode Node { get; set; } = node;
    }

    /// <summary>An abort raised inside a nested step list, with where inside it happened.</summary>
    private sealed record NestedAbort(TransformEvaluation Failure, string Place);

    /// <summary>Shared accounting across one evaluation, including every nested iteration.</summary>
    private sealed class EvaluationState(TransformLimits limits)
    {
        internal TransformLimits Limits { get; } = limits;

        internal int NodesTouched { get; private set; }

        internal int FanoutProcessed { get; private set; }

        private int _stepsExecuted;

        internal bool ConsumeStep()
        {
            _stepsExecuted++;
            return _stepsExecuted <= Limits.MaxSteps;
        }

        internal void ConsumeFanout() => FanoutProcessed++;

        internal void Touch() => NodesTouched++;
    }

    /// <summary>A step-level defect that aborts the evaluation with a declared code.</summary>
    private sealed class StepFailure(string code, string message) : Exception(message)
    {
        internal string Code { get; } = code;
    }
}
