using System.Globalization;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Transform;

/// <summary>
/// Reads a transformation program document into the typed model, refusing anything the closed
/// envelope and the closed step vocabulary do not define.
/// </summary>
/// <remarks>
/// <para>
/// The reader never throws for a document defect. A program arrives inside a manifest bundle
/// that may have been hand-authored, copied, edited or produced by a third party, so every
/// member is read through an accessor that reports the wrong JSON type as a finding instead of
/// asking the node for a value it does not hold. A reader that throws on <c>"op": 5</c> turns a
/// validation result into a crash, and a crash at load is indistinguishable from a bug in the
/// loader.
/// </para>
/// <para>
/// Nested step lists keep the top-level step index and extend the pointer. Reporting a nested
/// finding under the nested list's own index would name a step that exists at the top level and
/// is not the one at fault, which is worse than naming nothing.
/// </para>
/// </remarks>
internal static class TransformProgramReader
{
    /// <summary>The envelope's complete member set.</summary>
    private static readonly string[] EnvelopeMembers =
        ["transformVersion", "direction", "base", "limits", "steps"];

    /// <summary>The limits block's complete member set.</summary>
    private static readonly string[] LimitsMembers =
        ["maxSteps", "maxDepth", "maxNodes", "maxOutputBytes", "maxArrayFanout"];

    /// <summary>The comparison operators a predicate may carry.</summary>
    private static readonly string[] Comparisons = ["eq", "neq", "gt", "lt", "gte", "lte"];

    /// <summary>The connectives a predicate group may carry.</summary>
    private static readonly string[] Connectives = ["and", "or"];

    /// <summary>The closed condition vocabulary, for the message that reports leaving it.</summary>
    private static readonly string[] PredicateVocabulary =
        ["exists", "eq", "neq", "in", "gt", "lt", "gte", "lte", "and", "or", "not"];

    /// <summary>A template argument's complete member set.</summary>
    private static readonly string[] TemplateArgumentMembers = ["name", PointerMember];

    /// <summary>An enum mapping's complete member set.</summary>
    private static readonly string[] EnumMappingMembers = ["from", "to"];

    private const string VersionMember = "transformVersion";
    private const string DirectionMember = "direction";
    private const string BaseMember = "base";
    private const string LimitsMember = "limits";
    private const string StepsMember = "steps";
    private const string ElseStepsMember = "elseSteps";
    private const string OpMember = "op";
    private const string PointerMember = "pointer";

    private const string InputName = "input";
    private const string OutputName = "output";
    private const string PassthroughName = "passthrough";
    private const string EmptyName = "empty";

    /// <summary>Reads <paramref name="document"/>, returning the program or the reasons it is not one.</summary>
    internal static (TransformProgram? Program, IReadOnlyList<TransformFinding> Findings) Read(JsonObject document)
    {
        ArgumentNullException.ThrowIfNull(document);

        List<TransformFinding> findings = [];

        // The version gate runs before anything else is interpreted. A later grammar may give
        // an existing member a different meaning, so reading one under the wrong version would
        // report confident findings about a document this build cannot read.
        if (!TryInteger(document, VersionMember, out int version))
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                "The 'transformVersion' member is missing or is not an integer.",
                Pointer: Pointer(VersionMember)));
            return (null, findings);
        }

        if (version != TransformProgram.SupportedVersion)
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnsupportedVersion,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"transformVersion {version} is not supported; this build implements {TransformProgram.SupportedVersion}."),
                Pointer: Pointer(VersionMember)));
            return (null, findings);
        }

        Unknown(document, EnvelopeMembers, step: null, prefix: string.Empty, "program envelope", findings);

        TransformDirection? direction = Text(document, DirectionMember) switch
        {
            InputName => TransformDirection.Input,
            OutputName => TransformDirection.Output,
            _ => null,
        };

        if (direction is null)
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                $"The direction must be \"{InputName}\" or \"{OutputName}\".",
                Pointer: Pointer(DirectionMember)));
        }

        TransformBase? baseline = Text(document, BaseMember) switch
        {
            PassthroughName => TransformBase.Passthrough,
            EmptyName => TransformBase.Empty,
            _ => null,
        };

        if (baseline is null)
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                $"The base must be \"{PassthroughName}\" or \"{EmptyName}\".",
                Pointer: Pointer(BaseMember)));
        }

        TransformLimits? limits = ReadLimits(document[LimitsMember] as JsonObject, findings);
        IReadOnlyList<TransformStep> steps = ReadStepList(
            document[StepsMember],
            step: null,
            Pointer(StepsMember),
            findings);

        if (findings.Count > 0 || direction is null || baseline is null || limits is null)
        {
            return (null, findings);
        }

        return (
            new TransformProgram(version, direction.Value, baseline.Value, limits, steps),
            findings);
    }

    private static TransformLimits? ReadLimits(JsonObject? limits, List<TransformFinding> findings)
    {
        if (limits is null)
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                "The 'limits' block is required; a program declaring no bound is refused.",
                Pointer: Pointer(LimitsMember)));
            return null;
        }

        Unknown(limits, LimitsMembers, step: null, Pointer(LimitsMember), "limits block", findings);

        bool complete = true;

        int Bound(string member)
        {
            if (TryInteger(limits, member, out int value) && value >= 1)
            {
                return value;
            }

            findings.Add(new TransformFinding(
                TransformCodes.MissingBound,
                $"The limit '{member}' must be declared as a positive integer.",
                Pointer: Pointer(LimitsMember, member)));
            complete = false;
            return 0;
        }

        long Output()
        {
            if (TryLong(limits, "maxOutputBytes", out long value) && value >= 1)
            {
                return value;
            }

            findings.Add(new TransformFinding(
                TransformCodes.MissingBound,
                "The limit 'maxOutputBytes' must be declared as a positive integer.",
                Pointer: Pointer(LimitsMember, "maxOutputBytes")));
            complete = false;
            return 0;
        }

        int steps = Bound("maxSteps");
        int depth = Bound("maxDepth");
        int nodes = Bound("maxNodes");
        long output = Output();
        int fanout = Bound("maxArrayFanout");

        return complete ? new TransformLimits(steps, depth, nodes, output, fanout) : null;
    }

    private static IReadOnlyList<TransformStep> ReadStepList(
        JsonNode? node,
        int? step,
        string pointer,
        List<TransformFinding> findings)
    {
        if (node is not JsonArray array)
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                "A step list is required and must be an array.",
                step,
                pointer));
            return [];
        }

        List<TransformStep> steps = [];

        for (int index = 0; index < array.Count; index++)
        {
            string entry = Extend(pointer, index);

            if (array[index] is not JsonObject element)
            {
                findings.Add(new TransformFinding(
                    TransformCodes.UnknownField,
                    "A step must be an object.",
                    step ?? index,
                    entry));
                continue;
            }

            if (ReadStep(element, step ?? index, entry, findings) is { } parsed)
            {
                steps.Add(parsed);
            }
        }

        return steps;
    }

    private static TransformStep? ReadStep(
        JsonObject node,
        int step,
        string pointer,
        List<TransformFinding> findings)
    {
        string? name = Text(node, OpMember);

        if (!StepVocabulary.TryRead(name, out TransformOperation operation))
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnknownOperation,
                $"The operation '{DiagnosticText.Echo(name)}' is not in the closed vocabulary. " +
                $"Expected one of: {DiagnosticText.List(StepVocabulary.Names)}.",
                step,
                Extend(pointer, OpMember)));
            return null;
        }

        var reader = new StepReader(node, step, pointer, name!, findings);

        switch (operation)
        {
            case TransformOperation.Copy:
                reader.Members("source", "target", "onMissing");
                return new CopyStep(reader.Required("source"), reader.Required("target"), reader.OnMissing());

            case TransformOperation.Move:
                reader.Members("source", "target", "onMissing");
                return new MoveStep(reader.Required("source"), reader.Required("target"), reader.OnMissing());

            case TransformOperation.Omit:
                reader.Members("target");
                return new OmitStep(reader.Required("target"));

            case TransformOperation.Pick:
                reader.Members("source", "members", "target", "onMissing");
                return new PickStep(
                    reader.Required("source"),
                    reader.Strings("members"),
                    reader.Required("target"),
                    reader.OnMissing());

            case TransformOperation.Nest:
                reader.Members("source", "name", "target", "onMissing");
                return new NestStep(
                    reader.Required("source"),
                    reader.Required("name"),
                    reader.Required("target"),
                    reader.OnMissing());

            case TransformOperation.Flatten:
                reader.Members("source", "target", "onMissing");
                return new FlattenStep(reader.Required("source"), reader.Required("target"), reader.OnMissing());

            case TransformOperation.FlattenArray:
                reader.Members("source", "target", "onMissing");
                return new FlattenArrayStep(reader.Required("source"), reader.Required("target"), reader.OnMissing());

            case TransformOperation.Merge:
                reader.Members("sources", "target", "onMissing");
                return new MergeStep(reader.Strings("sources"), reader.Required("target"), reader.OnMissing());

            case TransformOperation.SetConstant:
                return ReadConstant(reader, fallback: false);

            case TransformOperation.Default:
                return ReadConstant(reader, fallback: true);

            case TransformOperation.Convert:
                return ReadConvert(reader);

            case TransformOperation.Template:
                return ReadTemplate(reader);

            case TransformOperation.Coalesce:
                reader.Members("sources", "target");
                return new CoalesceStep(reader.Strings("sources"), reader.Required("target"));

            case TransformOperation.EnumMap:
                return ReadEnumMap(reader);

            case TransformOperation.MapArray:
                return ReadMapArray(reader, findings);

            case TransformOperation.MapObject:
                return ReadMapObject(reader, findings);

            case TransformOperation.LimitArray:
                return ReadLimitArray(reader);

            case TransformOperation.When:
                return ReadWhen(reader, findings);

            case TransformOperation.FileRef:
                reader.Members("source", "target", "onMissing");
                return new FileRefStep(reader.Required("source"), reader.Required("target"), reader.OnMissing());

            default:
                return null;
        }
    }

    private static TransformStep? ReadConstant(StepReader reader, bool fallback)
    {
        reader.Members("target", "value");

        if (reader.Node("value") is not { } value)
        {
            reader.Missing("value");
            return null;
        }

        string target = reader.Required("target");

        return fallback ? new DefaultStep(target, value) : new SetConstantStep(target, value);
    }

    private static TransformStep? ReadConvert(StepReader reader)
    {
        reader.Members("source", "target", "to", "onMissing");

        TransformConvertType? to = reader.Text("to") switch
        {
            "string" => TransformConvertType.String,
            "number" => TransformConvertType.Number,
            "boolean" => TransformConvertType.Boolean,
            _ => null,
        };

        if (to is null)
        {
            reader.Reject(
                TransformCodes.UnknownField,
                "The convert target type must be \"string\", \"number\" or \"boolean\".",
                "to");
            return null;
        }

        return new ConvertStep(
            reader.Required("source"),
            reader.Required("target"),
            to.Value,
            reader.OnMissing());
    }

    private static TransformStep? ReadTemplate(StepReader reader)
    {
        reader.Members("target", "pattern", "arguments", "onMissing");

        List<TemplateArgument> arguments = [];

        if (reader.Node("arguments") is not JsonArray declared)
        {
            reader.Reject(TransformCodes.UnknownField, "The template arguments must be an array.", "arguments");
            return null;
        }

        for (int index = 0; index < declared.Count; index++)
        {
            if (declared[index] is JsonObject argument
                && Text(argument, "name") is { Length: > 0 } argumentName
                && Text(argument, PointerMember) is { } argumentPointer)
            {
                Unknown(
                    argument,
                    TemplateArgumentMembers,
                    reader.Step,
                    Extend(Extend(reader.Location, "arguments"), index),
                    "template argument",
                    reader.Findings);

                arguments.Add(new TemplateArgument(argumentName, argumentPointer));
                continue;
            }

            reader.Findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                "A template argument requires a non-empty 'name' and a 'pointer'.",
                reader.Step,
                Extend(Extend(reader.Location, "arguments"), index)));
        }

        return new TemplateStep(
            reader.Required("target"),
            reader.Required("pattern"),
            arguments,
            reader.OnMissing());
    }

    private static TransformStep? ReadEnumMap(StepReader reader)
    {
        reader.Members("source", "target", "mappings", "onMissing");

        List<EnumMapping> mappings = [];

        if (reader.Node("mappings") is not JsonArray declared)
        {
            reader.Reject(TransformCodes.UnknownField, "The enum mappings must be an array.", "mappings");
            return null;
        }

        for (int index = 0; index < declared.Count; index++)
        {
            string pointer = Extend(Extend(reader.Location, "mappings"), index);

            if (declared[index] is JsonObject mapping
                && mapping["from"] is { } from
                && mapping["to"] is { } to)
            {
                Unknown(mapping, EnumMappingMembers, reader.Step, pointer, "enum mapping", reader.Findings);
                mappings.Add(new EnumMapping(from.DeepClone(), to.DeepClone()));
                continue;
            }

            reader.Findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                "An enum mapping requires 'from' and 'to'.",
                reader.Step,
                pointer));
        }

        return new EnumMapStep(
            reader.Required("source"),
            reader.Required("target"),
            mappings,
            reader.OnMissing());
    }

    private static TransformStep? ReadMapArray(StepReader reader, List<TransformFinding> findings)
    {
        reader.Members("source", "target", "maxItems", StepsMember, "onMissing");

        if (!reader.Bound("maxItems", out int maxItems))
        {
            return null;
        }

        return new MapArrayStep(
            reader.Required("source"),
            reader.Required("target"),
            maxItems,
            ReadStepList(reader.Node(StepsMember), reader.Step, Extend(reader.Location, StepsMember), findings),
            reader.OnMissing());
    }

    private static TransformStep? ReadMapObject(StepReader reader, List<TransformFinding> findings)
    {
        reader.Members("source", "target", "maxEntries", StepsMember, "onMissing");

        if (!reader.Bound("maxEntries", out int maxEntries))
        {
            return null;
        }

        return new MapObjectStep(
            reader.Required("source"),
            reader.Required("target"),
            maxEntries,
            ReadStepList(reader.Node(StepsMember), reader.Step, Extend(reader.Location, StepsMember), findings),
            reader.OnMissing());
    }

    private static TransformStep? ReadLimitArray(StepReader reader)
    {
        reader.Members("source", "target", "maxItems", "onMissing");

        return reader.Bound("maxItems", out int maxItems)
            ? new LimitArrayStep(
                reader.Required("source"),
                reader.Required("target"),
                maxItems,
                reader.OnMissing())
            : null;
    }

    private static TransformStep? ReadWhen(StepReader reader, List<TransformFinding> findings)
    {
        reader.Members("condition", StepsMember, ElseStepsMember);

        TransformPredicate? condition = ReadPredicate(
            reader.Node("condition"),
            reader.Step,
            Extend(reader.Location, "condition"),
            findings);

        if (condition is null)
        {
            return null;
        }

        return new WhenStep(
            condition,
            ReadStepList(reader.Node(StepsMember), reader.Step, Extend(reader.Location, StepsMember), findings),
            reader.Node(ElseStepsMember) is null
                ? []
                : ReadStepList(
                    reader.Node(ElseStepsMember),
                    reader.Step,
                    Extend(reader.Location, ElseStepsMember),
                    findings));
    }

    /// <summary>
    /// Reads a closed predicate object.
    /// </summary>
    /// <remarks>
    /// Every branch closes its member set. Admitting an unknown member beside a recognised one
    /// would let a program carry an unread parameter that looks operative, which is exactly the
    /// shape an expression escape takes: a member nothing validates and some later
    /// implementation decides to honour.
    /// </remarks>
    private static TransformPredicate? ReadPredicate(
        JsonNode? node,
        int step,
        string pointer,
        List<TransformFinding> findings)
    {
        if (node is JsonValue value && value.TryGetValue(out string? _))
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                "A 'when' condition must be a closed predicate object, never a string. A string " +
                "condition would be an expression language, which the exclusions forbid.",
                step,
                pointer));
            return null;
        }

        if (node is not JsonObject predicate)
        {
            findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                "A 'when' condition must be a predicate object.",
                step,
                pointer));
            return null;
        }

        if (predicate.Count == 1 && predicate.ContainsKey("exists"))
        {
            if (Text(predicate, "exists") is not { } existing)
            {
                findings.Add(Malformed("The 'exists' predicate requires a pointer.", step, pointer));
                return null;
            }

            return new ExistsPredicate(existing);
        }

        if (predicate.Count == 1 && predicate.ContainsKey("not"))
        {
            TransformPredicate? inner = ReadPredicate(
                predicate["not"],
                step,
                Extend(pointer, "not"),
                findings);

            return inner is null ? null : new NotPredicate(inner);
        }

        foreach (string connective in Connectives)
        {
            if (!predicate.ContainsKey(connective))
            {
                continue;
            }

            if (predicate.Count != 1 || predicate[connective] is not JsonArray children || children.Count == 0)
            {
                findings.Add(Malformed(
                    $"The '{connective}' predicate requires a non-empty array of predicates and no other member.",
                    step,
                    Extend(pointer, connective)));
                return null;
            }

            List<TransformPredicate> parsed = [];

            for (int index = 0; index < children.Count; index++)
            {
                TransformPredicate? child = ReadPredicate(
                    children[index],
                    step,
                    Extend(Extend(pointer, connective), index),
                    findings);

                if (child is null)
                {
                    return null;
                }

                parsed.Add(child);
            }

            return new GroupPredicate(connective, parsed);
        }

        foreach (string comparison in Comparisons)
        {
            if (!predicate.ContainsKey(comparison))
            {
                continue;
            }

            if (predicate.Count != 2 || predicate[comparison] is not { } operand)
            {
                findings.Add(Malformed(
                    $"The '{comparison}' predicate carries exactly the operator and a 'pointer'.",
                    step,
                    pointer));
                return null;
            }

            if (Text(predicate, PointerMember) is not { } target)
            {
                findings.Add(Malformed($"The '{comparison}' predicate requires a 'pointer'.", step, pointer));
                return null;
            }

            return new ComparePredicate(comparison, target, operand.DeepClone());
        }

        if (predicate.ContainsKey("in"))
        {
            if (predicate.Count != 2 || predicate["in"] is not JsonArray admitted)
            {
                findings.Add(Malformed(
                    "The 'in' predicate carries exactly an array of values and a 'pointer'.",
                    step,
                    pointer));
                return null;
            }

            if (Text(predicate, PointerMember) is not { } target)
            {
                findings.Add(Malformed("The 'in' predicate requires a 'pointer'.", step, pointer));
                return null;
            }

            return new InPredicate(
                target,
                [.. admitted.Where(static entry => entry is not null).Select(static entry => entry!.DeepClone())]);
        }

        findings.Add(Malformed(
            $"The predicate is not part of the closed condition vocabulary: {DiagnosticText.List(PredicateVocabulary)}.",
            step,
            pointer));
        return null;
    }

    private static TransformFinding Malformed(string message, int step, string pointer)
        => new(TransformCodes.UnknownField, message, step, pointer);

    private static void Unknown(
        JsonObject node,
        string[] known,
        int? step,
        string prefix,
        string what,
        List<TransformFinding> findings)
    {
        foreach (KeyValuePair<string, JsonNode?> member in node)
        {
            if (known.Contains(member.Key, StringComparer.Ordinal))
            {
                continue;
            }

            findings.Add(new TransformFinding(
                TransformCodes.UnknownField,
                $"The member '{DiagnosticText.Echo(member.Key)}' is not part of the {what}.",
                step,
                Extend(prefix, member.Key)));
        }
    }

    private static string Pointer(params string[] tokens) => Manifest.Loading.JsonPointer.Build(tokens);

    private static string Extend(string pointer, string token)
        => pointer + Manifest.Loading.JsonPointer.Build(token);

    private static string Extend(string pointer, int index)
        => Extend(pointer, index.ToString(CultureInfo.InvariantCulture));

    private static string? Text(JsonObject node, string member)
        => node[member] is JsonValue value && value.TryGetValue(out string? text) ? text : null;

    /// <summary>
    /// Reads an integral member, accepting either integral backing.
    /// </summary>
    /// <remarks>
    /// A <see cref="JsonValue"/> parsed from text is backed by a <c>JsonElement</c> and widens
    /// on request; one constructed in memory is backed by the CLR type it was given and does
    /// not. Asking for only one of the two would make the same document valid when it arrives
    /// as bytes and invalid when it is built, which is a difference no author could see.
    /// </remarks>
    private static bool TryInteger(JsonObject node, string member, out int number)
    {
        if (node[member] is JsonValue value)
        {
            if (value.TryGetValue(out int parsed))
            {
                number = parsed;
                return true;
            }

            if (value.TryGetValue(out long widened) && widened is >= int.MinValue and <= int.MaxValue)
            {
                number = (int)widened;
                return true;
            }
        }

        number = 0;
        return false;
    }

    /// <inheritdoc cref="TryInteger"/>
    private static bool TryLong(JsonObject node, string member, out long number)
    {
        if (node[member] is JsonValue value)
        {
            if (value.TryGetValue(out long parsed))
            {
                number = parsed;
                return true;
            }

            if (value.TryGetValue(out int narrowed))
            {
                number = narrowed;
                return true;
            }
        }

        number = 0;
        return false;
    }

    /// <summary>Reads one step's members against that step's closed member set.</summary>
    private sealed class StepReader(
        JsonObject node,
        int step,
        string location,
        string operation,
        List<TransformFinding> findings)
    {
        /// <summary>The top-level step index this step belongs to.</summary>
        internal int Step => step;

        /// <summary>The pointer to this step.</summary>
        internal string Location => location;

        /// <summary>Where findings accumulate.</summary>
        internal List<TransformFinding> Findings => findings;

        /// <summary>Rejects every member outside this step's closed set.</summary>
        internal void Members(params string[] allowed)
            => Unknown(node, [OpMember, .. allowed], step, location, $"'{operation}' step", findings);

        /// <summary>Reads a required string member, reporting its absence.</summary>
        internal string Required(string member)
        {
            if (TransformProgramReader.Text(node, member) is { } value)
            {
                return value;
            }

            Missing(member);
            return string.Empty;
        }

        /// <summary>Reads an optional string member.</summary>
        internal string? Text(string member) => TransformProgramReader.Text(node, member);

        /// <summary>Reads a raw member.</summary>
        internal JsonNode? Node(string member) => node[member]?.DeepClone();

        /// <summary>Reads a mandatory positive bound.</summary>
        internal bool Bound(string member, out int value)
        {
            if (TryInteger(node, member, out value) && value >= 1)
            {
                return true;
            }

            findings.Add(new TransformFinding(
                TransformCodes.MissingBound,
                $"'{operation}' requires an explicit positive '{member}' bound.",
                step,
                Extend(location, member)));
            return false;
        }

        /// <summary>Reads the missing-source policy, which defaults to skipping.</summary>
        internal TransformOnMissing OnMissing()
            => TransformProgramReader.Text(node, "onMissing") switch
            {
                "null" => TransformOnMissing.Null,
                "error" => TransformOnMissing.Error,
                _ => TransformOnMissing.Skip,
            };

        /// <summary>Reads a string array member.</summary>
        internal IReadOnlyList<string> Strings(string member)
        {
            if (node[member] is not JsonArray array)
            {
                Reject(TransformCodes.UnknownField, $"The member '{member}' must be an array of strings.", member);
                return [];
            }

            List<string> values = [];

            for (int index = 0; index < array.Count; index++)
            {
                if (array[index] is JsonValue value && value.TryGetValue(out string? text))
                {
                    values.Add(text);
                    continue;
                }

                findings.Add(new TransformFinding(
                    TransformCodes.UnknownField,
                    $"Every entry of '{member}' must be a string.",
                    step,
                    Extend(Extend(location, member), index)));
            }

            return values;
        }

        /// <summary>Reports a required member as absent.</summary>
        internal void Missing(string member)
            => Reject(TransformCodes.UnknownField, $"The member '{member}' is required.", member);

        /// <summary>Reports a finding located at one of this step's members.</summary>
        internal void Reject(string code, string message, string member)
            => findings.Add(new TransformFinding(code, message, step, Extend(location, member)));
    }
}
