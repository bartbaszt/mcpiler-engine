using System.Text.Json.Nodes;

using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Transform;

/// <summary>
/// Enforces the exclusions that make the transformation model a security boundary rather than
/// a small language.
/// </summary>
/// <remarks>
/// <para>
/// Most of the seven excluded categories are closed by the grammar rather than by a check
/// here, and that is the stronger form. An expression string, a regular expression, a host
/// function, an <c>eval</c> operation, a sort with a locale and every ambient source are
/// refused because no member and no vocabulary entry carries them:
/// <see cref="TransformProgramReader"/> rejects the member with <c>E_UNKNOWN_FIELD</c> and
/// <see cref="StepVocabulary"/> rejects the operation with <c>E_UNKNOWN_OPERATION</c>. There
/// is nothing to disable, because there is nothing to enable.
/// </para>
/// <para>
/// What is left needs an actual check, because the grammar admits the member and only its
/// contents decide whether an exclusion is being attempted: the one pattern string in the
/// vocabulary, the two ways a program could try to manufacture or unwrap a file handle, and
/// the one header the request compiler owns.
/// </para>
/// </remarks>
internal static class ExclusionValidation
{
    /// <summary>The header a transformation may never write.</summary>
    /// <remarks>
    /// The content type is decided by the request compiler from the declared media type and,
    /// for multipart, from the boundary it generates. A program that set it would describe a
    /// body it did not produce, and the mismatch would be discovered by the upstream server.
    /// </remarks>
    internal const string ReservedHeader = "/headers/content-type";

    /// <summary>The schema keyword that marks an agent argument as a file slot.</summary>
    internal const string FileKeyword = "x-mcp-file";

    private const string PatternMember = "pattern";
    private const string ValueMember = "value";
    private const string SourceMember = "source";

    /// <summary>Reports every attempted escape in <paramref name="program"/>.</summary>
    /// <param name="program">The parsed program.</param>
    /// <param name="fileArguments">
    /// The agent argument names the operation declares as file slots, or empty when the
    /// operation declares no input schema.
    /// </param>
    /// <param name="findings">Where findings accumulate.</param>
    internal static void Validate(
        TransformProgram program,
        IReadOnlySet<string> fileArguments,
        ICollection<TransformFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(fileArguments);
        ArgumentNullException.ThrowIfNull(findings);

        foreach (WalkedStep walked in StepWalk.Descend(program.Steps))
        {
            switch (walked.Step)
            {
                case TemplateStep template:
                    ValidatePattern(template, walked, findings);
                    break;

                case SetConstantStep constant:
                    ValidateConstant(constant.Value, walked, findings);
                    break;

                case DefaultStep fallback:
                    ValidateConstant(fallback.Value, walked, findings);
                    break;

                case ConvertStep convert:
                    ValidateConvert(convert, walked, fileArguments, findings);
                    break;

                default:
                    break;
            }

            ValidateReservedHeader(walked, findings);
        }
    }

    /// <summary>
    /// A pattern is literal text and named placeholders bound to declared arguments.
    /// </summary>
    /// <remarks>
    /// Anything else is refused rather than ignored. An unrecognised placeholder left to
    /// render as literal text would make <c>{{now()}}</c> look like it had been considered and
    /// declined, when in fact nothing had looked at it; refusing states the boundary instead.
    /// </remarks>
    private static void ValidatePattern(
        TemplateStep template,
        WalkedStep walked,
        ICollection<TransformFinding> findings)
    {
        HashSet<string> declared = [.. template.Arguments.Select(static argument => argument.Name)];
        string pattern = template.Pattern;

        for (int index = 0; index < pattern.Length; index++)
        {
            if (pattern[index] != '{')
            {
                continue;
            }

            int close = pattern.IndexOf('}', index);

            if (close < 0)
            {
                findings.Add(new TransformFinding(
                    TransformCodes.TemplatePattern,
                    "The template pattern carries an unterminated placeholder. A pattern admits " +
                    "literal text and named placeholders bound to declared pointer arguments, and " +
                    "nothing else.",
                    walked.Index,
                    Extend(walked.Location, PatternMember)));
                return;
            }

            string name = pattern[(index + 1)..close];

            if (!declared.Contains(name))
            {
                findings.Add(new TransformFinding(
                    TransformCodes.TemplatePattern,
                    $"The template pattern carries the placeholder '{DiagnosticText.Echo(name)}', which " +
                    "is not bound to a declared pointer argument. A pattern admits literal text and " +
                    "named placeholders bound to declared pointer arguments, and nothing else.",
                    walked.Index,
                    Extend(walked.Location, PatternMember)));
                return;
            }

            index = close;
        }
    }

    /// <summary>A literal may not be a file handle.</summary>
    /// <remarks>
    /// Constructing a handle from a literal would let a program reference a file the caller
    /// never held. The shape is asked of the store that issues handles rather than restated
    /// here, so the two cannot drift into disagreeing about what a handle is.
    /// </remarks>
    private static void ValidateConstant(
        JsonNode value,
        WalkedStep walked,
        ICollection<TransformFinding> findings)
    {
        if (value is not JsonValue literal || !literal.TryGetValue(out string? text))
        {
            return;
        }

        if (!FileHandleStore.IsWellFormedId(text))
        {
            return;
        }

        findings.Add(new TransformFinding(
            TransformCodes.FileHandle,
            "A literal value has the shape of a file handle. A handle is issued to a caller and " +
            "moved by reference through 'fileRef'; it is never constructed by a program.",
            walked.Index,
            Extend(walked.Location, ValueMember)));
    }

    /// <summary>A file argument may not be coerced.</summary>
    /// <remarks>
    /// Coercing a handle to a string is how file content, or the reference to it, leaves the
    /// one path that accounts for it. <c>fileRef</c> is the only operation that touches a
    /// handle at all.
    /// </remarks>
    private static void ValidateConvert(
        ConvertStep convert,
        WalkedStep walked,
        IReadOnlySet<string> fileArguments,
        ICollection<TransformFinding> findings)
    {
        if (!AddressesFileArgument(convert.Source, fileArguments))
        {
            return;
        }

        findings.Add(new TransformFinding(
            TransformCodes.FileHandle,
            $"'convert' addresses '{DiagnosticText.Echo(convert.Source)}', which the operation declares " +
            $"as a file slot. Only 'fileRef' touches a file handle.",
            walked.Index,
            Extend(walked.Location, SourceMember)));
    }

    /// <summary>The content type is the request compiler's to decide.</summary>
    private static void ValidateReservedHeader(WalkedStep walked, ICollection<TransformFinding> findings)
    {
        foreach (string target in TargetsOf(walked.Step))
        {
            if (!target.StartsWith(ReservedHeader, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (target.Length != ReservedHeader.Length && target[ReservedHeader.Length] != '/')
            {
                continue;
            }

            findings.Add(new TransformFinding(
                TransformCodes.ContentTypeReserved,
                $"The step writes '{DiagnosticText.Echo(target)}'. The content type and any multipart " +
                "boundary are produced by request compilation from the declared media type, so a " +
                "program that wrote one would describe a body it did not produce.",
                walked.Index,
                walked.Location));
            return;
        }
    }

    /// <summary>Which agent arguments an input schema declares as file slots.</summary>
    internal static IReadOnlySet<string> FileArguments(JsonObject? inputSchema)
    {
        HashSet<string> names = new(StringComparer.Ordinal);

        if (inputSchema?["properties"] is not JsonObject properties)
        {
            return names;
        }

        foreach (KeyValuePair<string, JsonNode?> property in properties)
        {
            if (property.Value is JsonObject declared && declared[FileKeyword] is not null)
            {
                names.Add(property.Key);
            }
        }

        return names;
    }

    private static bool AddressesFileArgument(string pointer, IReadOnlySet<string> fileArguments)
    {
        if (fileArguments.Count == 0 || pointer.Length == 0 || pointer[0] != '/')
        {
            return false;
        }

        int next = pointer.IndexOf('/', 1);
        string root = next > 0 ? pointer[1..next] : pointer[1..];

        return fileArguments.Contains(JsonPointer.Unescape(root));
    }

    /// <summary>Every location the step writes.</summary>
    private static IEnumerable<string> TargetsOf(TransformStep step)
        => step switch
        {
            CopyStep s => [s.Target],
            MoveStep s => [s.Target],
            OmitStep s => [s.Target],
            PickStep s => [s.Target],
            NestStep s => [s.Target],
            FlattenStep s => [s.Target],
            FlattenArrayStep s => [s.Target],
            MergeStep s => [s.Target],
            SetConstantStep s => [s.Target],
            DefaultStep s => [s.Target],
            ConvertStep s => [s.Target],
            TemplateStep s => [s.Target],
            CoalesceStep s => [s.Target],
            EnumMapStep s => [s.Target],
            MapArrayStep s => [s.Target],
            MapObjectStep s => [s.Target],
            LimitArrayStep s => [s.Target],
            FileRefStep s => [s.Target],
            _ => [],
        };

    private static string Extend(string pointer, string token)
        => pointer + JsonPointer.Build(token);
}
