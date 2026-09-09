using System.Globalization;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads the <c>agentSurface</c> section: agent operations, groups and bindings.
/// </summary>
internal static class AgentSurfaceSectionReader
{
    internal static readonly string[] SectionMembers = ["formatVersion", "groups", "components", "operations"];

    internal static readonly string[] GroupMembers = ["name", "priority"];

    internal static readonly string[] OperationMembers =
    [
        "slug",
        "kind",
        "name",
        "summary",
        "description",
        "groups",
        "tags",
        "inputSchema",
        "outputSchema",
        "outputSchemaPolicy",
        "annotations",
        "risk",
        "search",
        "binding",
    ];

    internal static readonly string[] PolicyMembers = ["generate", "advertise", "useInternally"];

    internal static readonly string[] AnnotationMembers = ["readOnly", "destructive", "idempotent", "openWorld"];

    internal static readonly string[] SearchMembers = ["aliases", "keywords", "exampleIntents"];

    internal static readonly string[] HttpBindingMembers =
        ["type", "bindingId", "operation", "serverUrl", "credentialRef"];

    internal static readonly string[] HttpBaseMembers = ["operation", "serverUrl", "credentialRef"];

    // 'credentialRef' is deliberately absent from the transformed and compound member sets.
    // A transformation rewrites arguments and never changes which upstream identity executes,
    // so its scope belongs to 'base'; a compound binding delegates to steps that each carry
    // their own. Leaving the member out means the existing unknown-member refusal catches a
    // misplaced scope, which is stricter than accepting and ignoring it.
    internal static readonly string[] TransformedBindingMembers =
        ["type", "bindingId", "base", "inputProgram", "outputProgram"];

    internal static readonly string[] CompoundBindingMembers =
    [
        "type",
        "bindingId",
        "bindingVersion",
        "failurePolicy",
        "maxTotalResponseBytes",
        "workflowTimeoutSeconds",
        "steps",
        "outputSelection",
    ];

    internal static readonly string[] StepMembers =
        ["stepId", "operation", "inputMappings", "name", "summary", "inputProgram"];

    internal static readonly string[] MappingMembers = ["target", "argument", "fromStep", "response", "constant"];

    internal static readonly string[] OutputSelectionMembers = ["entries", "outputProgram"];

    private static readonly string[] BindingTypeNames =
        [HttpBinding.TypeName, TransformedHttpBinding.TypeName, CompoundBinding.TypeName];

    private static readonly string[] MappingSourceMembers = ["argument", "fromStep", "constant"];

    internal static AgentSurfaceSection? Read(JsonNode? document, SectionReadContext context)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, SectionMembers, string.Empty);
        context.VerifySectionFormatVersion(root, AgentSurfaceSection.FormatVersion);

        var groups = ReadGroups(root, context);
        var groupNames = new HashSet<string>(groups.Select(static group => group.Name), StringComparer.Ordinal);
        var operations = ReadOperations(root, groupNames, context);

        VerifyCompoundReferences(operations, context);

        return new AgentSurfaceSection(
            operations,
            groups,
            context.Object(root, "components", string.Empty));
    }

    private static IReadOnlyList<OperationGroupEntry> ReadGroups(
        JsonObject root,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(root, "groups", string.Empty);
        var groups = new List<OperationGroupEntry>(elements.Count);
        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, GroupMembers, pointer);

            var name = context.RequiredText(element, "name", pointer);

            if (name is null)
            {
                continue;
            }

            if (!names.Add(name))
            {
                context.Error(
                    ManifestDiagnosticCodes.UnknownGroup,
                    $"Group '{DiagnosticText.Echo(name)}' is declared more than once. The group join is by name, so a duplicate makes the priority ambiguous.",
                    SectionReadContext.Child(pointer, "name"));
                continue;
            }

            groups.Add(new OperationGroupEntry(name, context.Integer(element, "priority", pointer) ?? 0));
        }

        return groups;
    }

    private static IReadOnlyList<AgentOperationEntry> ReadOperations(
        JsonObject root,
        IReadOnlySet<string> groupNames,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(root, "operations", string.Empty);
        var operations = new List<AgentOperationEntry>(elements.Count);
        var slugs = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, OperationMembers, pointer);

            var slug = context.RequiredText(element, "slug", pointer);
            var name = context.RequiredText(element, "name", pointer);

            if (slug is null || name is null)
            {
                continue;
            }

            if (!slugs.Add(slug))
            {
                context.Error(
                    ManifestDiagnosticCodes.DuplicateAgentSlug,
                    $"Agent operation slug '{DiagnosticText.Echo(slug)}' is declared more than once.",
                    SectionReadContext.Child(pointer, "slug"));
                continue;
            }

            var binding = ReadBinding(element, pointer, slug, context);

            if (binding is null)
            {
                continue;
            }

            var kind = ReadKind(element, pointer, binding, context);

            if (kind is { Valid: false })
            {
                continue;
            }

            var groups = context.TextArray(element, "groups", pointer);

            foreach (var group in groups)
            {
                if (!groupNames.Contains(group))
                {
                    context.Error(
                        ManifestDiagnosticCodes.UnknownGroup,
                        $"Operation '{slug}' names group '{DiagnosticText.Echo(group)}', which the section does not declare.",
                        SectionReadContext.Child(pointer, "groups"));
                }
            }

            operations.Add(new AgentOperationEntry(
                slug,
                name,
                binding,
                kind?.Value,
                context.Text(element, "summary", pointer),
                context.Text(element, "description", pointer),
                groups,
                context.TextArray(element, "tags", pointer),
                ManifestSchema.FromOrNull(element["inputSchema"]),
                ManifestSchema.FromOrNull(element["outputSchema"]),
                ReadOutputSchemaPolicy(element, pointer, context),
                ReadAnnotations(element, pointer, context),
                context.Text(element, "risk", pointer),
                ReadSearchMetadata(element, pointer, context)));
        }

        return operations;
    }

    private static (AgentOperationKind Value, bool Valid)? ReadKind(
        JsonObject element,
        string pointer,
        ManifestBinding binding,
        SectionReadContext context)
    {
        if (element["kind"] is null)
        {
            return null;
        }

        var declared = context.Text(element, "kind", pointer);

        if (declared is null)
        {
            return (default, false);
        }

        if (!Vocabulary.TryReadOperationKind(declared, out var kind))
        {
            context.Error(
                ManifestDiagnosticCodes.KindBindingMismatch,
                $"'{DiagnosticText.Echo(declared)}' is not an operation kind. Expected one of: {DiagnosticText.List(Vocabulary.OperationKindNames)}.",
                SectionReadContext.Child(pointer, "kind"));
            return (default, false);
        }

        // Only the compound axis is checkable: source-backed and custom-http both execute
        // through an HTTP binding and differ solely in authoring provenance.
        var isCompoundBinding = binding is CompoundBinding;
        var isCompoundKind = kind is AgentOperationKind.Compound;

        if (isCompoundBinding != isCompoundKind)
        {
            context.Error(
                ManifestDiagnosticCodes.KindBindingMismatch,
                isCompoundKind
                    ? "Kind 'compound' requires a compound binding."
                    : $"A compound binding requires kind '{Vocabulary.Write(AgentOperationKind.Compound)}'.",
                SectionReadContext.Child(pointer, "kind"));
            return (default, false);
        }

        return (kind, true);
    }

    private static OutputSchemaPolicySettings? ReadOutputSchemaPolicy(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        var policy = context.Object(element, "outputSchemaPolicy", pointer);

        if (policy is null)
        {
            return null;
        }

        var policyPointer = SectionReadContext.Child(pointer, "outputSchemaPolicy");

        context.RejectUnknownMembers(policy, PolicyMembers, policyPointer);

        var advertise = OutputSchemaAdvertisement.Auto;
        var declared = context.Text(policy, "advertise", policyPointer);

        if (declared is not null && !Vocabulary.TryReadAdvertisement(declared, out advertise))
        {
            context.Error(
                ManifestDiagnosticCodes.UnknownMember,
                $"'{DiagnosticText.Echo(declared)}' is not an advertisement mode. Expected one of: {DiagnosticText.List(Vocabulary.AdvertisementNames)}.",
                SectionReadContext.Child(policyPointer, "advertise"));
            advertise = OutputSchemaAdvertisement.Auto;
        }

        return new OutputSchemaPolicySettings(
            context.Flag(policy, "generate", policyPointer, fallback: true),
            advertise,
            context.Flag(policy, "useInternally", policyPointer));
    }

    private static ToolAnnotations? ReadAnnotations(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        var annotations = context.Object(element, "annotations", pointer);

        if (annotations is null)
        {
            return null;
        }

        var annotationsPointer = SectionReadContext.Child(pointer, "annotations");

        context.RejectUnknownMembers(annotations, AnnotationMembers, annotationsPointer);

        return new ToolAnnotations(
            context.Flag(annotations, "readOnly", annotationsPointer),
            context.Flag(annotations, "destructive", annotationsPointer),
            context.Flag(annotations, "idempotent", annotationsPointer),
            context.Flag(annotations, "openWorld", annotationsPointer));
    }

    private static SearchMetadataEntry? ReadSearchMetadata(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        var search = context.Object(element, "search", pointer);

        if (search is null)
        {
            return null;
        }

        var searchPointer = SectionReadContext.Child(pointer, "search");

        context.RejectUnknownMembers(search, SearchMembers, searchPointer);

        return new SearchMetadataEntry(
            context.TextArray(search, "aliases", searchPointer),
            context.TextArray(search, "keywords", searchPointer),
            context.TextArray(search, "exampleIntents", searchPointer));
    }

    private static ManifestBinding? ReadBinding(
        JsonObject element,
        string pointer,
        string slug,
        SectionReadContext context)
    {
        var binding = context.Object(element, "binding", pointer);
        var bindingPointer = SectionReadContext.Child(pointer, "binding");

        if (binding is null)
        {
            if (element["binding"] is null)
            {
                context.Error(
                    ManifestDiagnosticCodes.MemberRequired,
                    $"Operation '{slug}' declares no binding, so it has no way to execute.",
                    bindingPointer);
            }

            return null;
        }

        var type = context.RequiredText(binding, "type", bindingPointer);

        if (type is null)
        {
            return null;
        }

        // The binding shape is read here and nowhere else. Every other component resolves the
        // executed operation through the dispatcher, so inspection and execution cannot
        // diverge the way a local type switch once let them.
        return type switch
        {
            HttpBinding.TypeName => ReadHttpBinding(binding, bindingPointer, slug, context),
            TransformedHttpBinding.TypeName => ReadTransformedBinding(binding, bindingPointer, slug, context),
            CompoundBinding.TypeName => ReadCompoundBinding(binding, bindingPointer, slug, context),
            _ => Unknown(type, bindingPointer, context),
        };

        static ManifestBinding? Unknown(string type, string bindingPointer, SectionReadContext context)
        {
            context.Error(
                ManifestDiagnosticCodes.BindingTypeUnknown,
                $"'{DiagnosticText.Echo(type)}' is not a binding type. Expected one of: {DiagnosticText.List(BindingTypeNames)}.",
                SectionReadContext.Child(bindingPointer, "type"));
            return null;
        }
    }

    private static ManifestBinding? ReadHttpBinding(
        JsonObject binding,
        string pointer,
        string slug,
        SectionReadContext context)
    {
        context.RejectUnknownMembers(binding, HttpBindingMembers, pointer);

        var operation = context.RequiredText(binding, "operation", pointer);

        if (operation is null)
        {
            return null;
        }

        return new HttpBinding(
            operation,
            ReadServerUrl(binding, pointer, context),
            context.TextArray(binding, "credentialRef", pointer))
        {
            BindingId = context.Text(binding, "bindingId", pointer) ?? slug,
        };
    }

    private static ManifestBinding? ReadTransformedBinding(
        JsonObject binding,
        string pointer,
        string slug,
        SectionReadContext context)
    {
        context.RejectUnknownMembers(binding, TransformedBindingMembers, pointer);

        var basePointer = SectionReadContext.Child(pointer, "base");
        var baseObject = context.Object(binding, "base", pointer);

        if (baseObject is null)
        {
            if (binding["base"] is null)
            {
                context.Error(
                    ManifestDiagnosticCodes.MemberRequired,
                    "A transformed binding requires a 'base' HTTP invocation.",
                    basePointer);
            }

            return null;
        }

        context.RejectUnknownMembers(baseObject, HttpBaseMembers, basePointer);

        var operation = context.RequiredText(baseObject, "operation", basePointer);

        if (operation is null)
        {
            return null;
        }

        return new TransformedHttpBinding(
            new HttpBinding(
                operation,
                ReadServerUrl(baseObject, basePointer, context),
                context.TextArray(baseObject, "credentialRef", basePointer)),
            // The program grammar is a separate versioned contract with its own validator and
            // its own diagnostic codes, so it is carried verbatim and validated separately.
            context.Object(binding, "inputProgram", pointer),
            context.Object(binding, "outputProgram", pointer))
        {
            BindingId = context.Text(binding, "bindingId", pointer) ?? slug,
        };
    }

    private static ManifestBinding? ReadCompoundBinding(
        JsonObject binding,
        string pointer,
        string slug,
        SectionReadContext context)
    {
        context.RejectUnknownMembers(binding, CompoundBindingMembers, pointer);

        var version = context.Integer(binding, "bindingVersion", pointer) ?? CompoundBindingVersions.Supported;

        if (version != CompoundBindingVersions.Supported)
        {
            context.Error(
                ManifestDiagnosticCodes.CompoundBindingVersionUnsupported,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Compound binding version {version} is not supported. This Engine implements version {CompoundBindingVersions.Supported}."),
                SectionReadContext.Child(pointer, "bindingVersion"));
            return null;
        }

        var failurePolicy = CompoundFailurePolicy.FailFast;
        var declaredPolicy = context.Text(binding, "failurePolicy", pointer);

        if (declaredPolicy is not null && !Vocabulary.TryReadFailurePolicy(declaredPolicy, out failurePolicy))
        {
            context.Error(
                ManifestDiagnosticCodes.UnknownMember,
                $"'{DiagnosticText.Echo(declaredPolicy)}' is not a failure policy. Expected one of: {DiagnosticText.List(Vocabulary.FailurePolicyNames)}.",
                SectionReadContext.Child(pointer, "failurePolicy"));
            return null;
        }

        var steps = ReadSteps(binding, pointer, context);

        if (steps.Count == 0)
        {
            context.Error(
                ManifestDiagnosticCodes.MemberRequired,
                "A compound binding requires at least one step.",
                SectionReadContext.Child(pointer, "steps"));
            return null;
        }

        var budget = context.Integer64(binding, "maxTotalResponseBytes", pointer);

        if (budget is { } bytes && !context.RequireAtLeast(bytes, 1, "maxTotalResponseBytes", pointer))
        {
            budget = null;
        }

        return new CompoundBinding(
            steps,
            version,
            failurePolicy,
            budget,
            context.Seconds(binding, "workflowTimeoutSeconds", pointer),
            ReadOutputSelection(binding, pointer, steps, context))
        {
            BindingId = context.Text(binding, "bindingId", pointer) ?? slug,
        };
    }

    private static IReadOnlyList<CompoundStepEntry> ReadSteps(
        JsonObject binding,
        string pointer,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(binding, "steps", pointer);
        var steps = new List<CompoundStepEntry>(elements.Count);
        var stepIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (element, elementPointer) in elements)
        {
            context.RejectUnknownMembers(element, StepMembers, elementPointer);

            var stepId = context.RequiredText(element, "stepId", elementPointer);
            var operation = context.RequiredText(element, "operation", elementPointer);

            if (stepId is null || operation is null)
            {
                continue;
            }

            if (stepIds.Contains(stepId))
            {
                context.Error(
                    ManifestDiagnosticCodes.DuplicateStepId,
                    $"Step identifier '{DiagnosticText.Echo(stepId)}' is declared more than once.",
                    SectionReadContext.Child(elementPointer, "stepId"));
                continue;
            }

            // The mappings are read against the steps declared *before* this one, so a step
            // can neither read its own response nor a later step's.
            var priorStepIds = new HashSet<string>(stepIds, StringComparer.Ordinal);

            stepIds.Add(stepId);

            steps.Add(new CompoundStepEntry(
                stepId,
                operation,
                ReadMappings(element, "inputMappings", elementPointer, priorStepIds, requestTargets: true, context),
                context.Text(element, "name", elementPointer),
                context.Text(element, "summary", elementPointer),
                context.Object(element, "inputProgram", elementPointer)));
        }

        return steps;
    }

    private static CompoundOutputSelection? ReadOutputSelection(
        JsonObject binding,
        string pointer,
        IReadOnlyList<CompoundStepEntry> steps,
        SectionReadContext context)
    {
        var selection = context.Object(binding, "outputSelection", pointer);

        if (selection is null)
        {
            return null;
        }

        var selectionPointer = SectionReadContext.Child(pointer, "outputSelection");

        context.RejectUnknownMembers(selection, OutputSelectionMembers, selectionPointer);

        var declaredSteps = new HashSet<string>(
            steps.Select(static step => step.StepId),
            StringComparer.Ordinal);

        var mappings = ReadMappings(
            selection,
            "entries",
            selectionPointer,
            declaredSteps,
            requestTargets: false,
            context);

        return new CompoundOutputSelection(
            [.. mappings.Select(static mapping => new CompoundOutputEntry(mapping.Target, mapping.Source))],
            context.Object(selection, "outputProgram", selectionPointer));
    }

    private static IReadOnlyList<StepInputMapping> ReadMappings(
        JsonObject parent,
        string member,
        string pointer,
        IReadOnlySet<string> knownStepIds,
        bool requestTargets,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(parent, member, pointer);
        var mappings = new List<StepInputMapping>(elements.Count);

        foreach (var (element, elementPointer) in elements)
        {
            context.RejectUnknownMembers(element, MappingMembers, elementPointer);

            var target = context.RequiredText(element, "target", elementPointer);

            if (target is null)
            {
                continue;
            }

            if (!JsonPointer.IsSyntacticallyValid(target))
            {
                context.Error(
                    ManifestDiagnosticCodes.PointerRootNotAllowed,
                    $"'{DiagnosticText.Echo(target)}' is not a valid JSON Pointer.",
                    SectionReadContext.Child(elementPointer, "target"));
                continue;
            }

            // A step target addresses a request scope; a workflow result target addresses a
            // free-form result document and is therefore unrestricted.
            if (requestTargets && !ManifestPointerRoots.IsRequestTarget(target))
            {
                context.Error(
                    ManifestDiagnosticCodes.PointerRootNotAllowed,
                    $"'{DiagnosticText.Echo(target)}' does not start at a request scope. Expected one of: {DiagnosticText.List(ManifestPointerRoots.RequestTargets)}.",
                    SectionReadContext.Child(elementPointer, "target"));
                continue;
            }

            if (ReadMappingSource(element, elementPointer, knownStepIds, context) is { } source)
            {
                mappings.Add(new StepInputMapping(target, source));
            }
        }

        return mappings;
    }

    private static MappingSource? ReadMappingSource(
        JsonObject element,
        string pointer,
        IReadOnlySet<string> knownStepIds,
        SectionReadContext context)
    {
        var declared = MappingSourceMembers.Where(member => element[member] is not null).ToList();

        if (declared.Count != 1)
        {
            context.Error(
                ManifestDiagnosticCodes.PointerRootNotAllowed,
                declared.Count == 0
                    ? $"A mapping must declare exactly one source: {DiagnosticText.List(MappingSourceMembers)}."
                    : $"A mapping declares {DiagnosticText.List(declared)}. Exactly one source is permitted.",
                pointer);
            return null;
        }

        switch (declared[0])
        {
            case "argument":
            {
                var argument = context.RequiredText(element, "argument", pointer);

                if (argument is null)
                {
                    return null;
                }

                if (!JsonPointer.IsSyntacticallyValid(argument))
                {
                    context.Error(
                        ManifestDiagnosticCodes.PointerRootNotAllowed,
                        $"'{DiagnosticText.Echo(argument)}' is not a valid JSON Pointer.",
                        SectionReadContext.Child(pointer, "argument"));
                    return null;
                }

                return MappingSource.FromArgument(argument);
            }

            case "fromStep":
            {
                var fromStep = context.RequiredText(element, "fromStep", pointer);
                var response = context.RequiredText(element, "response", pointer);

                if (fromStep is null || response is null)
                {
                    return null;
                }

                // Only an already-declared step can be read, so a workflow cannot depend on a
                // response that does not exist yet.
                if (!knownStepIds.Contains(fromStep))
                {
                    context.Error(
                        ManifestDiagnosticCodes.StepReferenceUnknown,
                        $"'{DiagnosticText.Echo(fromStep)}' is not a step declared before this point.",
                        SectionReadContext.Child(pointer, "fromStep"));
                    return null;
                }

                if (!ManifestPointerRoots.IsResponseSource(response))
                {
                    context.Error(
                        ManifestDiagnosticCodes.PointerRootNotAllowed,
                        $"'{DiagnosticText.Echo(response)}' does not start at a response scope. Expected one of: {DiagnosticText.List(ManifestPointerRoots.ResponseSources)}.",
                        SectionReadContext.Child(pointer, "response"));
                    return null;
                }

                return MappingSource.FromStepResponse(fromStep, response);
            }

            default:
                if (element["response"] is not null)
                {
                    context.Error(
                        ManifestDiagnosticCodes.PointerRootNotAllowed,
                        "'response' applies only to a 'fromStep' source.",
                        SectionReadContext.Child(pointer, "response"));
                    return null;
                }

                return MappingSource.FromConstant(element["constant"]!.DeepClone());
        }
    }

    /// <summary>
    /// Reads a per-operation server override.
    /// </summary>
    /// <remarks>
    /// The override is still fully subject to the policy origin allow-list, so it can narrow
    /// where one operation goes but can never widen the perimeter.
    /// </remarks>
    private static string? ReadServerUrl(JsonObject binding, string pointer, SectionReadContext context)
    {
        var declared = context.Text(binding, "serverUrl", pointer);

        if (declared is null)
        {
            return null;
        }

        if (!Uri.TryCreate(declared, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            context.Error(
                ManifestDiagnosticCodes.BaseUrlInvalid,
                $"'serverUrl' must be an absolute http or https URL, but '{DiagnosticText.Echo(declared)}' was declared.",
                SectionReadContext.Child(pointer, "serverUrl"));
            return null;
        }

        return declared;
    }

    private static void VerifyCompoundReferences(
        IReadOnlyList<AgentOperationEntry> operations,
        SectionReadContext context)
    {
        var byslug = operations.ToDictionary(
            static operation => operation.Slug,
            static operation => operation,
            StringComparer.Ordinal);

        for (var index = 0; index < operations.Count; index++)
        {
            if (operations[index].Binding is not CompoundBinding compound)
            {
                continue;
            }

            var pointer = "/operations/" + index.ToString(CultureInfo.InvariantCulture) + "/binding/steps";

            for (var step = 0; step < compound.Steps.Count; step++)
            {
                var stepPointer = pointer + "/" + step.ToString(CultureInfo.InvariantCulture) + "/operation";
                var target = compound.Steps[step].Operation;

                if (!byslug.TryGetValue(target, out var referenced))
                {
                    context.Error(
                        ManifestDiagnosticCodes.CompoundStepUnknownOperation,
                        $"Step '{compound.Steps[step].StepId}' references operation '{DiagnosticText.Echo(target)}', which the section does not declare.",
                        stepPointer);
                    continue;
                }

                if (referenced.Binding is CompoundBinding)
                {
                    context.Error(
                        ManifestDiagnosticCodes.CompoundNested,
                        $"Step '{compound.Steps[step].StepId}' references compound operation '{target}'. Compound nesting is forbidden.",
                        stepPointer);
                }
            }
        }
    }
}
