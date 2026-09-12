using System.Globalization;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Transform;

namespace MCPiler.Engine.Manifest.Validation;

/// <summary>
/// Validates the invariants that span more than one manifest section.
/// </summary>
/// <remarks>
/// <para>
/// Single-section invariants belong to the section readers, which reject them while they still
/// know the exact JSON pointer. What is left here is genuinely cross-section: a reference from
/// one section into another, and a check whose bound comes from a different section than the
/// value it constrains.
/// </para>
/// <para>
/// The validator returns <em>every</em> diagnostic rather than the first, because for a
/// hand-authored manifest the validator is the authoring tool. Reporting one problem per run
/// would turn writing a manifest into a guessing loop.
/// </para>
/// </remarks>
public static class ManifestValidator
{
    /// <summary>
    /// Returns every cross-section problem in <paramref name="manifest"/>.
    /// </summary>
    public static IReadOnlyList<ManifestDiagnostic> Validate(ManifestDocument manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        List<ManifestDiagnostic> diagnostics = [];

        ValidateSurfaceOperations(manifest, diagnostics);
        ValidateCompoundExposure(manifest, diagnostics);
        ValidateBindingOperationKeys(manifest, diagnostics);
        ValidateDestinations(manifest, diagnostics);
        ValidateCredentialIdentity(manifest, diagnostics);
        ValidateBindingCredentialScope(manifest, diagnostics);
        ValidateCredentialReachability(manifest, diagnostics);
        ValidateSchemaReferences(manifest, diagnostics);
        ValidateDeclaredTools(manifest, diagnostics);
        ValidateTransformPrograms(manifest, diagnostics);

        return diagnostics;
    }

    /// <summary>
    /// Every transformation program the manifest carries passes Tier-1 validation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A program is a separately versioned document that arrives inside an artifact this
    /// process did not author, so it is checked here rather than trusted. The refusal is
    /// <see cref="ManifestDiagnosticCodes.TransformInvalid"/> and it carries the program
    /// grammar's own code, because one manifest code covering twelve distinct defects would
    /// tell an operator only that something is wrong somewhere.
    /// </para>
    /// <para>
    /// The ceiling comes from the narrowed policy, which is the policy this deployment will
    /// actually enforce. Measuring a static estimate against the manifest's unnarrowed values
    /// would pass a program the evaluator then aborts on.
    /// </para>
    /// </remarks>
    private static void ValidateTransformPrograms(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        TransformCeiling declared = manifest.Policy.EffectiveTransformCeiling;
        var ceiling = new TransformCeilingValues(
            declared.MaxSteps,
            declared.MaxDepth,
            declared.MaxNodes,
            declared.MaxOutputBytes,
            declared.MaxArrayFanout);

        for (int index = 0; index < manifest.AgentSurface.Operations.Count; index++)
        {
            AgentOperationEntry operation = manifest.AgentSurface.Operations[index];
            IReadOnlySet<string> files = ExclusionValidation.FileArguments(operation.InputSchema?.Object);
            string binding = JsonPointer.Build("operations", Segment(index), "binding");

            foreach ((string member, JsonObject program, TransformDirection direction) in ProgramsOf(operation.Binding))
            {
                foreach (TransformFinding finding in TransformValidation.Validate(program, ceiling, files, direction))
                {
                    diagnostics.Add(new ManifestDiagnostic(
                        ManifestDiagnosticCodes.TransformInvalid,
                        DiagnosticSeverity.Error,
                        Located(finding),
                        ManifestSectionName.AgentSurface,
                        binding + member + finding.Pointer)
                    {
                        ProgramCode = finding.Code,
                    });
                }
            }
        }
    }

    /// <summary>Prefixes the step index onto a program finding's message.</summary>
    /// <remarks>
    /// The index is what every criterion asks a refusal to name and what the author counts in.
    /// It is stated rather than left to be read out of the pointer, because the pointer locates
    /// the offending member and those are not always the same depth.
    /// </remarks>
    private static string Located(TransformFinding finding)
        => finding.Step is { } step
            ? string.Create(CultureInfo.InvariantCulture, $"Step {step}: {finding.Message}")
            : finding.Message;

    /// <summary>
    /// Every transformation program a binding carries, with the pointer from the binding to it.
    /// </summary>
    /// <remarks>
    /// The pointer is assembled token by token rather than written as one string with slashes
    /// in it. A slash inside a reference token is escaped, so a path written as text arrives as
    /// a single member name nobody declared and the diagnostic points nowhere.
    /// </remarks>
    private static IEnumerable<(string Pointer, JsonObject Program, TransformDirection Direction)> ProgramsOf(
        ManifestBinding binding)
    {
        switch (binding)
        {
            case TransformedHttpBinding transformed:
                if (transformed.InputProgram is { } input)
                {
                    yield return (JsonPointer.Build("inputProgram"), input, TransformDirection.Input);
                }

                if (transformed.OutputProgram is { } output)
                {
                    yield return (JsonPointer.Build("outputProgram"), output, TransformDirection.Output);
                }

                break;

            case CompoundBinding compound:
                for (int index = 0; index < compound.Steps.Count; index++)
                {
                    if (compound.Steps[index].InputProgram is { } step)
                    {
                        yield return (
                            JsonPointer.Build("steps", Segment(index), "inputProgram"),
                            step,
                            TransformDirection.Input);
                    }
                }

                if (compound.OutputSelection?.OutputProgram is { } selection)
                {
                    yield return (
                        JsonPointer.Build("outputSelection", "outputProgram"),
                        selection,
                        TransformDirection.Output);
                }

                break;

            default:
                break;
        }
    }

    /// <summary>
    /// A pinned tool set must be internally consistent and must address the surfaces and
    /// operations the rest of the manifest declares.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Whether a pinned set agrees with derivation is a separate question answered when a
    /// surface is actually advertised, because that comparison needs the derivation itself.
    /// What is checked here is the part that is wrong regardless of derivation: a name the
    /// protocol cannot carry, two tools competing for one name, a tool set addressed to a
    /// surface that does not exist, and a tool claiming to back an operation the surface does
    /// not expose directly.
    /// </para>
    /// <para>
    /// A tool with no backing operation is legal only under the reserved Navigator prefix.
    /// Without that rule an unbacked tool is indistinguishable from an operation tool whose
    /// binding was lost, and the two need opposite responses.
    /// </para>
    /// </remarks>
    private static void ValidateDeclaredTools(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        if (manifest.Tools is not { } section)
        {
            return;
        }

        foreach ((string surfaceSlug, SurfaceToolSet set) in section.Surfaces.OrderBy(static entry => entry.Key, StringComparer.Ordinal))
        {
            string surfacePointer = JsonPointer.Build("surfaces", surfaceSlug);
            ManifestSurface? surface = manifest.Server.Surface(surfaceSlug);

            if (surface is null)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.ToolSurfaceUnknown,
                    $"A tool set is declared for surface '{DiagnosticText.Echo(surfaceSlug)}', which the " +
                    $"'{ManifestSectionName.Server}' section does not declare.",
                    section: ManifestSectionName.Tools,
                    pointer: surfacePointer));
                continue;
            }

            for (int index = 0; index < set.Tools.Count; index++)
            {
                ManifestTool tool = set.Tools[index];

                // Name shape, name uniqueness, and the Navigator naming rule are decided by
                // the tools reader, which sees the declared document. Repeating them here
                // would mean one invariant with two enforcement points, and the reader drops
                // an offending tool, so the copy would never even run.
                if (tool.Operation is not { } slug)
                {
                    continue;
                }

                if (surface.ExposureOf(slug) != OperationExposure.Direct)
                {
                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.ToolOperationUnknown,
                        $"Tool '{DiagnosticText.Echo(tool.Name)}' backs operation '{DiagnosticText.Echo(slug)}', " +
                        $"which surface '{DiagnosticText.Echo(surfaceSlug)}' does not expose directly. Advertising " +
                        "it would grant through the tool list what the exposure list withheld.",
                        section: ManifestSectionName.Tools,
                        pointer: JsonPointer.Build("surfaces", surfaceSlug, "tools", Segment(index), "operation")));
                }
            }
        }
    }

    /// <summary>
    /// Every operation a surface exposes must be declared in the agent surface.
    /// </summary>
    /// <remarks>
    /// A surface entry naming an undeclared slug is not a harmless stale reference: exposure
    /// is the single invocation authority, so the entry claims to grant access to something
    /// that does not exist. Refusing it keeps that authority meaningful.
    /// </remarks>
    private static void ValidateSurfaceOperations(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        HashSet<string> declared = new(
            manifest.AgentSurface.Operations.Select(static operation => operation.Slug),
            StringComparer.Ordinal);

        for (int surfaceIndex = 0; surfaceIndex < manifest.Server.Surfaces.Count; surfaceIndex++)
        {
            ManifestSurface surface = manifest.Server.Surfaces[surfaceIndex];

            for (int entryIndex = 0; entryIndex < surface.Operations.Count; entryIndex++)
            {
                SurfaceOperation entry = surface.Operations[entryIndex];

                if (declared.Contains(entry.Operation))
                {
                    continue;
                }

                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SurfaceOperationUnknown,
                    $"Surface '{DiagnosticText.Echo(surface.Slug)}' exposes operation " +
                    $"'{DiagnosticText.Echo(entry.Operation)}', which the '{ManifestSectionName.AgentSurface}' " +
                    "section does not declare.",
                    section: ManifestSectionName.Server,
                    pointer: JsonPointer.Build("surfaces", Segment(surfaceIndex), "operations", Segment(entryIndex), "operation")));
            }
        }
    }

    /// <summary>
    /// A workflow may not reach an operation the surface that publishes it withholds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Exposure is per surface, so the question is too: the same workflow may be legitimate on
    /// one surface and a tunnel on another, and the answer belongs to the surface that
    /// publishes it rather than to the manifest as a whole. A workflow no surface publishes is
    /// not asked about at all, because there is nowhere it can be invoked from.
    /// </para>
    /// <para>
    /// Only an explicit exclusion is refused. A surface's operation list is a selection, and an
    /// operation simply not on it was never considered for that surface; <c>hidden</c> is the
    /// author stating that this operation was considered and withheld. Refusing an omission as
    /// well would mean a workflow could never be assembled from anything the surface does not
    /// also publish individually, which no requirement asks for.
    /// </para>
    /// </remarks>
    private static void ValidateCompoundExposure(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        for (int surfaceIndex = 0; surfaceIndex < manifest.Server.Surfaces.Count; surfaceIndex++)
        {
            ManifestSurface surface = manifest.Server.Surfaces[surfaceIndex];

            for (int entryIndex = 0; entryIndex < surface.Operations.Count; entryIndex++)
            {
                SurfaceOperation published = surface.Operations[entryIndex];

                if (published.Exposure == OperationExposure.Hidden
                    || manifest.AgentSurface.Operation(published.Operation) is not { } compound
                    || ManifestBindingDispatcher.TryResolveCompoundSteps(compound.Binding) is not { } steps)
                {
                    continue;
                }

                for (int stepIndex = 0; stepIndex < steps.Count; stepIndex++)
                {
                    CompoundStepEntry step = steps[stepIndex];

                    if (surface.ExposureOf(step.Operation) != OperationExposure.Hidden)
                    {
                        continue;
                    }

                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.CompoundStepExcluded,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"Compound operation '{DiagnosticText.Echo(published.Operation)}' reaches operation " +
                            $"'{DiagnosticText.Echo(step.Operation)}' at step {stepIndex} ('{DiagnosticText.Echo(step.StepId)}'), " +
                            $"which surface '{DiagnosticText.Echo(surface.Slug)}' excludes. A composition may not widen a perimeter."),
                        section: ManifestSectionName.Server,
                        pointer: JsonPointer.Build("surfaces", Segment(surfaceIndex), "operations", Segment(entryIndex), "operation")));
                }
            }
        }
    }

    /// <summary>
    /// Every HTTP execution key a binding names must exist in the operations section.
    /// </summary>
    /// <remarks>
    /// The key is resolved through the same accessor execution uses, and a transformed binding
    /// is resolved through its base rather than by re-deriving a key from the agent operation.
    /// A capability or security check that re-derived the key locally is exactly how a
    /// transformation once slipped a file upload past a profile without file support.
    /// </remarks>
    private static void ValidateBindingOperationKeys(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        for (int index = 0; index < manifest.AgentSurface.Operations.Count; index++)
        {
            AgentOperationEntry operation = manifest.AgentSurface.Operations[index];
            string pointer = JsonPointer.Build("operations", Segment(index), "binding");

            if (ManifestBindingDispatcher.TryResolveHttp(operation.Binding) is not { } http)
            {
                continue;
            }

            if (manifest.Operations.Operation(http.Operation) is not null)
            {
                continue;
            }

            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.BindingOperationKeyUnknown,
                $"Operation '{DiagnosticText.Echo(operation.Slug)}' binds execution key " +
                $"'{DiagnosticText.Echo(http.Operation)}', which the '{ManifestSectionName.Operations}' " +
                "section does not declare.",
                section: ManifestSectionName.AgentSurface,
                pointer: pointer));
        }
    }

    /// <summary>
    /// Every compiled destination must lie inside the compiled perimeter.
    /// </summary>
    /// <remarks>
    /// The origin allow-list is enforced on every request, so a destination outside it means
    /// the affected operations fail closed on every call. Reporting that at load turns a
    /// runtime mystery into an authoring error, and it is reported even though the fail-closed
    /// behavior is itself correct.
    /// </remarks>
    private static void ValidateDestinations(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        HashSet<string> perimeter = new(manifest.Policy.AllowedOrigins, StringComparer.OrdinalIgnoreCase);
        string baseOrigin = PolicySection.OriginOf(manifest.Policy.BaseUrl);

        if (!perimeter.Contains(baseOrigin))
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.DestinationNotAllowed,
                $"The base URL origin '{DiagnosticText.Echo(baseOrigin)}' is not in the allowed-origin " +
                $"perimeter {DiagnosticText.List(manifest.Policy.AllowedOrigins)}, so every request " +
                "without a per-operation server URL is refused.",
                section: ManifestSectionName.Policy,
                pointer: JsonPointer.Build("baseUrl")));
        }

        for (int index = 0; index < manifest.AgentSurface.Operations.Count; index++)
        {
            AgentOperationEntry operation = manifest.AgentSurface.Operations[index];

            if (ManifestBindingDispatcher.TryResolveHttp(operation.Binding) is not { ServerUrl: { } serverUrl })
            {
                continue;
            }

            // A malformed server URL is already reported by the section reader, so skipping it
            // here reports one defect once rather than the same typo twice.
            if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out Uri? parsed) || parsed is null)
            {
                continue;
            }

            string origin = PolicySection.OriginOf(parsed);

            if (perimeter.Contains(origin))
            {
                continue;
            }

            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.DestinationNotAllowed,
                $"Operation '{DiagnosticText.Echo(operation.Slug)}' routes to origin " +
                $"'{DiagnosticText.Echo(origin)}', which is not in the allowed-origin perimeter " +
                $"{DiagnosticText.List(manifest.Policy.AllowedOrigins)}. A per-operation server URL " +
                "narrows the destination but can never widen the perimeter.",
                section: ManifestSectionName.AgentSurface,
                pointer: JsonPointer.Build("operations", Segment(index), "binding", "serverUrl")));
        }
    }

    /// <summary>
    /// Credential ids must be unique, and a basic credential needs both halves declared.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identity is a section property and is checked here. Destination contention is not: two
    /// credentials may legitimately target one slot when no single binding authorizes both,
    /// which is how one manifest addresses two upstreams that each expect an
    /// <c>Authorization</c> header. That check therefore moved to
    /// <see cref="ValidateBindingCredentialScope"/>, where the executing binding is known.
    /// </para>
    /// <para>
    /// The basic-halves check stays at section level because a half-declared pair is unusable
    /// by every binding, not just by one: sending one half produces a syntactically valid
    /// header carrying an empty user or an empty password, a silently wrong credential rather
    /// than a refusal.
    /// </para>
    /// </remarks>
    private static void ValidateCredentialIdentity(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        IReadOnlyList<ManifestCredential> credentials = manifest.EffectiveCredentials.Credentials;
        Dictionary<string, int> seen = new(StringComparer.Ordinal);

        for (int index = 0; index < credentials.Count; index++)
        {
            ManifestCredential credential = credentials[index];

            if (seen.TryGetValue(credential.Id, out int first))
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.DuplicateCredentialId,
                    $"Credentials {first} and {index} both declare the id " +
                    $"'{DiagnosticText.Echo(credential.Id)}'. Every reference to it would be " +
                    "ambiguous, and resolving it by position would let declaration order decide " +
                    "which secret an operation sends.",
                    section: ManifestSectionName.Credentials,
                    pointer: JsonPointer.Build("credentials", Segment(index), "id")));
                continue;
            }

            seen[credential.Id] = index;
        }

        ValidateBasicCredentialHalves(credentials, diagnostics);
    }

    /// <summary>
    /// Every credential an operation references must exist, must not contend with another
    /// reference of the same operation, and must carry both halves of a basic pair.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Scope is resolved through <see cref="ManifestBindingDispatcher.CredentialRefsOf"/> and
    /// never by a local type test, so the set inspected here is exactly the set an invocation
    /// would apply. A gate that resolved a different binding than execution is the defect that
    /// rule exists to prevent.
    /// </para>
    /// <para>
    /// A reference list is treated as a set: naming one id twice is harmless because the
    /// resolved credential is the same one, so it is accepted rather than reported.
    /// </para>
    /// </remarks>
    private static void ValidateBindingCredentialScope(
        ManifestDocument manifest,
        List<ManifestDiagnostic> diagnostics)
    {
        IReadOnlyList<ManifestCredential> credentials = manifest.EffectiveCredentials.Credentials;
        IReadOnlyList<AgentOperationEntry> operations = manifest.AgentSurface.Operations;
        Dictionary<string, ManifestCredential> byId = new(StringComparer.Ordinal);

        foreach (ManifestCredential credential in credentials)
        {
            byId.TryAdd(credential.Id, credential);
        }

        for (int index = 0; index < operations.Count; index++)
        {
            AgentOperationEntry operation = operations[index];
            IReadOnlyList<string> refs = ManifestBindingDispatcher.CredentialRefsOf(operation.Binding);

            if (refs.Count == 0)
            {
                continue;
            }

            Dictionary<string, string> destinations = new(StringComparer.OrdinalIgnoreCase);
            HashSet<string> resolved = new(StringComparer.Ordinal);

            for (int refIndex = 0; refIndex < refs.Count; refIndex++)
            {
                string reference = refs[refIndex];

                if (!byId.TryGetValue(reference, out ManifestCredential? credential))
                {
                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.BindingCredentialRefUnknown,
                        $"Operation '{DiagnosticText.Echo(operation.Slug)}' references credential " +
                        $"'{DiagnosticText.Echo(reference)}', which the credentials section does not " +
                        "declare. The operation would send nothing where a secret was intended.",
                        section: ManifestSectionName.AgentSurface,
                        pointer: JsonPointer.Build(
                            "operations",
                            Segment(index),
                            "binding",
                            "credentialRef",
                            Segment(refIndex))));
                    continue;
                }

                if (!resolved.Add(reference))
                {
                    continue;
                }

                string destination = DestinationOf(credential);

                if (destinations.TryGetValue(destination, out string? first))
                {
                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.DuplicateCredentialSlot,
                        $"Operation '{DiagnosticText.Echo(operation.Slug)}' references credentials " +
                        $"'{DiagnosticText.Echo(first)}' and '{DiagnosticText.Echo(reference)}', which " +
                        $"both target '{DiagnosticText.Echo(destination)}'. Which value reaches the " +
                        "upstream service would depend on reference order.",
                        section: ManifestSectionName.AgentSurface,
                        pointer: JsonPointer.Build(
                            "operations",
                            Segment(index),
                            "binding",
                            "credentialRef",
                            Segment(refIndex))));
                    continue;
                }

                destinations[destination] = reference;
            }

            ValidateBasicPairIsComplete(operation, index, resolved, byId, diagnostics);
        }
    }

    /// <summary>
    /// An operation that references one half of a basic pair must reference the other.
    /// </summary>
    private static void ValidateBasicPairIsComplete(
        AgentOperationEntry operation,
        int index,
        HashSet<string> resolved,
        Dictionary<string, ManifestCredential> byId,
        List<ManifestDiagnostic> diagnostics)
    {
        bool hasUsername = false;
        bool hasPassword = false;

        foreach (string reference in resolved)
        {
            ManifestCredential credential = byId[reference];

            if (credential.Scheme is not CredentialScheme.Basic)
            {
                continue;
            }

            hasUsername |= string.Equals(
                credential.Slot,
                ManifestCredential.BasicUsernameSlot,
                StringComparison.Ordinal);
            hasPassword |= string.Equals(
                credential.Slot,
                ManifestCredential.BasicPasswordSlot,
                StringComparison.Ordinal);
        }

        if (hasUsername == hasPassword)
        {
            return;
        }

        string missing = hasUsername
            ? ManifestCredential.BasicPasswordSlot
            : ManifestCredential.BasicUsernameSlot;

        diagnostics.Add(ManifestDiagnostic.Error(
            ManifestDiagnosticCodes.BindingCredentialBasicIncomplete,
            $"Operation '{DiagnosticText.Echo(operation.Slug)}' references one half of a basic " +
            $"credential pair but not the '{missing}' half. Sending one half would produce a " +
            "well-formed header carrying an empty value rather than failing.",
            section: ManifestSectionName.AgentSurface,
            pointer: JsonPointer.Build("operations", Segment(index), "binding", "credentialRef")));
    }

    /// <summary>
    /// Reports a declared credential that no operation references.
    /// </summary>
    /// <remarks>
    /// A warning rather than a refusal: declaring a credential ahead of the operation that will
    /// use it is legitimate. It is worth reporting because the likelier cause is an operation
    /// that was meant to be authenticated and is not, and the fail-safe default makes that
    /// mistake silent at the wire.
    /// </remarks>
    private static void ValidateCredentialReachability(
        ManifestDocument manifest,
        List<ManifestDiagnostic> diagnostics)
    {
        IReadOnlyList<ManifestCredential> credentials = manifest.EffectiveCredentials.Credentials;

        if (credentials.Count == 0)
        {
            return;
        }

        HashSet<string> referenced = new(StringComparer.Ordinal);

        foreach (AgentOperationEntry operation in manifest.AgentSurface.Operations)
        {
            foreach (string reference in ManifestBindingDispatcher.CredentialRefsOf(operation.Binding))
            {
                referenced.Add(reference);
            }
        }

        for (int index = 0; index < credentials.Count; index++)
        {
            if (referenced.Contains(credentials[index].Id))
            {
                continue;
            }

            diagnostics.Add(ManifestDiagnostic.Warning(
                ManifestDiagnosticCodes.CredentialUnreferenced,
                $"Credential '{DiagnosticText.Echo(credentials[index].Id)}' is referenced by no " +
                "operation, so it is never applied. An operation that was meant to be " +
                "authenticated sends an unauthenticated request.",
                section: ManifestSectionName.Credentials,
                pointer: JsonPointer.Build("credentials", Segment(index), "id")));
        }
    }

    private static void ValidateBasicCredentialHalves(
        IReadOnlyList<ManifestCredential> credentials,
        List<ManifestDiagnostic> diagnostics)
    {
        List<ManifestCredential> basic = [.. credentials.Where(static credential => credential.Scheme == CredentialScheme.Basic)];

        if (basic.Count == 0)
        {
            return;
        }

        bool hasUsername = basic.Exists(static credential =>
            string.Equals(credential.Slot, ManifestCredential.BasicUsernameSlot, StringComparison.Ordinal));
        bool hasPassword = basic.Exists(static credential =>
            string.Equals(credential.Slot, ManifestCredential.BasicPasswordSlot, StringComparison.Ordinal));

        if (hasUsername && hasPassword)
        {
            return;
        }

        string missing = hasUsername ? ManifestCredential.BasicPasswordSlot : ManifestCredential.BasicUsernameSlot;

        diagnostics.Add(ManifestDiagnostic.Error(
            ManifestDiagnosticCodes.CredentialSlotInvalid,
            $"A basic credential is declared but the '{missing}' slot is missing. Sending one half " +
            "would produce a well-formed header carrying an empty value rather than failing.",
            section: ManifestSectionName.Credentials,
            pointer: JsonPointer.Build("credentials")));
    }

    /// <summary>
    /// Validates every schema reference against the bounds the policy section declares.
    /// </summary>
    /// <remarks>
    /// This is cross-section by construction: the schemas live in <c>operations</c> and
    /// <c>agentSurface</c> while the anti-amplification bounds live in <c>policy</c>. Running
    /// it eagerly here — rather than only lazily during execution — is what turns a reference
    /// bomb into a load-time refusal instead of a first-request failure.
    /// </remarks>
    private static void ValidateSchemaReferences(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        SchemaBounds bounds = manifest.Policy.EffectiveSchemaBounds;

        if (manifest.OperationsDocument is { } operationsDocument)
        {
            SchemaReferenceResolver resolver = new(operationsDocument, bounds);

            for (int index = 0; index < manifest.Operations.Operations.Count; index++)
            {
                ValidateOperationSchemas(
                    manifest.Operations.Operations[index],
                    resolver,
                    Pointer("operations", index),
                    diagnostics);
            }
        }

        if (manifest.AgentSurfaceDocument is { } agentDocument)
        {
            SchemaReferenceResolver resolver = new(agentDocument, bounds);

            for (int index = 0; index < manifest.AgentSurface.Operations.Count; index++)
            {
                AgentOperationEntry operation = manifest.AgentSurface.Operations[index];
                string pointer = Pointer("operations", index);

                Collect(resolver, operation.InputSchema, ManifestSectionName.AgentSurface, pointer + "/inputSchema", diagnostics);
                Collect(resolver, operation.OutputSchema, ManifestSectionName.AgentSurface, pointer + "/outputSchema", diagnostics);
            }
        }
    }

    private static void ValidateOperationSchemas(
        ManifestOperation operation,
        SchemaReferenceResolver resolver,
        string pointer,
        List<ManifestDiagnostic> diagnostics)
    {
        for (int index = 0; index < operation.Parameters.Count; index++)
        {
            ManifestParameter parameter = operation.Parameters[index];
            string parameterPointer = pointer + Pointer("parameters", index);

            Collect(resolver, parameter.Schema, ManifestSectionName.Operations, parameterPointer + "/schema", diagnostics);
            CollectContent(resolver, parameter.Content, parameterPointer + "/content", diagnostics);
        }

        if (operation.RequestBody is { } body)
        {
            CollectContent(resolver, body.Content, pointer + "/requestBody/content", diagnostics);
        }

        foreach ((string status, ManifestResponse response) in operation.Responses)
        {
            CollectContent(
                resolver,
                response.Content,
                pointer + "/responses/" + JsonPointer.Escape(status) + "/content",
                diagnostics);
        }
    }

    private static string Pointer(string member, int index)
        => JsonPointer.Build(member, Segment(index));

    private static string Segment(int index) => index.ToString(CultureInfo.InvariantCulture);

    private static void CollectContent(
        SchemaReferenceResolver resolver,
        IReadOnlyDictionary<string, ManifestMediaType>? content,
        string pointer,
        List<ManifestDiagnostic> diagnostics)
    {
        if (content is null)
        {
            return;
        }

        foreach ((string mediaType, ManifestMediaType declared) in content)
        {
            string mediaPointer = pointer + "/" + JsonPointer.Escape(mediaType);

            Collect(resolver, declared.Schema, ManifestSectionName.Operations, mediaPointer + "/schema", diagnostics);
            Collect(resolver, declared.ItemSchema, ManifestSectionName.Operations, mediaPointer + "/itemSchema", diagnostics);
        }
    }

    private static void Collect(
        SchemaReferenceResolver resolver,
        ManifestSchema? schema,
        string section,
        string pointer,
        List<ManifestDiagnostic> diagnostics)
    {
        if (schema is null)
        {
            return;
        }

        diagnostics.AddRange(resolver.Validate(schema, section, pointer));
    }

    private static string DestinationOf(ManifestCredential credential) => credential.Scheme switch
    {
        CredentialScheme.Basic => "basic:" + credential.Slot,
        CredentialScheme.Bearer => "header:" + credential.Slot,
        CredentialScheme.Header => "header:" + credential.Slot,
        _ => Vocabulary.Write(credential.EffectiveLocation) + ":" + credential.Slot,
    };
}
