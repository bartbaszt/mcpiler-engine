using System.Globalization;

using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;

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
        ValidateBindingOperationKeys(manifest, diagnostics);
        ValidateDestinations(manifest, diagnostics);
        ValidateCredentialSlots(manifest, diagnostics);
        ValidateSchemaReferences(manifest, diagnostics);
        ValidateDeclaredTools(manifest, diagnostics);

        return diagnostics;
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
    /// Credentials must address distinct slots, and a basic credential needs both halves.
    /// </summary>
    /// <remarks>
    /// Both checks exist because the applier iterates the declared credentials in order. A
    /// duplicate slot makes the value that reaches the upstream service depend on declaration
    /// order, and a basic credential missing one half produces a syntactically valid header
    /// carrying an empty user or an empty password — a silently wrong credential rather than a
    /// refusal.
    /// </remarks>
    private static void ValidateCredentialSlots(ManifestDocument manifest, List<ManifestDiagnostic> diagnostics)
    {
        IReadOnlyList<ManifestCredential> credentials = manifest.EffectiveCredentials.Credentials;
        Dictionary<string, int> seen = new(StringComparer.OrdinalIgnoreCase);

        for (int index = 0; index < credentials.Count; index++)
        {
            ManifestCredential credential = credentials[index];
            string destination = DestinationOf(credential);

            if (seen.TryGetValue(destination, out int first))
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.DuplicateCredentialSlot,
                    $"Credentials {first} and {index} both target '{DiagnosticText.Echo(destination)}'. " +
                    "Which value reaches the upstream service would depend on declaration order.",
                    section: ManifestSectionName.Credentials,
                    pointer: JsonPointer.Build("credentials", Segment(index), "slot")));
                continue;
            }

            seen[destination] = index;
        }

        ValidateBasicCredentialHalves(credentials, diagnostics);
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
