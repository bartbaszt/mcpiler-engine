using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads the <c>credentials</c> section: credential slots holding value references.
/// </summary>
/// <remarks>
/// No diagnostic produced here may echo a secret. The inline variant deliberately reports
/// only its shape, because a reader that helpfully quotes the offending value is exactly how
/// a secret reaches a log file.
/// </remarks>
internal static class CredentialsSectionReader
{
    internal static readonly string[] SectionMembers = ["formatVersion", "credentials"];

    internal static readonly string[] CredentialMembers = ["id", "scheme", "slot", "location", "value"];

    internal static readonly string[] ValueMembers = ["fromEnv", "fromFile", "fromProvider", "inline"];

    /// <summary>The longest accepted provider key.</summary>
    /// <remarks>
    /// The key is opaque to Engine: Platform generates it and the managed envelope carries the
    /// matching value. The bound only keeps a hostile manifest from dragging an unbounded
    /// token through every diagnostic that echoes it.
    /// </remarks>
    internal const int MaxProviderKeyLength = 200;

    internal static CredentialsSection? Read(
        JsonNode? document,
        SectionReadContext context,
        bool allowInlineSecrets,
        bool allowProviderReferences)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, SectionMembers, string.Empty);
        context.VerifySectionFormatVersion(root, CredentialsSection.FormatVersion);

        var elements = context.ObjectArray(root, "credentials", string.Empty);
        var credentials = new List<ManifestCredential>(elements.Count);

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, CredentialMembers, pointer);

            var id = context.RequiredText(element, "id", pointer);

            if (id is null)
            {
                continue;
            }

            if (!ManifestCredential.IsValidId(id))
            {
                context.Error(
                    ManifestDiagnosticCodes.CredentialIdInvalid,
                    $"'{DiagnosticText.Echo(id)}' is not a credential id. An id starts with a lower-case ASCII letter or digit, continues with those or '-', and is at most {ManifestCredential.MaxIdLength} characters.",
                    SectionReadContext.Child(pointer, "id"));
                continue;
            }

            var declaredScheme = context.RequiredText(element, "scheme", pointer);

            if (declaredScheme is null)
            {
                continue;
            }

            if (!Vocabulary.TryReadCredentialScheme(declaredScheme, out var scheme))
            {
                context.Error(
                    ManifestDiagnosticCodes.CredentialSchemeUnknown,
                    $"'{DiagnosticText.Echo(declaredScheme)}' is not a credential scheme. Expected one of: {DiagnosticText.List(Vocabulary.CredentialSchemeNames)}.",
                    SectionReadContext.Child(pointer, "scheme"));
                continue;
            }

            var slot = context.RequiredText(element, "slot", pointer);

            if (slot is null)
            {
                continue;
            }

            if (!ValidateSlot(scheme, slot, pointer, context))
            {
                continue;
            }

            var location = ReadLocation(element, pointer, scheme, context);

            if (location is { Valid: false })
            {
                continue;
            }

            var reference = ReadReference(element, pointer, allowInlineSecrets, allowProviderReferences, context);

            if (reference is null)
            {
                continue;
            }

            // Uniqueness is deliberately NOT checked here, for either identity. Destination
            // contention is a property of scheme plus slot plus location together — a bearer
            // credential and a basic credential both write Authorization while declaring
            // different schemes — and it is now also a property of which binding references
            // both, which this reader cannot see. Id uniqueness is withheld for the narrower
            // reason that a reader reporting it would refuse the section before the validator
            // could report every other finding in it. This reader owns id syntax; the validator
            // owns both uniqueness invariants.
            credentials.Add(new ManifestCredential(id, scheme, slot, reference, location?.Value));
        }

        return new CredentialsSection(credentials);
    }

    private static bool ValidateSlot(
        CredentialScheme scheme,
        string slot,
        string pointer,
        SectionReadContext context)
    {
        if (scheme is not CredentialScheme.Basic)
        {
            return true;
        }

        if (string.Equals(slot, ManifestCredential.BasicUsernameSlot, StringComparison.Ordinal)
            || string.Equals(slot, ManifestCredential.BasicPasswordSlot, StringComparison.Ordinal))
        {
            return true;
        }

        context.Error(
            ManifestDiagnosticCodes.CredentialSlotInvalid,
            $"The basic scheme accepts only the slots '{ManifestCredential.BasicUsernameSlot}' and '{ManifestCredential.BasicPasswordSlot}', but '{DiagnosticText.Echo(slot)}' was declared.",
            SectionReadContext.Child(pointer, "slot"));

        return false;
    }

    private static (CredentialLocation Value, bool Valid)? ReadLocation(
        JsonObject element,
        string pointer,
        CredentialScheme scheme,
        SectionReadContext context)
    {
        if (element["location"] is null)
        {
            return null;
        }

        var locationPointer = SectionReadContext.Child(pointer, "location");

        if (scheme is not CredentialScheme.ApiKey)
        {
            context.Error(
                ManifestDiagnosticCodes.CredentialLocationInvalid,
                $"'location' applies only to the apiKey scheme, but scheme '{Vocabulary.Write(scheme)}' declared one.",
                locationPointer);
            return (default, false);
        }

        var declared = context.Text(element, "location", pointer);

        if (declared is null)
        {
            return (default, false);
        }

        if (!Vocabulary.TryReadCredentialLocation(declared, out var location))
        {
            context.Error(
                ManifestDiagnosticCodes.CredentialLocationInvalid,
                $"'{DiagnosticText.Echo(declared)}' is not a credential location. Expected one of: {DiagnosticText.List(Vocabulary.CredentialLocationNames)}.",
                locationPointer);
            return (default, false);
        }

        return (location, true);
    }

    private static CredentialReference? ReadReference(
        JsonObject element,
        string pointer,
        bool allowInlineSecrets,
        bool allowProviderReferences,
        SectionReadContext context)
    {
        var value = context.Object(element, "value", pointer);
        var valuePointer = SectionReadContext.Child(pointer, "value");

        if (value is null)
        {
            if (element["value"] is null)
            {
                context.Error(
                    ManifestDiagnosticCodes.MemberRequired,
                    "'value' is required. A credential slot with no source cannot be resolved.",
                    valuePointer);
            }

            return null;
        }

        context.RejectUnknownMembers(value, ValueMembers, valuePointer);

        var declared = ValueMembers.Where(member => value[member] is not null).ToList();

        if (declared.Count != 1)
        {
            context.Error(
                ManifestDiagnosticCodes.CredentialReferenceAmbiguous,
                declared.Count == 0
                    ? $"A credential value must declare exactly one of: {DiagnosticText.List(ValueMembers)}."
                    : $"A credential value declares {DiagnosticText.List(declared)}. Exactly one source is permitted.",
                valuePointer);
            return null;
        }

        var member = declared[0];
        var text = context.RequiredText(value, member, valuePointer);

        if (text is null)
        {
            return null;
        }

        switch (member)
        {
            case "fromEnv":
                return CredentialReference.Env(text);

            case "fromFile":
                if (!IsAbsoluteSecretPath(text))
                {
                    context.Error(
                        ManifestDiagnosticCodes.CredentialReferenceUnresolved,
                        $"'fromFile' must be an absolute path, but '{DiagnosticText.Echo(text)}' is relative. A relative secret path resolves against whatever directory Engine happens to run in.",
                        SectionReadContext.Child(valuePointer, "fromFile"));
                    return null;
                }

                return CredentialReference.File(text);

            case "fromProvider":
                if (!allowProviderReferences)
                {
                    context.Error(
                        ManifestDiagnosticCodes.CredentialProviderNotPermitted,
                        "This credential declares a managed provider reference. 'fromProvider' resolves only in managed mode; file mode has no provider secret set and must use 'fromEnv' or 'fromFile'.",
                        valuePointer);
                    return null;
                }

                if (!IsValidProviderKey(text))
                {
                    context.Error(
                        ManifestDiagnosticCodes.CredentialProviderKeyInvalid,
                        $"'fromProvider' must be an opaque bounded provider key: printable non-whitespace ASCII, at most {MaxProviderKeyLength} characters.",
                        SectionReadContext.Child(valuePointer, "fromProvider"));
                    return null;
                }

                return CredentialReference.Provider(text);

            default:
                if (!allowInlineSecrets)
                {
                    context.Error(
                        ManifestDiagnosticCodes.CredentialInlineNotPermitted,
                        "This credential declares a literal secret. Inline secrets require an explicit Engine opt-in; prefer 'fromEnv' or 'fromFile'.",
                        valuePointer);
                    return null;
                }

                context.Warning(
                    ManifestDiagnosticCodes.CredentialInlineDiscouraged,
                    "This credential declares a literal secret, so the secret lives in the manifest itself. Prefer 'fromEnv' or 'fromFile'.",
                    valuePointer);

                return CredentialReference.Literal(text);
        }
    }

    /// <summary>
    /// Decides whether a provider key is well formed without asking the host anything.
    /// </summary>
    /// <remarks>
    /// The key is a stable opaque identifier generated by the managed producer, so the rule is
    /// deliberately narrow: printable ASCII without whitespace or control characters. That
    /// admits a UUID, a slug, or a namespaced key while refusing anything that could not be
    /// matched exactly. Whether a matching value exists is a managed-activation question, not
    /// a load-time one.
    /// </remarks>
    private static bool IsValidProviderKey(string key)
    {
        if (key.Length == 0 || key.Length > MaxProviderKeyLength)
        {
            return false;
        }

        foreach (char character in key)
        {
            if (character < 0x21 || character > 0x7e)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Decides whether a secret path is absolute, without asking the host operating system.
    /// </summary>
    /// <remarks>
    /// <see cref="Path.IsPathFullyQualified(string)"/> answers a different question: whether the
    /// running OS would resolve the path without consulting the current directory. On Windows it
    /// rejects <c>/run/secrets/token</c>, which is the normal shape for the Linux container Engine
    /// actually ships in. Using it would make the same manifest valid in production and invalid
    /// when an operator runs <c>validate</c> on a laptop, which is exactly the portability the
    /// format is supposed to guarantee. The rule is therefore about the text: a POSIX root, a
    /// Windows drive root, or a UNC root. Nothing here touches the filesystem — whether the file
    /// exists and can be read is an execution-time auth question, not a load-time one.
    /// </remarks>
    private static bool IsAbsoluteSecretPath(string path)
    {
        if (path.Length == 0)
        {
            return false;
        }

        if (path[0] is '/')
        {
            return true;
        }

        if (path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return true;
        }

        return path.Length >= 3
            && char.IsAsciiLetter(path[0])
            && path[1] == ':'
            && path[2] is '/' or '\\';
    }
}
