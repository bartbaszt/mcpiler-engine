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
    private static readonly string[] SectionMembers = ["formatVersion", "credentials"];

    private static readonly string[] CredentialMembers = ["scheme", "slot", "location", "value"];

    private static readonly string[] ValueMembers = ["fromEnv", "fromFile", "inline"];

    internal static CredentialsSection? Read(
        JsonNode? document,
        SectionReadContext context,
        bool allowInlineSecrets)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, SectionMembers, string.Empty);
        context.VerifySectionFormatVersion(root, CredentialsSection.FormatVersion);

        var elements = context.ObjectArray(root, "credentials", string.Empty);
        var credentials = new List<ManifestCredential>(elements.Count);
        var slots = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, CredentialMembers, pointer);

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

            var reference = ReadReference(element, pointer, allowInlineSecrets, context);

            if (reference is null)
            {
                continue;
            }

            var effectiveLocation = location?.Value ?? CredentialLocation.Header;
            var identity = string.Concat(
                Vocabulary.Write(scheme),
                "|",
                slot,
                "|",
                Vocabulary.Write(effectiveLocation));

            if (!slots.Add(identity))
            {
                context.Error(
                    ManifestDiagnosticCodes.CredentialSlotInvalid,
                    $"Slot '{DiagnosticText.Echo(slot)}' is declared more than once for scheme '{Vocabulary.Write(scheme)}'. Which value applies would depend on declaration order.",
                    SectionReadContext.Child(pointer, "slot"));
                continue;
            }

            credentials.Add(new ManifestCredential(scheme, slot, reference, location?.Value));
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
                if (!Path.IsPathFullyQualified(text))
                {
                    context.Error(
                        ManifestDiagnosticCodes.CredentialReferenceUnresolved,
                        $"'fromFile' must be an absolute path, but '{DiagnosticText.Echo(text)}' is relative. A relative secret path resolves against whatever directory Engine happens to run in.",
                        SectionReadContext.Child(valuePointer, "fromFile"));
                    return null;
                }

                return CredentialReference.File(text);

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
}
