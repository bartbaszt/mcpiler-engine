using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads the <c>server</c> section: display identity plus the surfaces that define routing
/// and exposure.
/// </summary>
internal static class ServerSectionReader
{
    private static readonly string[] SectionMembers =
        ["formatVersion", "name", "description", "version", "surfaces"];

    private static readonly string[] SurfaceMembers =
    [
        "slug",
        "name",
        "isDefault",
        "enabled",
        "requiredScopes",
        "navigator",
        "outputSchemas",
        "operations",
    ];

    private static readonly string[] NavigatorMembers = ["enabled", "pageSize"];

    private static readonly string[] OperationMembers = ["operation", "exposure"];

    internal static ServerSection? Read(JsonNode? document, SectionReadContext context)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, SectionMembers, string.Empty);
        context.VerifySectionFormatVersion(root, ServerSection.FormatVersion);

        var name = context.RequiredText(root, "name", string.Empty);
        var surfaces = ReadSurfaces(root, context);

        if (name is null)
        {
            return null;
        }

        return new ServerSection(
            name,
            context.Text(root, "description", string.Empty),
            context.Text(root, "version", string.Empty),
            surfaces);
    }

    private static IReadOnlyList<ManifestSurface> ReadSurfaces(
        JsonObject root,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(root, "surfaces", string.Empty);

        if (elements.Count == 0)
        {
            // A manifest that declares no surface is the minimal form. Engine synthesizes one
            // default surface at load, so an empty list is legal rather than incomplete.
            return [];
        }

        var surfaces = new List<ManifestSurface>(elements.Count);
        var slugs = new HashSet<string>(StringComparer.Ordinal);
        var defaults = 0;

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, SurfaceMembers, pointer);

            var slug = context.RequiredText(element, "slug", pointer);

            if (slug is null)
            {
                continue;
            }

            if (!slugs.Add(slug))
            {
                context.Error(
                    ManifestDiagnosticCodes.DuplicateSurfaceSlug,
                    $"Surface slug '{DiagnosticText.Echo(slug)}' is declared more than once.",
                    SectionReadContext.Child(pointer, "slug"));
                continue;
            }

            var isDefault = context.Flag(element, "isDefault", pointer);

            if (isDefault)
            {
                defaults++;
            }

            var operations = ReadSurfaceOperations(element, pointer, context);

            if (operations.Count == 0)
            {
                context.Warning(
                    ManifestDiagnosticCodes.SurfaceHasNoOperations,
                    $"Surface '{slug}' exposes no operation, so it advertises nothing and can serve no invocation.",
                    pointer);
            }

            surfaces.Add(new ManifestSurface(
                slug,
                operations,
                context.Text(element, "name", pointer),
                isDefault,
                context.Flag(element, "enabled", pointer, fallback: true),
                context.TextArray(element, "requiredScopes", pointer),
                ReadNavigator(element, pointer, context),
                context.Flag(element, "outputSchemas", pointer)));
        }

        switch (defaults)
        {
            case 0 when surfaces.Count > 0:
                context.Error(
                    ManifestDiagnosticCodes.NoDefaultSurface,
                    "No surface is marked default, so the bare connector route cannot be served. Mark exactly one surface with 'isDefault'.",
                    "/surfaces");
                break;

            case > 1:
                context.Error(
                    ManifestDiagnosticCodes.MultipleDefaultSurfaces,
                    "More than one surface is marked default. Exactly one surface may serve the bare connector route.",
                    "/surfaces");
                break;

            default:
                break;
        }

        return surfaces;
    }

    private static NavigatorSettings? ReadNavigator(
        JsonObject surface,
        string pointer,
        SectionReadContext context)
    {
        var navigator = context.Object(surface, "navigator", pointer);

        if (navigator is null)
        {
            return null;
        }

        var navigatorPointer = SectionReadContext.Child(pointer, "navigator");

        context.RejectUnknownMembers(navigator, NavigatorMembers, navigatorPointer);

        var pageSize = context.Integer(navigator, "pageSize", navigatorPointer);

        if (pageSize is { } declared && !context.RequireAtLeast(declared, 1, "pageSize", navigatorPointer))
        {
            pageSize = null;
        }

        return new NavigatorSettings(
            context.Flag(navigator, "enabled", navigatorPointer),
            pageSize ?? NavigatorDefaults.PageSize);
    }

    private static IReadOnlyList<SurfaceOperation> ReadSurfaceOperations(
        JsonObject surface,
        string pointer,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(surface, "operations", pointer);
        var operations = new List<SurfaceOperation>(elements.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (element, elementPointer) in elements)
        {
            context.RejectUnknownMembers(element, OperationMembers, elementPointer);

            var slug = context.RequiredText(element, "operation", elementPointer);

            if (slug is null)
            {
                continue;
            }

            if (!seen.Add(slug))
            {
                context.Error(
                    ManifestDiagnosticCodes.DuplicateSurfaceOperation,
                    $"Operation '{DiagnosticText.Echo(slug)}' is listed more than once on this surface.",
                    SectionReadContext.Child(elementPointer, "operation"));
                continue;
            }

            // Membership in this list is itself the grant, so an omitted exposure cannot widen
            // anything: the only open question is direct versus navigator, and both are
            // invocable. Hiding requires spelling 'hidden' explicitly.
            var declaredExposure = context.Text(element, "exposure", elementPointer);
            var exposure = OperationExposure.Direct;

            if (declaredExposure is not null
                && !Vocabulary.TryReadExposure(declaredExposure, out exposure))
            {
                context.Error(
                    ManifestDiagnosticCodes.UnknownMember,
                    $"'{DiagnosticText.Echo(declaredExposure)}' is not an exposure. Expected one of: {DiagnosticText.List(Vocabulary.ExposureNames)}.",
                    SectionReadContext.Child(elementPointer, "exposure"));
                continue;
            }

            operations.Add(new SurfaceOperation(slug, exposure));
        }

        return operations;
    }
}
