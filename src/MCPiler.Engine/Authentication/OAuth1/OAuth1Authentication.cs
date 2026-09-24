using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.OAuth1;

/// <summary>
/// Resolves the closed method-specific OAuth 1.0a runtime material for one profile from the
/// credentials its references declared. Each method receives only its required slots;
/// missing or unexpected material fails before any request is signed.
/// </summary>
/// <remarks>
/// Diagnostics name the profile, the method, and the slot. They never carry a value: the
/// values cross this boundary only inside the returned material.
/// </remarks>
internal static class OAuth1Authentication
{
    public static OAuth1SigningMaterial ResolveMaterial(
        AuthenticationProfile profile,
        IReadOnlyList<ResolvedCredential> declared)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(declared);

        string? method = profile.Configuration["signatureMethod"] is JsonValue methodValue
            && methodValue.TryGetValue<string>(out string? text)
                ? text
                : null;

        if (!OAuth1Vocabulary.TryGetRequiredSlots(method, out string[] required))
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"Authentication profile '{profile.Id}' declares signature method '{method}', which this Engine build cannot execute. " +
                $"Reviewed methods: {string.Join(", ", OAuth1Vocabulary.SignatureMethods)}.");
        }

        string? consumerKey = profile.Configuration["consumerKey"] is JsonValue keyValue
            && keyValue.TryGetValue<string>(out string? key)
            && !string.IsNullOrWhiteSpace(key)
                ? key
                : null;

        if (consumerKey is null)
        {
            throw new AuthenticationPlanException(profile.Id, "An OAuth 1.0a profile requires a non-empty 'consumerKey'.");
        }

        Dictionary<string, string> bySlot = new(StringComparer.Ordinal);
        foreach (ResolvedCredential credential in declared)
        {
            if (credential.Declaration.Scheme != CredentialScheme.OAuth1Authorization)
            {
                continue;
            }

            bySlot.TryAdd(credential.Declaration.Slot, credential.Value);
        }

        string? missing = required.FirstOrDefault(slot => !bySlot.ContainsKey(slot));
        if (missing is not null)
        {
            throw new CredentialUnavailableException(
                profile.Id,
                $"OAuth 1.0a '{method}' signing cannot proceed without the '{missing}' credential. " +
                $"The profile must reference it.");
        }

        string? unexpected = bySlot.Keys.FirstOrDefault(slot => !required.Contains(slot, StringComparer.Ordinal));
        if (unexpected is not null)
        {
            throw new AuthenticationPlanException(
                profile.Id,
                $"OAuth 1.0a '{method}' signing refused the unexpected credential slot '{unexpected}'. " +
                $"The method accepts exactly: {string.Join(", ", required)}.");
        }

        string token = bySlot[OAuth1Vocabulary.TokenSlot];

        if (string.Equals(method, OAuth1Vocabulary.RsaSha1, StringComparison.Ordinal))
        {
            return new OAuth1SigningMaterial.RsaMaterial
            {
                ConsumerKey = consumerKey,
                Token = token,
                PrivateKeyPem = bySlot[OAuth1Vocabulary.RsaPrivateKeySlot],
            };
        }

        return new OAuth1SigningMaterial.SharedSecretMaterial
        {
            ConsumerKey = consumerKey,
            Token = token,
            ConsumerSecret = bySlot[OAuth1Vocabulary.ConsumerSecretSlot],
            TokenSecret = bySlot[OAuth1Vocabulary.TokenSecretSlot],
        };
    }
}
