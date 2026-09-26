using System.Text.Json.Nodes;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Challenge;
using MCPiler.Engine.Authentication.Exchange;
using MCPiler.Engine.Authentication.OAuth1;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution.Projection;

internal static class SensitiveHeaderNames
{
    internal static IReadOnlySet<string> For(
        AuthenticationProfile? profile,
        IReadOnlyList<ResolvedCredential> credentials,
        ResolvedAuthentication? resolved = null)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (ResolvedCredential credential in credentials)
        {
            AddCredential(names, credential.Declaration);
        }

        if (resolved is not null)
        {
            foreach (ResolvedCredential credential in resolved.Credentials)
            {
                AddCredential(names, credential.Declaration);
            }

            if (resolved.Signing is { } signing)
            {
                foreach (string name in signing.SensitiveHeaders)
                {
                    names.Add(Canonical(name));
                }
            }

            if (resolved.OAuth1Signing is not null)
            {
                names.Add("authorization");
            }
        }

        AddAuthenticationSelectors(names, profile);
        AddStrategyHeaders(names, profile);
        return names;
    }

    internal static IReadOnlySet<string> For(
        AuthenticationProfile? profile,
        IReadOnlyList<ManifestCredential> declarations)
    {
        ArgumentNullException.ThrowIfNull(declarations);

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (ManifestCredential declaration in declarations)
        {
            if (profile is not null
                && !profile.CredentialRef.Contains(declaration.Id, StringComparer.Ordinal))
            {
                continue;
            }

            AddCredential(names, declaration);
        }

        AddAuthenticationSelectors(names, profile);
        AddStrategyHeaders(names, profile);
        return names;
    }

    internal static IReadOnlySet<string> QueryFor(
        AuthenticationProfile? profile,
        IReadOnlyList<ManifestCredential> declarations)
    {
        ArgumentNullException.ThrowIfNull(declarations);

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (ManifestCredential declaration in declarations)
        {
            if (profile is not null
                && !profile.CredentialRef.Contains(declaration.Id, StringComparer.Ordinal))
            {
                continue;
            }

            if (declaration.EffectiveLocation == CredentialLocation.Query)
            {
                names.Add(Canonical(declaration.Slot));
            }
        }

        AddAuthenticationQuerySelectors(names, profile);
        AddStrategyQueryNames(names, profile);
        return names;
    }

    internal static (IReadOnlySet<string> Headers, IReadOnlySet<string> Queries) ForBinding(
        ManifestDocument manifest,
        ManifestBinding binding)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(binding);

        AuthenticationProfile? profile = ManifestBindingDispatcher.AuthenticationRefOf(binding) is { } profileId
            ? manifest.EffectiveAuthentication.Profile(profileId)
            : null;
        IReadOnlyList<ManifestCredential> declarations = profile is null
            ? [.. manifest.EffectiveCredentials.Credentials.Where(declaration =>
                ManifestBindingDispatcher.CredentialRefsOf(binding).Contains(declaration.Id, StringComparer.Ordinal))]
            : manifest.EffectiveCredentials.Credentials;

        return (For(profile, declarations), QueryFor(profile, declarations));
    }

    internal static IReadOnlySet<string> QueryFor(
        AuthenticationProfile? profile,
        IReadOnlyList<ResolvedCredential> credentials,
        ResolvedAuthentication? resolved = null)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddQueryCredentials(names, credentials);
        if (resolved is not null)
        {
            AddQueryCredentials(names, resolved.Credentials);
            if (resolved.Signing is { } signing)
            {
                names.UnionWith(signing.SensitiveQueryParameters);
            }

            if (resolved.OAuth1Signing is not null)
            {
                names.UnionWith(OAuth1Vocabulary.SensitiveProtocolParameters);
            }
        }

        AddAuthenticationQuerySelectors(names, profile);
        AddStrategyQueryNames(names, profile);
        return names;
    }

    private static void AddQueryCredentials(
        HashSet<string> names,
        IEnumerable<ResolvedCredential> credentials)
    {
        foreach (ResolvedCredential credential in credentials)
        {
            if (credential.Declaration.EffectiveLocation == CredentialLocation.Query)
            {
                names.Add(Canonical(credential.Declaration.Slot));
            }
        }
    }

    private static void AddAuthenticationQuerySelectors(
        HashSet<string> names,
        AuthenticationProfile? profile)
    {
        if (profile is null)
        {
            return;
        }

        switch (profile.Kind)
        {
            case AuthenticationKind.TokenSessionExchange:
                TokenSessionExchangeDefinition exchange =
                    TokenSessionExchangeDefinition.FromConfiguration(profile.Configuration);
                if (exchange.Injection.Location == "query" && exchange.Injection.Name is { } exchangeName)
                {
                    names.Add(Canonical(exchangeName));
                }
                break;
            case AuthenticationKind.ChallengeSession:
                ChallengeSessionDefinition challenge =
                    ChallengeSessionDefinition.FromConfiguration(profile.Configuration);
                if (challenge.Injection.Location == "query" && challenge.Injection.Name is { } challengeName)
                {
                    names.Add(Canonical(challengeName));
                }
                break;
        }
    }

    private static void AddInjectionName(HashSet<string> names, SessionInjectionDefinition injection)
    {
        if (injection.Location == "bearer")
        {
            names.Add("authorization");
        }
        else if (injection.Name is { } name)
        {
            names.Add(Canonical(name));
            if (injection.Location == "cookie")
            {
                names.Add("cookie");
            }
        }
    }

    private static void AddStrategyHeaders(HashSet<string> names, AuthenticationProfile? profile)
    {
        if (profile is null)
        {
            return;
        }

        switch (profile.Kind)
        {
            case AuthenticationKind.OAuth2ClientCredentials:
            case AuthenticationKind.OAuth2AuthorizationCodePkceRefresh:
            case AuthenticationKind.OAuth1Authorization:
                names.Add("authorization");
                break;
            case AuthenticationKind.TokenSessionExchange:
                TokenSessionExchangeDefinition exchange =
                    TokenSessionExchangeDefinition.FromConfiguration(profile.Configuration);
                AddInjectionName(names, exchange.Injection);
                break;
            case AuthenticationKind.ChallengeSession:
                ChallengeSessionDefinition challenge =
                    ChallengeSessionDefinition.FromConfiguration(profile.Configuration);
                AddInjectionName(names, challenge.Injection);
                break;
            case AuthenticationKind.RequestSigning:
                string strategyId = RequiredConfigurationText(profile.Configuration, "strategyId");
                if (!string.Equals(strategyId, "request-signing-subsonic-md5", StringComparison.Ordinal))
                {
                    names.Add("authorization");
                }
                break;
        }
    }

    private static void AddStrategyQueryNames(HashSet<string> names, AuthenticationProfile? profile)
    {
        if (profile is null)
        {
            return;
        }

        switch (profile.Kind)
        {
            case AuthenticationKind.RequestSigning:
                string strategyId = RequiredConfigurationText(profile.Configuration, "strategyId");
                if (string.Equals(strategyId, "request-signing-subsonic-md5", StringComparison.Ordinal))
                {
                    names.Add("u");
                    names.Add("t");
                    names.Add("s");
                }
                break;
            case AuthenticationKind.OAuth1Authorization:
                if (string.Equals(
                        RequiredConfigurationText(profile.Configuration, "parameterTransport"),
                        OAuth1Vocabulary.QueryTransport,
                        StringComparison.Ordinal))
                {
                    names.UnionWith(OAuth1Vocabulary.SensitiveProtocolParameters);
                }
                break;
        }
    }

    private static void AddCredential(HashSet<string> names, ManifestCredential declaration)
    {
        if (!declaration.IsRedirectSensitiveHeader)
        {
            return;
        }

        switch (declaration.Scheme)
        {
            case CredentialScheme.Basic:
            case CredentialScheme.Bearer:
            case CredentialScheme.OAuth2ClientCredentials:
            case CredentialScheme.OAuth2AuthorizationCode:
                names.Add("authorization");
                break;
            case CredentialScheme.Header:
                names.Add(Canonical(declaration.Slot));
                break;
            case CredentialScheme.ApiKey when declaration.EffectiveLocation == CredentialLocation.Cookie:
                names.Add("cookie");
                break;
            case CredentialScheme.ApiKey when declaration.EffectiveLocation == CredentialLocation.Header:
                names.Add(Canonical(declaration.Slot));
                break;
        }
    }

    private static void AddAuthenticationSelectors(
        HashSet<string> names,
        AuthenticationProfile? profile)
    {
        if (profile is null)
        {
            return;
        }

        switch (profile.Kind)
        {
            case AuthenticationKind.TokenSessionExchange:
                TokenSessionExchangeDefinition exchange =
                    TokenSessionExchangeDefinition.FromConfiguration(profile.Configuration);
                AddSelector(names, exchange.TokenSelector);
                AddSelector(names, exchange.Expiry?.Selector);
                AddSelector(names, exchange.Destination?.Selector);
                break;
            case AuthenticationKind.ChallengeSession:
                ChallengeSessionDefinition challenge =
                    ChallengeSessionDefinition.FromConfiguration(profile.Configuration);
                AddSelector(names, new ExchangeSelector(
                    challenge.SelectorKind,
                    challenge.Selector));
                break;
        }
    }

    private static void AddSelector(HashSet<string> names, ExchangeSelector? selector)
    {
        if (selector is { Kind: ExchangeSelectorKind.Header })
        {
            names.Add(Canonical(selector.Selector));
        }
    }

    private static string RequiredConfigurationText(JsonObject configuration, string member)
        => configuration[member] is JsonValue value
            && value.TryGetValue<string>(out string? text)
            && !string.IsNullOrWhiteSpace(text)
                ? text
                : throw new InvalidOperationException($"Authentication sensitivity requires '{member}'.");

    internal static bool IsSensitiveParameter(
        ManifestParameter parameter,
        IReadOnlySet<string> sensitiveHeaderNames,
        IReadOnlySet<string> sensitiveQueryNames)
    {
        ArgumentNullException.ThrowIfNull(parameter);
        ArgumentNullException.ThrowIfNull(sensitiveHeaderNames);
        ArgumentNullException.ThrowIfNull(sensitiveQueryNames);

        string canonical = Canonical(parameter.Name);
        return parameter.In switch
        {
            ParameterLocation.Header =>
                AgentOutputProjectionSafety.IsHardDenied(canonical)
                || sensitiveHeaderNames.Contains(canonical),
            ParameterLocation.Query => sensitiveQueryNames.Contains(canonical),
            _ => false,
        };
    }

    private static string Canonical(string name) => name.Trim().ToLowerInvariant();
}
