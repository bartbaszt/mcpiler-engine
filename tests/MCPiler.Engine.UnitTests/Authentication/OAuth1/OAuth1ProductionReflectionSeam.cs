using System.Reflection;
using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication.OAuth1;

/// <summary>
/// Temporary test-only bridge to the planned Engine OAuth1 API, which Task 1 precedes.
/// Reflection keeps standalone Engine tests compilable before those production types exist.
/// Once present, invocation is against Engine production methods; no fake signer/canonicalizer
/// belongs in Engine or the test project. Keep this seam aligned when Tasks 7/8 implement OAuth1.
/// </summary>
internal static class OAuth1ProductionReflectionSeam
{
    private const BindingFlags StaticMethods = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;

    public static Type RequireType(Assembly assembly, string typeName)
    {
        var type = assembly.GetType($"MCPiler.Engine.Authentication.OAuth1.{typeName}", throwOnError: false);
        Assert.True(type is not null,
            $"Engine OAuth1 production type '{typeName}' is not implemented yet. This failure is intentional in Task 1; do not add a test stub, bind the seam to the production API when Tasks 7/8 implement it.");
        return type!;
    }

    public static string InvokeString(Type type, string methodName, params object?[] arguments)
    {
        var method = FindMethod(type, methodName, arguments.Length);
        return Assert.IsType<string>(method.Invoke(null, arguments));
    }

    public static IReadOnlyList<KeyValuePair<string, string>> InvokePairs(
        Type type,
        string methodName,
        params object?[] arguments)
    {
        var method = FindMethod(type, methodName, arguments.Length);
        var result = method.Invoke(null, arguments);
        Assert.NotNull(result);
        return Assert.IsAssignableFrom<IEnumerable<KeyValuePair<string, string>>>(result).ToArray();
    }

    private static MethodInfo FindMethod(Type type, string methodName, int parameterCount)
    {
        var candidates = type.GetMethods(StaticMethods)
            .Where(method => string.Equals(method.Name, methodName, StringComparison.Ordinal)
                && method.GetParameters().Length == parameterCount)
            .ToArray();

        Assert.True(candidates.Length == 1,
            $"Expected exactly one production {type.FullName}.{methodName} method with {parameterCount} parameters; found {candidates.Length}.");
        return candidates[0];
    }
}
