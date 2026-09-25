using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.UnitTests;

using Xunit;

namespace MCPiler.Engine.UnitTests.Compatibility;

public sealed class SharedFailureClassificationTests
{
    [Fact]
    public void Engine_matches_the_authored_shared_failure_table()
    {
        JsonObject table = JsonNode.Parse(File.ReadAllText(
            TestRepository.Fixture("compatibility", "failure-classifications.json")))!.AsObject();
        string[] shared = table["shared"]!.AsArray().Select(static value => value!.GetValue<string>()).ToArray();
        string[] engineOnly = table["engineOnly"]!.AsArray().Select(static value => value!["name"]!.GetValue<string>()).ToArray();

        Assert.Equal(
            shared.Concat(engineOnly).Order(StringComparer.Ordinal),
            Enum.GetValues<ExecutionFailureKind>().Select(static kind => kind.ToString()).Order(StringComparer.Ordinal));
        Assert.Empty(table["platformOnly"]!.AsArray());
        Assert.All(
            table["engineOnly"]!.AsArray(),
            value => Assert.False(string.IsNullOrWhiteSpace(value!["reason"]!.GetValue<string>())));
    }
}
