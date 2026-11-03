using MCPiler.Engine.Host.Cli;

using Microsoft.AspNetCore.Builder;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Hosting;

/// <summary>
/// The first-listener holder's wait/reset contract: a rolled-back provisional bind must leave the
/// process-lifetime wait pending for the retry, not strand the main thread on a replaced signal.
/// </summary>
public sealed class ManagedListenerHolderTests
{
    [Fact]
    public async Task A_released_provisional_bind_wakes_the_same_waiter_when_a_later_retry_is_confirmed()
    {
        await using WebApplication first = MinimalApplication();
        await using WebApplication second = MinimalApplication();
        using var holder = new HostCommands.ManagedListenerHolder();

        Assert.True(holder.TryAttach(first));

        // The main thread starts waiting before the first bind's rollback. This call captures the
        // serving signal and returns while it is still incomplete.
        Task<WebApplication> serving = holder.WaitForServingAsync(
            TestContext.Current.CancellationToken);

        // Rollback: the first socket is discarded and never became serving.
        holder.Release(first);
        Assert.Null(holder.Application);

        // A later delivery binds and its candidate activates successfully.
        Assert.True(holder.TryAttach(second));
        holder.Confirm(second);

        WebApplication confirmed = await serving.WaitAsync(
            TimeSpan.FromSeconds(5),
            TestContext.Current.CancellationToken);

        Assert.Same(second, confirmed);
    }

    [Fact]
    public async Task A_confirmed_listener_cannot_be_released_by_a_late_rollback()
    {
        await using WebApplication application = MinimalApplication();
        using var holder = new HostCommands.ManagedListenerHolder();

        Assert.True(holder.TryAttach(application));
        holder.Confirm(application);

        holder.Release(application);

        Assert.Same(application, holder.Application);
    }

    private static WebApplication MinimalApplication()
        => WebApplication.CreateSlimBuilder().Build();
}
