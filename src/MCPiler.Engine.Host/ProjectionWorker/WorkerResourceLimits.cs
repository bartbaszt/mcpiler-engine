using System.Collections;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;

using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Host.ProjectionWorker;

/// <summary>The host platforms for which worker memory confinement is or is not implemented.</summary>
internal enum WorkerHostPlatform
{
    /// <summary>Windows: a Job Object with <c>JOB_OBJECT_LIMIT_PROCESS_MEMORY</c>.</summary>
    Windows,

    /// <summary>Linux: <c>RLIMIT_AS</c> plus a managed heap cap.</summary>
    Linux,

    /// <summary>Any other host, including macOS: confinement is unavailable and evaluation is refused.</summary>
    Other,
}

/// <summary>
/// Applies the operating system's per-process memory confinement to the worker itself.
/// </summary>
/// <remarks>
/// <para>
/// The limit is applied by the child, before it reads any expression or body, and it is verified
/// afterwards by querying the mechanism back. A parent that spawned a process and assumed the
/// limit took effect would be assuming the one property the whole design rests on, and the two
/// operating systems bound different things:
/// </para>
/// <list type="bullet">
///   <item>Windows: a Job Object with <c>JOB_OBJECT_LIMIT_PROCESS_MEMORY</c> limits the
///     process's committed memory. The child creates the job, assigns itself and queries the
///     limit back. Measured working under the development host's own job.</item>
///   <item>Linux: <c>RLIMIT_AS</c> limits the process's virtual address space, and
///     <c>DOTNET_GCHeapHardLimit</c> caps the managed heap. Neither is an RSS measure: the
///     address-space limit is the one that stops an unbounded allocation from succeeding, while
///     the GC limit keeps the runtime's own reservation from consuming the whole allowance.
///     Calibration on the real Engine image measured which combinations start and which abort
///     before readiness.</item>
/// </list>
/// <para>
/// The caller is told exactly what was applied. A host that could not apply confinement refuses
/// to evaluate rather than evaluating unconfined, which is why this returns a result instead of
/// throwing: the refusal has a documented shape and reaches the caller as a classified failure.
/// </para>
/// </remarks>
internal static class WorkerResourceLimits
{
    /// <summary>The default per-worker committed-memory limit: 256 MiB.</summary>
    internal const long DefaultCommittedBytes = 256L * 1024 * 1024;

    /// <summary>The Linux GC heap cap applied alongside the address-space limit: 256 MiB.</summary>
    internal const string GcHeapHardLimitVariable = "DOTNET_GCHeapHardLimit";

    /// <summary>Selects the workstation GC, which reserves one smaller heap rather than per-core heaps.</summary>
    internal const string GcServerVariable = "DOTNET_gcServer";

    /// <summary>
    /// Caps the GC's reserved virtual region range, which otherwise derives from the memory the
    /// process sees and can consume most of a bounded address space.
    /// </summary>
    internal const string GcRegionRangeVariable = "DOTNET_GCRegionRange";

    /// <summary>The default Linux address-space limit: 4 GiB.</summary>
    internal const long DefaultAddressSpaceBytes = 4L * 1024 * 1024 * 1024;

    internal const long DefaultInputBodyLimitBytes = (int.MaxValue - 1024) / 6;

    internal const string CommittedBytesVariable = "MCPILER_PROJECTION_WORKER_COMMITTED_BYTES";

    internal const string AddressSpaceBytesVariable = "MCPILER_PROJECTION_WORKER_ADDRESS_SPACE_BYTES";

    internal const string InputBodyBytesVariable = "MCPILER_PROJECTION_WORKER_INPUT_BODY_BYTES";

    private static readonly HashSet<string> AllowedWorkerEnvironmentVariables = new(
        [
            GcHeapHardLimitVariable,
            GcServerVariable,
            GcRegionRangeVariable,
            CommittedBytesVariable,
            AddressSpaceBytesVariable,
            InputBodyBytesVariable,
            "DOTNET_ROOT",
            "DOTNET_ROOT(x86)",
            "DOTNET_ROOT_X86",
            "DOTNET_ROOT_X64",
            "DOTNET_ROOT_ARM64",
            "SystemRoot",
            "WINDIR",
        ],
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JobObjectLimitProcessMemory = 0x00000100;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;

    /// <summary>
    /// A test seam for the detected host platform. Production reads the real operating system;
    /// tests override it to prove the unsupported-host fail-closed path without a macOS host. The
    /// value flows with the async execution context so it cannot leak across parallel tests.
    /// </summary>
    private static readonly AsyncLocal<WorkerHostPlatform?> PlatformOverride = new();

    /// <summary>The confinement platform this process is running on.</summary>
    internal static WorkerHostPlatform CurrentPlatform
        => PlatformOverride.Value
            ?? (OperatingSystem.IsWindows()
                ? WorkerHostPlatform.Windows
                : OperatingSystem.IsLinux()
                    ? WorkerHostPlatform.Linux
                    : WorkerHostPlatform.Other);

    /// <summary>Test seam: overrides the detected platform for the current async flow.</summary>
    internal static IDisposable OverridePlatformForTesting(WorkerHostPlatform? platform)
    {
        WorkerHostPlatform? previous = PlatformOverride.Value;
        PlatformOverride.Value = platform;
        return new PlatformRestore(previous);
    }

    private sealed class PlatformRestore(WorkerHostPlatform? previous) : IDisposable
    {
        public void Dispose() => PlatformOverride.Value = previous;
    }

    /// <summary>Applies the platform's confinement to this process.</summary>
    /// <param name="committedBytes">The Windows committed-memory limit.</param>
    /// <param name="addressSpaceBytes">The Linux address-space (RLIMIT_AS) limit.</param>
    /// <param name="applied">What was applied, for the ready handshake.</param>
    /// <param name="refusal">Why confinement could not be applied.</param>
    internal static bool TryApply(
        long committedBytes,
        long addressSpaceBytes,
        out string applied,
        out string? refusal)
        => TryApply(CurrentPlatform, committedBytes, addressSpaceBytes, out applied, out refusal);

    /// <summary>
    /// Applies confinement for one explicit platform. Confinement exists only on Windows (Job
    /// Object) and Linux (RLIMIT_AS); every other host, including macOS, is unsupported and is
    /// refused fail-closed rather than being assumed protected.
    /// </summary>
    internal static bool TryApply(
        WorkerHostPlatform platform,
        long committedBytes,
        long addressSpaceBytes,
        out string applied,
        out string? refusal)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(committedBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(addressSpaceBytes, 1);

        applied = string.Empty;
        refusal = null;

        if (committedBytes > long.MaxValue / 2)
        {
            refusal = "The committed-memory limit is too large to derive the worker GC region range.";
            return false;
        }

        return platform switch
        {
            WorkerHostPlatform.Windows => TryApplyWindowsJob(committedBytes, out applied, out refusal),
            WorkerHostPlatform.Linux => TryApplyPosixLimit(addressSpaceBytes, out applied, out refusal),
            _ => RefuseUnsupportedHost(out refusal),
        };
    }

    private static bool RefuseUnsupportedHost(out string? refusal)
    {
        refusal = string.Create(
            CultureInfo.InvariantCulture,
            $"No memory confinement is implemented for {RuntimeInformation.OSDescription}.");
        return false;
    }

    /// <summary>
    /// Sets the environment variables a child needs so the runtime caps its managed heap and its
    /// virtual reservations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The variables are read by the runtime at initialization, so a parent that starts the child
    /// must set them on the child's <see cref="ProcessStartInfo"/> rather than in the parent's own
    /// environment.
    /// </para>
    /// <para>
    /// On Linux the address-space limit is a virtual bound, and the runtime's default reservation
    /// is derived from the memory the process sees rather than from the allowance. Left alone it
    /// reserves most of a bounded address space, so an otherwise trivial evaluation dies
    /// intermittently when the loader maps a framework assembly. These two variables are what
    /// shrink that reservation to the stated heap cap: the workstation GC keeps one heap instead
    /// of one per core, and the region range is set to twice the heap cap, which the runtime
    /// documentation names as safe for a workload that does not make many large allocations.
    /// </para>
    /// </remarks>
    internal static void ApplyGcHeapCap(IDictionary<string, string?> environment, long committedBytes)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentOutOfRangeException.ThrowIfLessThan(committedBytes, 1);

        // The runtime reads these as hexadecimal byte counts.
        long regionRangeBytes = checked(2 * committedBytes);
        environment[GcHeapHardLimitVariable] = committedBytes.ToString("X", CultureInfo.InvariantCulture);

        // Workstation GC: one heap sized to the cap instead of a heap per core.
        environment[GcServerVariable] = "0";

        // Twice the heap cap, which is the documented safe reservation for a small-heap workload.
        environment[GcRegionRangeVariable] =
            regionRangeBytes.ToString("X", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Replaces the inherited child environment with the small set of runtime and confinement
    /// values required by the worker.
    /// </summary>
    internal static bool TryConfigureWorkerEnvironment(
        IDictionary<string, string?> environment,
        long committedBytes,
        long addressSpaceBytes,
        out string? refusal)
        => TryConfigureWorkerEnvironment(
            environment,
            committedBytes,
            addressSpaceBytes,
            DefaultInputBodyLimitBytes,
            out refusal);

    internal static bool TryConfigureWorkerEnvironment(
        IDictionary<string, string?> environment,
        long committedBytes,
        long addressSpaceBytes,
        long inputBodyBytes,
        out string? refusal)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentOutOfRangeException.ThrowIfLessThan(committedBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(addressSpaceBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(inputBodyBytes, 1);

        if (committedBytes > long.MaxValue / 2)
        {
            refusal = "The committed-memory limit is too large to derive the worker GC region range.";
            return false;
        }

        refusal = null;
        environment.Clear();

        // Apphosts use these explicit runtime roots when .NET is installed outside a default
        // location. Copy only the documented discovery variables, never the rest of DOTNET_*.
        foreach (string variableName in DotNetRootVariables)
        {
            string? value = Environment.GetEnvironmentVariable(variableName);

            if (!string.IsNullOrWhiteSpace(value))
            {
                environment[variableName] = value;
            }
        }

        if (OperatingSystem.IsWindows())
        {
            string? systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string? windowsDirectory = Environment.GetEnvironmentVariable("WINDIR");
            systemRoot = string.IsNullOrWhiteSpace(systemRoot) ? windowsDirectory : systemRoot;

            if (string.IsNullOrWhiteSpace(systemRoot))
            {
                refusal = "The required Windows system directory environment variable is unavailable.";
                return false;
            }

            environment["SystemRoot"] = systemRoot;

            if (!string.IsNullOrWhiteSpace(windowsDirectory))
            {
                environment["WINDIR"] = windowsDirectory;
            }
        }

        ApplyGcHeapCap(environment, committedBytes);
        environment[CommittedBytesVariable] =
            committedBytes.ToString(CultureInfo.InvariantCulture);
        environment[AddressSpaceBytesVariable] =
            addressSpaceBytes.ToString(CultureInfo.InvariantCulture);
        environment[InputBodyBytesVariable] =
            inputBodyBytes.ToString(CultureInfo.InvariantCulture);

        return true;
    }

    private static readonly string[] DotNetRootVariables =
    [
        "DOTNET_ROOT",
        "DOTNET_ROOT(x86)",
        "DOTNET_ROOT_X86",
        "DOTNET_ROOT_X64",
        "DOTNET_ROOT_ARM64",
    ];

    /// <summary>Refuses worker startup if an unapproved environment variable reaches the child.</summary>
    internal static bool TryValidateWorkerEnvironment(out string? refusal)
    {
        foreach (DictionaryEntry item in Environment.GetEnvironmentVariables())
        {
            if (item.Key is string name && !AllowedWorkerEnvironmentVariables.Contains(name))
            {
                refusal = "The worker environment contains an unapproved variable.";
                return false;
            }
        }

        refusal = null;
        return true;
    }

    /// <summary>
    /// Forces the runtime to map the assemblies an evaluation needs, under the applied limit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The managed-heap witness proves the limit is not so low that the runtime merely started.
    /// It does not prove the loader can still map a framework assembly afterwards, and that is the
    /// failure that actually occurs on Linux: the reservation from startup sits just under the
    /// address-space limit, and the next mapping fails with an allocation error the loader reports
    /// as a missing assembly. Loading the evaluation assemblies here turns that failure into a
    /// readiness refusal the parent classifies, rather than a child that dies on its first request.
    /// </para>
    /// <para>
    /// The warm-up executes one trivial evaluation through the same seam a real request uses, so it
    /// exercises exactly the code path a bound that is too tight would break.
    /// </para>
    /// </remarks>
    internal static bool TryWarmUp([NotNullWhen(false)] out string? refusal)
    {
        refusal = null;

        try
        {
            JmesPathEvaluationResult result = JmesPathProfile.EvaluatePrepared(
                WarmUpBody,
                WarmUpExpression,
                JmesPathLimits.AuthoringDefault);

            if (!result.Succeeded)
            {
                refusal = string.Create(
                    CultureInfo.InvariantCulture,
                    $"The worker could not evaluate its warm-up expression: {result.Failure!.Code}.");
                return false;
            }

            return true;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            refusal = string.Create(
                CultureInfo.InvariantCulture,
                $"The worker's warm-up evaluation failed: {exception.Message}");
            return false;
        }
    }

    private static readonly byte[] WarmUpBody = "{}"u8.ToArray();

    private const string WarmUpExpression = "@";

    /// <summary>
    /// Allocates and touches a block sized as a fraction of the allowance, proving that the
    /// limit is not so low that the runtime merely started successfully.
    /// </summary>
    /// <remarks>
    /// Measured on the real Linux image: setting <c>RLIMIT_AS</c> below what the runtime
    /// reserves succeeds, and the process then dies before it can evaluate anything. A witness
    /// allocation after the limit turns that silent start failure into a refusal the parent
    /// classifies.
    /// </remarks>
    internal static bool TryProveAllocatable(long committedBytes, out string? refusal)
    {
        refusal = null;

        // A sixteenth of the allowance: large enough to fail on a limit that cannot support work,
        // small enough not to consume a meaningful share of the budget.
        int witnessBytes = (int)Math.Min(int.MaxValue, Math.Max(1024 * 1024, committedBytes / 16));

        try
        {
            byte[] witness = GC.AllocateUninitializedArray<byte>(witnessBytes);

            // Touch one byte per page so the allocation becomes resident rather than virtual.
            for (int offset = 0; offset < witness.Length; offset += 4096)
            {
                witness[offset] = 1;
            }

            GC.KeepAlive(witness);
            return true;
        }
        catch (OutOfMemoryException)
        {
            refusal = string.Create(
                CultureInfo.InvariantCulture,
                $"The worker cannot allocate its {witnessBytes}-byte witness under the applied memory limit.");
            return false;
        }
    }

    private static bool TryApplyWindowsJob(long committedBytes, out string applied, out string? refusal)
    {
        applied = string.Empty;
        refusal = null;

        IntPtr job = CreateJobObjectW(IntPtr.Zero, IntPtr.Zero);

        if (job == IntPtr.Zero)
        {
            refusal = string.Create(
                CultureInfo.InvariantCulture,
                $"A job object could not be created (Win32 error {Marshal.GetLastWin32Error()}).");
            return false;
        }

        var information = new JobObjectExtendedLimitInformationStructure();
        information.BasicLimitInformation.LimitFlags = JobObjectLimitProcessMemory | JobObjectLimitKillOnJobClose;
        information.ProcessMemoryLimit = (UIntPtr)committedBytes;

        if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformationClass,
                ref information,
                Marshal.SizeOf<JobObjectExtendedLimitInformationStructure>()))
        {
            refusal = string.Create(
                CultureInfo.InvariantCulture,
                $"The job object's memory limit could not be set (Win32 error {Marshal.GetLastWin32Error()}).");
            return false;
        }

        if (!AssignProcessToJobObject(job, GetCurrentProcess()))
        {
            refusal = string.Create(
                CultureInfo.InvariantCulture,
                $"The worker could not assign itself to the job object (Win32 error {Marshal.GetLastWin32Error()}).");
            return false;
        }

        int size = Marshal.SizeOf<JobObjectExtendedLimitInformationStructure>();

        if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformationClass, out var queried, size, out _))
        {
            refusal = string.Create(
                CultureInfo.InvariantCulture,
                $"The applied job object limit could not be read back (Win32 error {Marshal.GetLastWin32Error()}).");
            return false;
        }

        if ((queried.BasicLimitInformation.LimitFlags & JobObjectLimitProcessMemory) == 0
            || queried.ProcessMemoryLimit != (UIntPtr)committedBytes)
        {
            refusal = string.Create(
                CultureInfo.InvariantCulture,
                $"The applied job object limit does not match the requested {committedBytes} bytes.");
            return false;
        }

        applied = string.Create(
            CultureInfo.InvariantCulture,
            $"windows-job-commit-{committedBytes}");
        return true;
    }

    private static bool TryApplyPosixLimit(long addressSpaceBytes, out string applied, out string? refusal)
    {
        applied = string.Empty;
        refusal = null;

        int resource = AddressSpaceResourceId();

        if (!TryGetResourceLimit(resource, out long soft, out long hard))
        {
            refusal = "The worker could not read its own address-space limit.";
            return false;
        }

        // Never raise a limit the host set; only narrow it.
        long target = Math.Min(addressSpaceBytes, hard == Unlimited ? addressSpaceBytes : hard);

        if (!TrySetResourceLimit(resource, target, hard == Unlimited ? target : hard))
        {
            refusal = string.Create(
                CultureInfo.InvariantCulture,
                $"The worker could not set RLIMIT_AS to {target} bytes.");
            return false;
        }

        if (!TryGetResourceLimit(resource, out long appliedSoft, out _) || appliedSoft != target)
        {
            refusal = "The applied address-space limit does not match the requested value.";
            return false;
        }

        applied = string.Create(CultureInfo.InvariantCulture, $"posix-rlimit-as-{appliedSoft}");
        return true;
    }

    /// <summary>
    /// The <c>getrlimit</c>/<c>setrlimit</c> resource id that names the address-space limit on the
    /// only supported POSIX host. Linux numbers it 9. No other POSIX host is supported: an
    /// unsupported host is refused rather than mapped to a different kernel's resource numbering.
    /// </summary>
    internal static int AddressSpaceResourceId() => LinuxResourceAddressSpace;

    private const int LinuxResourceAddressSpace = 9;

    private const long Unlimited = -1;
    private const int JobObjectExtendedLimitInformationClass = JobObjectExtendedLimitInformation;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr attributes, IntPtr name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JobObjectExtendedLimitInformationStructure information,
        int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(
        IntPtr job,
        int informationClass,
        out JobObjectExtendedLimitInformationStructure information,
        int length,
        out int returned);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("libc", EntryPoint = "getrlimit", SetLastError = true)]
    private static extern int GetResourceLimit(int resource, out ResourceLimit limit);

    [DllImport("libc", EntryPoint = "setrlimit", SetLastError = true)]
    private static extern int SetResourceLimit(int resource, ref ResourceLimit limit);

    private static bool TryGetResourceLimit(int resource, out long soft, out long hard)
    {
        soft = 0;
        hard = 0;

        if (GetResourceLimit(resource, out ResourceLimit limit) != 0)
        {
            return false;
        }

        soft = limit.Soft;
        hard = limit.Hard;
        return true;
    }

    private static bool TrySetResourceLimit(int resource, long soft, long hard)
    {
        var limit = new ResourceLimit { Soft = soft, Hard = hard };

        return SetResourceLimit(resource, ref limit) == 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ResourceLimit
    {
        public long Soft;
        public long Hard;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformationStructure
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
}
