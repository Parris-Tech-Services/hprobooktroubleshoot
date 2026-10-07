using System.Security.Principal;
using WindowsCrashDoctor.Models;

namespace WindowsCrashDoctor.Services;

public sealed class PreflightService
{
    public async Task<PreflightReport> RunAsync(
        string outputRoot,
        EngineExtractor engine,
        HistoryService history,
        PowerShellRunner runner,
        DiagnosticRegistry registry,
        CancellationToken cancellationToken = default)
    {
        var report = new PreflightReport { CheckedAt = DateTimeOffset.UtcNow };
        void Add(string id, string name, string state, string detail, bool blocking = false) =>
            report.Items.Add(new PreflightItem { Id = id, Name = name, State = state, Detail = detail, Blocking = blocking });

        Add("platform", "Windows platform", OperatingSystem.IsWindows() ? "healthy" : "unavailable",
            OperatingSystem.IsWindows() ? Environment.OSVersion.VersionString : "Windows Crash Doctor requires Windows.", blocking: true);

        var admin = IsAdministrator();
        Add("administrator", "Administrator rights", admin ? "healthy" : "degraded",
            admin ? "Running elevated." : "Some collectors require elevation; the app will request it when a full diagnosis starts.");

        try
        {
            engine.EnsureExtracted();
            var required = new[] { engine.CollectorPath, engine.CrashDoctorPath, engine.RegistryPath, engine.VersionPath };
            var missing = required.Where(x => !File.Exists(x)).ToList();
            Add("engine", "Embedded diagnostic engine", missing.Count == 0 ? "healthy" : "unavailable",
                missing.Count == 0 ? $"Engine {EngineExtractor.EngineVersion} extracted successfully." : "Missing: " + string.Join(", ", missing.Select(Path.GetFileName)), blocking: missing.Count > 0);
        }
        catch (Exception ex)
        {
            Add("engine", "Embedded diagnostic engine", "unavailable", ex.Message, blocking: true);
        }

        Add("registry", "Diagnostic registry", registry.Diagnostics.Count > 0 ? "healthy" : "unavailable",
            $"Registry {registry.RegistryVersion}; {registry.Diagnostics.Count} diagnostic definitions.", blocking: registry.Diagnostics.Count == 0);

        try
        {
            Directory.CreateDirectory(outputRoot);
            var probe = Path.Combine(outputRoot, $".wcd-write-{Guid.NewGuid():N}.tmp");
            await File.WriteAllTextAsync(probe, "probe", cancellationToken);
            File.Delete(probe);
            var root = Path.GetPathRoot(outputRoot) ?? outputRoot;
            var drive = new DriveInfo(root);
            var freeGb = drive.AvailableFreeSpace / 1024d / 1024d / 1024d;
            Add("output", "Evidence output", freeGb < 0.5 ? "unavailable" : freeGb < 1 ? "degraded" : "healthy",
                $"Writable; {freeGb:0.0} GiB free.", blocking: freeGb < 0.25);
        }
        catch (Exception ex)
        {
            Add("output", "Evidence output", "unavailable", "Output directory is not writable: " + ex.Message, blocking: true);
        }

        Add("history", "SQLite run ledger", history.CheckHealth(out var historyDetail) ? "healthy" : "unavailable", historyDetail);

        var ps = await runner.RunCommandAsync("$PSVersionTable.PSVersion.ToString()", cancellationToken: cancellationToken,
            options: new ProcessRunOptions(TimeSpan.FromSeconds(12), OperationId: "preflight.powershell"));
        Add("powershell", "Windows PowerShell", ps.Succeeded ? "healthy" : "unavailable",
            ps.Succeeded ? "PowerShell " + ps.StandardOutput.Trim() : (ps.FailureReason ?? "PowerShell unavailable."), blocking: !ps.Succeeded);

        var cim = await runner.RunCommandAsync("(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption", cancellationToken: cancellationToken,
            options: new ProcessRunOptions(TimeSpan.FromSeconds(15), OperationId: "preflight.cim"));
        Add("cim", "WMI/CIM access", cim.Succeeded ? "healthy" : "degraded",
            cim.Succeeded ? cim.StandardOutput.Trim() : (cim.FailureReason ?? "CIM query failed."));

        var events = await runner.RunCommandAsync("(Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction Stop).Id", cancellationToken: cancellationToken,
            options: new ProcessRunOptions(TimeSpan.FromSeconds(15), OperationId: "preflight.eventlog"));
        Add("eventlog", "Windows Event Log", events.Succeeded ? "healthy" : "degraded",
            events.Succeeded ? "System event log is readable." : (events.FailureReason ?? "System event log is not readable."));

        var dump = await runner.RunCommandAsync("$v=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -ErrorAction SilentlyContinue).CrashDumpEnabled; if($null -eq $v){'not-configured'}else{$v}", cancellationToken: cancellationToken,
            options: new ProcessRunOptions(TimeSpan.FromSeconds(12), OperationId: "preflight.dumps"));
        var dumpValue = dump.StandardOutput.Trim();
        Add("dump-readiness", "Crash dump configuration", dump.Succeeded && dumpValue != "0" && dumpValue != "not-configured" ? "healthy" : "degraded",
            dump.Succeeded ? $"CrashDumpEnabled={dumpValue}." : (dump.FailureReason ?? "Dump configuration could not be read."));

        var debugger = FindDebugger();
        Add("debugger", "WinDbg/cdb", debugger is null ? "not-configured" : "healthy",
            debugger is null ? "Optional debugger not found; native header parsing remains available." : debugger);

        var symbolPath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
        if (string.IsNullOrWhiteSpace(symbolPath)) symbolPath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH", EnvironmentVariableTarget.User);
        if (string.IsNullOrWhiteSpace(symbolPath)) symbolPath = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH", EnvironmentVariableTarget.Machine);
        Add("symbols", "Debugger symbols", string.IsNullOrWhiteSpace(symbolPath) ? "not-configured" : "healthy",
            string.IsNullOrWhiteSpace(symbolPath) ? "No _NT_SYMBOL_PATH configured; only relevant to symbolized dump analysis." : "Symbol path is configured.");

        var sensorProvider = FindSensorProvider();
        Add("sensors", "Deep sensor provider", sensorProvider is null ? "not-configured" : "healthy",
            sensorProvider ?? "LibreHardwareMonitor/HWiNFO not detected; optional integration can install or configure a provider.");

        report.OverallState = report.Items.Any(x => x.Blocking && x.State == "unavailable") ? "unavailable"
            : report.Items.Any(x => x.State is "degraded" or "unavailable") ? "degraded" : "healthy";
        return report;
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string? FindDebugger()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "WinDbgX.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Kits", "10", "Debuggers", "x64", "cdb.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Kits", "10", "Debuggers", "x64", "cdb.exe")
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static string? FindSensorProvider()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "HWiNFO64", "HWiNFO64.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WindowsCrashDoctor", "Tools", "librehardwaremonitor", "LibreHardwareMonitorLib.dll"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WindowsCrashDoctor", "providers", "librehardwaremonitor", "LibreHardwareMonitorLib.dll")
        };
        return candidates.FirstOrDefault(File.Exists);
    }
}
