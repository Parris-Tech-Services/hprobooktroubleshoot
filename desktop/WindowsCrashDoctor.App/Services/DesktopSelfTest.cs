using System.Diagnostics;
using System.IO.Compression;
using System.Text.Json;
using WindowsCrashDoctor.Models;

namespace WindowsCrashDoctor.Services;

public static class DesktopSelfTest
{
    public static int Run()
    {
        var temp = Path.Combine(Path.GetTempPath(), "WindowsCrashDoctorDesktopSelfTest-" + Guid.NewGuid().ToString("N"));
        var errorPath = Path.Combine(Path.GetTempPath(), "WindowsCrashDoctor-selftest-error.txt");
        var progressPath = Path.Combine(Path.GetTempPath(), "WindowsCrashDoctor-selftest-progress.txt");
        Directory.CreateDirectory(temp);

        void Stage(string name)
        {
            try { File.WriteAllText(progressPath, $"{DateTimeOffset.UtcNow:o} {name}"); } catch { }
        }

        try
        {
            if (File.Exists(errorPath)) File.Delete(errorPath);
            if (File.Exists(progressPath)) File.Delete(progressPath);
            Stage("engine-extract");
            var engine = new EngineExtractor();
            engine.EnsureExtracted();

            foreach (var required in new[]
            {
                engine.CollectorPath, engine.CrashDoctorPath, engine.NetworkDoctorPath, engine.TelemetryPath,
                engine.DumpParserPath, engine.WerDoctorPath, engine.IntegrationManagerPath, engine.VersionPath, engine.RegistryPath
            })
                if (!File.Exists(required)) throw new InvalidOperationException($"Embedded engine self-test missing required file: {required}");

            Stage("registry");
            var registry = DiagnosticRegistry.Load(engine.RegistryPath);
            if (registry.Diagnostics.Count < 20 || registry.Diagnostics.Select(x => x.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != registry.Diagnostics.Count)
                throw new InvalidOperationException("Packaged diagnostic registry is incomplete or contains duplicate IDs.");

            File.WriteAllText(Path.Combine(temp, "sensors.csv"),
                "Date,Time,\"Physical Memory Load [%]\",\"Total CPU Usage [%]\",\"CPU Package [C]\",\"Total Activity [%]\"\r\n" +
                "12.9.2026,15:16:14.000,91,42,48,12\r\n" +
                "12.9.2026,15:16:16.000,92,100,52,60\r\n" +
                "12.9.2026,15:16:18.000,90,35,46,18\r\n");

            Stage("engine-analysis");
            var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(powershell)) powershell = "powershell.exe";
            var psi = new ProcessStartInfo(powershell)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
            };
            psi.ArgumentList.Add("-NoProfile"); psi.ArgumentList.Add("-ExecutionPolicy"); psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-File"); psi.ArgumentList.Add(engine.CrashDoctorPath);
            psi.ArgumentList.Add("-EvidencePath"); psi.ArgumentList.Add(temp);
            psi.ArgumentList.Add("-OutputDirectory"); psi.ArgumentList.Add(temp);

            using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start Windows PowerShell for packaged-engine self-test.");
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(60_000))
            {
                try { process.Kill(true); } catch { }
                throw new TimeoutException("Packaged-engine self-test timed out.");
            }
            var stdout = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();
            if (process.ExitCode != 0) throw new InvalidOperationException($"Packaged engine returned {process.ExitCode}. {stdout} {stderr}");

            Stage("report-validation");
            var reportPath = Path.Combine(temp, "crash-doctor-report.json");
            if (!File.Exists(reportPath)) throw new InvalidOperationException("Packaged engine did not create crash-doctor-report.json.");
            using (var report = JsonDocument.Parse(File.ReadAllText(reportPath)))
            {
                if (!report.RootElement.TryGetProperty("Telemetry", out var telemetry) || !telemetry.TryGetProperty("Sensor", out var sensor) ||
                    !sensor.TryGetProperty("Available", out var available) || !available.GetBoolean())
                    throw new InvalidOperationException("Packaged engine did not load embedded telemetry analysis.");
                if (!report.RootElement.TryGetProperty("Product", out var product) || !product.TryGetProperty("EngineVersion", out var engineVersion) ||
                    engineVersion.GetString() != EngineExtractor.EngineVersion)
                    throw new InvalidOperationException("Packaged engine report is missing matching product/build provenance.");
                if (!report.RootElement.TryGetProperty("DiagnosticRegistry", out var registryJson) ||
                    registryJson.GetProperty("RegistryVersion").GetString() != registry.RegistryVersion)
                    throw new InvalidOperationException("Packaged engine report is missing canonical diagnostic-registry provenance.");
                if (report.RootElement.GetProperty("Coverage").GetProperty("ExpectedCount").GetInt32() != registry.Diagnostics.Count)
                    throw new InvalidOperationException("Report coverage is not sourced from the canonical diagnostic registry.");
                if (!report.RootElement.TryGetProperty("CrashHistory", out var crashHistory) || crashHistory.ValueKind != JsonValueKind.Array)
                    throw new InvalidOperationException("Packaged engine report is missing CrashHistory array.");
            }

            Stage("network-doctor-selftest");
            var networkPsi = new ProcessStartInfo(powershell)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
            };
            networkPsi.ArgumentList.Add("-NoProfile");
            networkPsi.ArgumentList.Add("-ExecutionPolicy");
            networkPsi.ArgumentList.Add("Bypass");
            networkPsi.ArgumentList.Add("-File");
            networkPsi.ArgumentList.Add(engine.NetworkDoctorPath);
            networkPsi.ArgumentList.Add("-SelfTest");

            using (var networkProcess = Process.Start(networkPsi) ?? throw new InvalidOperationException("Could not start Network Doctor self-test."))
            {
                var networkStdoutTask = networkProcess.StandardOutput.ReadToEndAsync();
                var networkStderrTask = networkProcess.StandardError.ReadToEndAsync();
                if (!networkProcess.WaitForExit(30_000))
                {
                    try { networkProcess.Kill(true); } catch { }
                    throw new TimeoutException("Network Doctor self-test timed out.");
                }
                var networkStdout = networkStdoutTask.GetAwaiter().GetResult();
                var networkStderr = networkStderrTask.GetAwaiter().GetResult();
                if (networkProcess.ExitCode != 0 || !networkStdout.Contains("Network Doctor self-test passed.", StringComparison.Ordinal))
                    throw new InvalidOperationException($"Network Doctor self-test failed. Exit={networkProcess.ExitCode}. {networkStdout} {networkStderr}");
            }

            Stage("runner-timeout");
            RunRunnerSelfTest();
            Stage("comparison");
            RunComparisonSelfTest();
            Stage("privacy-export");
            RunPrivacyExportSelfTest(temp);
            Stage("toolkit-integration");
            ToolkitSelfTest.Run(temp);
            Stage("complete");
            return 0;
        }
        catch (Exception ex)
        {
            Stage("failed");
            try { File.WriteAllText(errorPath, ex.ToString()); } catch { }
            return 1;
        }
        finally
        {
            try { Directory.Delete(temp, true); } catch { }
        }
    }

    private static void RunRunnerSelfTest()
    {
        var runner = new PowerShellRunner();
        var timed = runner.RunCommandAsync("Start-Sleep -Seconds 2", options: new ProcessRunOptions(TimeSpan.FromMilliseconds(250), OperationId: "self-test-timeout"))
            .GetAwaiter().GetResult();
        if (timed.Status != ProcessExecutionStatus.TimedOut)
            throw new InvalidOperationException($"PowerShell runner timeout classification failed: {timed.Status}.");
        if (timed.Duration > TimeSpan.FromSeconds(5))
            throw new InvalidOperationException("Timed-out PowerShell process was not terminated promptly.");
    }

    private static void RunComparisonSelfTest()
    {
        var previous = new DiagnosticRunHistory
        {
            RunId = "previous", CoveragePercent = 100,
            Findings = new List<FindingSnapshot>
            {
                new() { FindingId = "same", Fingerprint = "aaa", Severity = "Medium", Title = "Same" },
                new() { FindingId = "gone", Fingerprint = "bbb", Severity = "High", Title = "Gone" },
                new() { FindingId = "improve", Fingerprint = "ccc", Severity = "High", Title = "Improve" }
            }
        };
        var currentReport = new CrashDoctorReport
        {
            Coverage = new CoverageInfo { Percent = 100 },
            Findings = new List<DiagnosticFinding>
            {
                new() { Id = "same", Severity = "Medium", Title = "Same" },
                new() { Id = "improve", Severity = "Low", Title = "Improve" },
                new() { Id = "new", Severity = "High", Title = "New" }
            }
        };
        var current = new List<FindingSnapshot>
        {
            new() { FindingId = "same", Fingerprint = "aaa", Severity = "Medium", Title = "Same" },
            new() { FindingId = "improve", Fingerprint = "changed", Severity = "Low", Title = "Improve" },
            new() { FindingId = "new", Fingerprint = "ddd", Severity = "High", Title = "New" }
        };
        var comparison = new RunComparisonService().Compare(currentReport, current, previous);
        if (comparison.NewCount != 1 || comparison.ResolvedCount != 1 || comparison.ImprovedCount != 1 || comparison.UnchangedCount != 1)
            throw new InvalidOperationException("Run comparison semantics regression detected.");
    }

    private static void RunPrivacyExportSelfTest(string tempRoot)
    {
        var source = Path.Combine(tempRoot, "privacy-source");
        Directory.CreateDirectory(source);
        const string bitLockerFixture = "111111-222222-333333-444444-555555-666666-777777-888888";
        var fakeApiKey = string.Concat("sk", "-proj-", new string('A', 32));
        File.WriteAllText(Path.Combine(source, "report.txt"),
            $"User: person@example.com\nPath: C:\\Users\\Joshua\\Desktop\\report.txt\nRecovery: {bitLockerFixture}\nPassword=do-not-export\nApiKey={fakeApiKey}\n");
        File.WriteAllText(Path.Combine(source, "private-key.txt"), "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----");
        File.WriteAllBytes(Path.Combine(source, "raw.evtx"), new byte[] { 1, 2, 3, 4 });

        var service = new PrivacyExportService();
        var plan = service.CreatePlan(source);
        if (plan.IncludedCount != 1 || plan.ExcludedCount != 2 || plan.RedactedFileCount != 1 || plan.SensitiveMatchCount < 5)
            throw new InvalidOperationException($"Privacy export plan was unexpected: include={plan.IncludedCount}, exclude={plan.ExcludedCount}, redacted={plan.RedactedFileCount}, matches={plan.SensitiveMatchCount}.");

        var zipPath = Path.Combine(tempRoot, "privacy-export.zip");
        var result = service.Export(plan, zipPath);
        if (result.IncludedCount != 1 || result.ExcludedCount != 2 || result.TotalRedactions < 5)
            throw new InvalidOperationException("Privacy export result did not preserve the preview policy/redactions.");

        using var archive = ZipFile.OpenRead(zipPath);
        if (archive.GetEntry("raw.evtx") is not null || archive.GetEntry("private-key.txt") is not null)
            throw new InvalidOperationException("Privacy export included a high-risk artefact that should have been excluded.");
        var manifestEntry = archive.GetEntry("export-manifest.json") ?? throw new InvalidOperationException("Privacy export did not include export-manifest.json.");
        using (var manifestReader = new StreamReader(manifestEntry.Open()))
        {
            var manifest = manifestReader.ReadToEnd();
            if (manifest.Contains(fakeApiKey, StringComparison.Ordinal) || manifest.Contains(bitLockerFixture, StringComparison.Ordinal))
                throw new InvalidOperationException("Privacy manifest exposed a matched secret value.");
            if (!manifest.Contains("sensitiveMatches", StringComparison.Ordinal))
                throw new InvalidOperationException("Privacy manifest omitted secret-scan metadata.");
        }

        var reportEntry = archive.GetEntry("report.txt") ?? throw new InvalidOperationException("Privacy export omitted the expected report derivative.");
        using var reader = new StreamReader(reportEntry.Open());
        var exportedText = reader.ReadToEnd();
        if (exportedText.Contains("person@example.com", StringComparison.OrdinalIgnoreCase) || exportedText.Contains(bitLockerFixture, StringComparison.Ordinal) ||
            exportedText.Contains("do-not-export", StringComparison.Ordinal) || exportedText.Contains(fakeApiKey, StringComparison.Ordinal))
            throw new InvalidOperationException("Privacy export left a known sensitive fixture unredacted.");
        if (!exportedText.Contains("[REDACTED_EMAIL]", StringComparison.Ordinal) || !exportedText.Contains("[REDACTED_BITLOCKER_RECOVERY_PASSWORD]", StringComparison.Ordinal) ||
            !exportedText.Contains("[REDACTED_SECRET]", StringComparison.Ordinal) || !exportedText.Contains("[REDACTED_API_KEY]", StringComparison.Ordinal))
            throw new InvalidOperationException("Privacy export did not emit expected redaction markers.");
    }
}
