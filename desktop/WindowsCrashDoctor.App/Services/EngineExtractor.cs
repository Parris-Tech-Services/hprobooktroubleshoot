using System.Reflection;
using System.Text.Json;

namespace WindowsCrashDoctor.Services;

public sealed class EngineExtractor
{
    public const string EngineVersion = "0.3.0";

    private static readonly IReadOnlyDictionary<string, string> Resources =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["WCD.Engine.scripts.collect-diagnostics.ps1"] = Path.Combine("scripts", "collect-diagnostics.ps1"),
            ["WCD.Engine.scripts.check-public-evidence.ps1"] = Path.Combine("scripts", "check-public-evidence.ps1"),
            ["WCD.Engine.windows-crash-doctor.CrashDoctor.psm1"] = Path.Combine("windows-crash-doctor", "CrashDoctor.psm1"),
            ["WCD.Engine.windows-crash-doctor.TelemetryAnalysis.psm1"] = Path.Combine("windows-crash-doctor", "TelemetryAnalysis.psm1"),
            ["WCD.Engine.windows-crash-doctor.DumpParser.psm1"] = Path.Combine("windows-crash-doctor", "DumpParser.psm1"),
            ["WCD.Engine.windows-crash-doctor.Invoke-CrashDoctor.ps1"] = Path.Combine("windows-crash-doctor", "Invoke-CrashDoctor.ps1"),
            ["WCD.Engine.windows-crash-doctor.NetworkDoctor.ps1"] = Path.Combine("windows-crash-doctor", "NetworkDoctor.ps1"),
            ["WCD.Engine.windows-crash-doctor.DiagnosticRegistry.psm1"] = Path.Combine("windows-crash-doctor", "DiagnosticRegistry.psm1"),
            ["WCD.Engine.windows-crash-doctor.diagnostics.registry.json"] = Path.Combine("windows-crash-doctor", "diagnostics", "registry.json"),
            ["WCD.Engine.windows-crash-doctor.Integrations.psm1"] = Path.Combine("windows-crash-doctor", "Integrations.psm1"),
            ["WCD.Engine.windows-crash-doctor.Manage-Integrations.ps1"] = Path.Combine("windows-crash-doctor", "Manage-Integrations.ps1"),
            ["WCD.Engine.windows-crash-doctor.version.json"] = Path.Combine("windows-crash-doctor", "version.json"),
            ["WCD.Engine.windows-crash-doctor.integrations.catalog.json"] = Path.Combine("windows-crash-doctor", "integrations", "catalog.json"),
            ["WCD.Engine.windows-crash-doctor.WerDoctor.psm1"] = Path.Combine("windows-crash-doctor", "WerDoctor.psm1"),
            ["WCD.Engine.windows-crash-doctor.SymbolServer.psm1"] = Path.Combine("windows-crash-doctor", "SymbolServer.psm1")
        };

    public string RootPath { get; }
    public string CollectorPath => Path.Combine(RootPath, "scripts", "collect-diagnostics.ps1");
    public string CrashDoctorPath => Path.Combine(RootPath, "windows-crash-doctor", "Invoke-CrashDoctor.ps1");
    public string NetworkDoctorPath => Path.Combine(RootPath, "windows-crash-doctor", "NetworkDoctor.ps1");
    public string TelemetryPath => Path.Combine(RootPath, "windows-crash-doctor", "TelemetryAnalysis.psm1");
    public string DumpParserPath => Path.Combine(RootPath, "windows-crash-doctor", "DumpParser.psm1");
    public string WerDoctorPath => Path.Combine(RootPath, "windows-crash-doctor", "WerDoctor.psm1");
    public string SymbolServerPath => Path.Combine(RootPath, "windows-crash-doctor", "SymbolServer.psm1");
    public string IntegrationManagerPath => Path.Combine(RootPath, "windows-crash-doctor", "Manage-Integrations.ps1");
    public string VersionPath => Path.Combine(RootPath, "windows-crash-doctor", "version.json");
    public string RegistryPath => Path.Combine(RootPath, "windows-crash-doctor", "diagnostics", "registry.json");

    public EngineExtractor()
    {
        RootPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WindowsCrashDoctor",
            "engine",
            EngineVersion);
    }

    public void EnsureExtracted()
    {
        var assembly = Assembly.GetExecutingAssembly();
        foreach (var (resourceName, relativePath) in Resources)
        {
            using var stream = assembly.GetManifestResourceStream(resourceName)
                ?? throw new InvalidOperationException($"Embedded diagnostic resource is missing: {resourceName}");

            var destination = Path.Combine(RootPath, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            using var output = File.Create(destination);
            stream.CopyTo(output);
        }

        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion ?? assembly.GetName().Version?.ToString() ?? "unknown";
        var commit = informationalVersion.Contains('+')
            ? informationalVersion[(informationalVersion.IndexOf('+') + 1)..]
            : "unknown";

        var buildInfo = new
        {
            appVersion = informationalVersion,
            engineVersion = EngineVersion,
            commit,
            extractedAtUtc = DateTimeOffset.UtcNow.ToString("O")
        };
        var buildInfoPath = Path.Combine(RootPath, "windows-crash-doctor", "build-info.json");
        File.WriteAllText(buildInfoPath, JsonSerializer.Serialize(buildInfo, new JsonSerializerOptions { WriteIndented = true }));
    }
}
