using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using WindowsCrashDoctor.Models;

namespace WindowsCrashDoctor.Services;

public sealed class ToolkitService
{
    private const long MaxEvidenceBytes = 100 * 1024 * 1024;
    private readonly string _settingsPath;
    private readonly Dictionary<string, string> _configuredPaths;
    private readonly RedactionService _redaction = new();
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    public List<ToolkitTool> Tools { get; }

    public ToolkitService(string? settingsPath = null)
    {
        _settingsPath = settingsPath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WindowsCrashDoctor", "toolkit-paths.json");
        _configuredPaths = File.Exists(_settingsPath)
            ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_settingsPath), JsonOptions)
                ?? throw new InvalidDataException("Toolkit path settings are invalid.")
            : new(StringComparer.OrdinalIgnoreCase);
        using var catalog = OpenResource("WCD.Toolkit.Data.tsv");
        using var reader = new StreamReader(catalog);
        _ = reader.ReadLine();
        using var definitions = OpenResource("WCD.Toolkit.Actions.json");
        var mappings = JsonSerializer.Deserialize<Dictionary<string, ToolkitDefinition>>(definitions, JsonOptions)
            ?? throw new InvalidDataException("Toolkit actions are invalid.");
        Tools = [];
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var fields = line.Split('\t');
            if (fields.Length != 5 || !Uri.TryCreate(fields[2], UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
                throw new InvalidDataException("Toolkit entry is malformed.");
            if (Tools.Any(x => x.Name.Equals(fields[1], StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Duplicate toolkit name.");
            Tools.Add(new ToolkitTool
            {
                Category = fields[0], Name = fields[1], Url = fields[2], Todo = fields[3], Note = fields[4],
                Definition = mappings.GetValueOrDefault(fields[1]) ?? new()
            });
        }
        foreach (var tool in Tools)
            foreach (var action in tool.Definition.Actions)
                if (string.IsNullOrWhiteSpace(action.Command) || action.TimeoutSeconds is < 1 or > 3600)
                    throw new InvalidDataException($"Invalid action for {tool.Name}.");
    }

    private static Stream OpenResource(string name) => Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
        ?? throw new InvalidOperationException($"Missing embedded resource: {name}");

    public void Refresh()
    {
        var installedDirectories = InstalledDirectories();
        foreach (var tool in Tools)
        {
            var configured = _configuredPaths.GetValueOrDefault(tool.Name);
            tool.Executable = configured is null ? FindExecutable(tool.Definition.Executables, installedDirectories)
                : File.Exists(configured) ? configured : null;
            if (configured is null && tool.Definition.Arguments.FirstOrDefault() is { } console && console.EndsWith(".msc", StringComparison.OrdinalIgnoreCase)
                && !File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), console)))
                tool.Executable = null;
            tool.Status = tool.Executable is not null ? "Available"
                : configured is not null ? "Configured file missing"
                : tool.Definition.Executables.Length == 0 ? "External / boot / service"
                : "Not detected";
            tool.Version = null;
            if (tool.Executable is not null)
            {
                try { tool.Version = FileVersionInfo.GetVersionInfo(tool.Executable).FileVersion; }
                catch (IOException) { }
            }
        }
    }

    public void ConfigureExecutable(ToolkitTool tool, string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath) || !Path.GetExtension(fullPath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Select an existing Windows .exe file.");
        _configuredPaths[tool.Name] = fullPath;
        Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
        var temporary = _settingsPath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(_configuredPaths, JsonOptions));
        File.Move(temporary, _settingsPath, overwrite: true);
        tool.Executable = fullPath;
        tool.Status = "Available";
    }

    public void Launch(ToolkitTool tool)
    {
        var path = tool.Executable ?? throw new FileNotFoundException("Tool not detected. Select its installed executable first.");
        if (!File.Exists(path)) throw new FileNotFoundException("The configured tool no longer exists.", path);
        var start = new ProcessStartInfo(path) { UseShellExecute = true };
        foreach (var argument in tool.Definition.Arguments) start.ArgumentList.Add(argument);
        Process.Start(start);
    }

    public static void OpenWebsite(ToolkitTool tool)
    {
        if (!Uri.TryCreate(tool.Url, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
            throw new InvalidDataException("Only HTTPS toolkit links are supported.");
        Process.Start(new ProcessStartInfo(tool.Url) { UseShellExecute = true });
    }

    public void OpenDump(ToolkitTool tool, string dumpPath)
    {
        if (tool.Name != "WinDbg / cdb" || tool.Executable is null || !File.Exists(tool.Executable))
            throw new InvalidOperationException("Select an available WinDbg/cdb debugger.");
        if (!File.Exists(dumpPath) || Path.GetExtension(dumpPath).ToLowerInvariant() is not (".dmp" or ".mdmp"))
            throw new InvalidDataException("Select an existing .dmp or .mdmp file.");
        var start = new ProcessStartInfo(tool.Executable) { UseShellExecute = true };
        start.ArgumentList.Add("-z"); start.ArgumentList.Add(Path.GetFullPath(dumpPath));
        var symbols = Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH", EnvironmentVariableTarget.User)
            ?? Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH");
        if (!string.IsNullOrWhiteSpace(symbols)) { start.ArgumentList.Add("-y"); start.ArgumentList.Add(symbols); }
        Process.Start(start);
    }

    public async Task<ToolkitEvidence> ImportEvidenceAsync(ToolkitTool tool, string source, string outputRoot,
        CancellationToken cancellationToken = default)
    {
        var info = new FileInfo(source);
        if (!info.Exists || info.Length > MaxEvidenceBytes)
            throw new InvalidDataException("Select an existing report of at most 100 MiB. Large dumps/traces can use the dedicated analysis tools.");
        var directory = NewEvidenceDirectory(outputRoot);
        var destination = Path.Combine(directory, "artifact" + Path.GetExtension(info.Name));
        try
        {
            await using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
            await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[64 * 1024];
                long total = 0;
                int read;
                while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
                {
                    total += read;
                    if (total > MaxEvidenceBytes) throw new InvalidDataException("Report grew beyond the import limit.");
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
            }
            await using var content = File.OpenRead(destination);
            var sha = Convert.ToHexString(await SHA256.HashDataAsync(content, cancellationToken)).ToLowerInvariant();
            var manifest = new
            {
                schemaVersion = "1.0", importedAtUtc = DateTimeOffset.UtcNow, tool = tool.Name,
                category = tool.Category, version = tool.Version, sourceFileName = info.Name,
                artifact = Path.GetFileName(destination), sha256 = sha, interpretation = "External report attached; not automatically diagnosed",
                sensitivity = "private", verified = "Artifact hash measured locally; vendor conclusions not independently verified"
            };
            await File.WriteAllTextAsync(Path.Combine(directory, "toolkit-evidence.json"), JsonSerializer.Serialize(manifest, JsonOptions), cancellationToken);
            return new(directory, destination, sha);
        }
        catch
        {
            // Only delete our own unique, bounded staging directory after a failed import.
            Directory.Delete(directory, recursive: true);
            throw;
        }
    }

    public async Task<(string Directory, ProcessResult Result)> RunReadOnlyAsync(ToolkitTool tool, ToolkitAction action,
        string outputRoot, PowerShellRunner runner, Action<string>? onOutput, CancellationToken cancellationToken)
    {
        if (action.ChangesSystem) throw new InvalidOperationException("System-changing actions must use the explicit console handoff.");
        EnsureOwnedAction(tool, action);
        var directory = NewEvidenceDirectory(outputRoot);
        var script = Path.Combine(directory, "action.ps1");
        await File.WriteAllTextAsync(script, "$ErrorActionPreference = 'Stop'\nSet-Location -LiteralPath $PSScriptRoot\n$global:LASTEXITCODE = 0\n" +
            action.Command + "\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n", cancellationToken);
        var result = await runner.RunFileAsync(script, onOutput: onOutput, cancellationToken: cancellationToken,
            options: new ProcessRunOptions(TimeSpan.FromSeconds(action.TimeoutSeconds), OperationId: "toolkit." + tool.Name));
        await File.WriteAllTextAsync(Path.Combine(directory, "output.txt"), _redaction.RedactForLog(result.StandardOutput));
        await File.WriteAllTextAsync(Path.Combine(directory, "error.txt"), _redaction.RedactForLog(result.StandardError));
        await File.WriteAllTextAsync(Path.Combine(directory, "toolkit-execution.json"), JsonSerializer.Serialize(new
        {
            schemaVersion = "1.0", tool = tool.Name, action = action.Name, command = action.Command,
            result.StartedAt, result.FinishedAt, status = result.Status.ToString(), result.ExitCode,
            result.FailureReason, sensitivity = "private"
        }, JsonOptions));
        return (directory, result);
    }

    public string LaunchActionConsole(ToolkitTool tool, ToolkitAction action, string outputRoot)
    {
        EnsureOwnedAction(tool, action);
        var directory = NewEvidenceDirectory(outputRoot);
        var script = Path.Combine(directory, "action.ps1");
        var transcript = Path.Combine(directory, "console-transcript.txt").Replace("'", "''");
        var scriptBody = "$ErrorActionPreference = 'Stop'\nSet-Location -LiteralPath $PSScriptRoot\n$global:LASTEXITCODE = 0\nStart-Transcript -LiteralPath '" + transcript + "'\n" +
            "try {\n" + action.Command + "\nif ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw \"Native command exited $LASTEXITCODE\" }\n" +
            "Write-Host 'Action finished; review the output before concluding the issue is repaired.'\n} finally { Stop-Transcript }";
        File.WriteAllText(script, scriptBody);
        var start = new ProcessStartInfo(SystemPowerShell()) { UseShellExecute = true };
        if (action.RequiresAdmin) start.Verb = "runas";
        foreach (var argument in new[] { "-NoProfile", "-NoExit", "-ExecutionPolicy", "Bypass", "-File", script })
            start.ArgumentList.Add(argument);
        Process.Start(start);
        File.WriteAllText(Path.Combine(directory, "toolkit-handoff.json"), JsonSerializer.Serialize(new
        {
            schemaVersion = "1.0", tool = tool.Name, action = action.Name, action.Command,
            startedAtUtc = DateTimeOffset.UtcNow, status = "Console launched; completion not observed", sensitivity = "private"
        }, JsonOptions));
        return directory;
    }

    private static void EnsureOwnedAction(ToolkitTool tool, ToolkitAction action)
    {
        if (!tool.Definition.Actions.Contains(action)) throw new InvalidOperationException("Unknown toolkit action.");
    }

    public static string SystemPowerShell() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
        "WindowsPowerShell", "v1.0", "powershell.exe");

    private static string NewEvidenceDirectory(string root)
    {
        var directory = Path.Combine(root, "Toolkit", DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static List<string> InstalledDirectories()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var registry = RegistryKey.OpenBaseKey(hive, view);
            using var uninstall = registry.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if (uninstall is null) continue;
            foreach (var name in uninstall.GetSubKeyNames())
            {
                using var entry = uninstall.OpenSubKey(name);
                if (entry?.GetValue("InstallLocation") is string location && Directory.Exists(location)) paths.Add(location);
                if (entry?.GetValue("DisplayIcon") is string icon)
                {
                    var executable = icon.Split(',')[0].Trim('"');
                    if (Path.IsPathFullyQualified(executable) && File.Exists(executable))
                        paths.Add(Path.GetDirectoryName(executable)!);
                }
            }
        }
        foreach (var root in new[] {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WinGet", "Packages"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinGet", "Packages") })
        {
            if (!Directory.Exists(root)) continue;
            foreach (var directory in Directory.EnumerateDirectories(root).Take(1000)) paths.Add(directory);
        }
        return paths.Take(2000).ToList();
    }

    private static string? FindExecutable(IEnumerable<string> names, List<string> installedDirectories)
    {
        var roots = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Concat((Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "").Split(Path.PathSeparator))
            .Concat((Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "").Split(Path.PathSeparator))
            .Concat(installedDirectories)
            .Concat(new[] { Environment.GetFolderPath(Environment.SpecialFolder.System), Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WinGet", "Links"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinGet", "Links"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WindowsCrashDoctor", "Tools"),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
            .Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var name in names)
        {
            var expanded = Environment.ExpandEnvironmentVariables(name);
            if (Path.IsPathFullyQualified(expanded) && File.Exists(expanded)) return expanded;
            foreach (var root in roots)
            {
                var candidate = Path.Combine(root.Trim('"'), expanded);
                if (File.Exists(candidate)) return candidate;
            }
        }
        return null;
    }
}
