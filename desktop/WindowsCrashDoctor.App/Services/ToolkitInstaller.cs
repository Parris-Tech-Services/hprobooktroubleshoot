using System.Text.RegularExpressions;
using WindowsCrashDoctor.Models;

namespace WindowsCrashDoctor.Services;

public static class ToolkitInstaller
{
    public static string BuildInstallCommand(ToolkitTool tool)
    {
        var id = tool.Definition.PackageId;
        if (id is null || !Regex.IsMatch(id, @"\A[A-Za-z0-9]+(?:[A-Za-z0-9.-]*[A-Za-z0-9])?\z"))
            throw new InvalidDataException("This tool has no supported automatic installer.");
        // Catalog values must never become arbitrary PowerShell or a fuzzy package match.
        return "$ErrorActionPreference='Stop'; if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { throw 'WinGet is unavailable. Install Microsoft App Installer from the Microsoft Store, then retry.' }; " +
            $"winget.exe install --id '{id}' --exact --source winget --silent --no-upgrade --accept-source-agreements --accept-package-agreements --disable-interactivity; exit $LASTEXITCODE";
    }

    public static Task<ProcessResult> InstallAsync(ToolkitTool tool, PowerShellRunner runner,
        Action<string>? output, CancellationToken cancellationToken)
        => runner.RunCommandAsync(BuildInstallCommand(tool), output, cancellationToken,
            new ProcessRunOptions(TimeSpan.FromMinutes(15), OperationId: "toolkit.install." + tool.Definition.PackageId));
}
