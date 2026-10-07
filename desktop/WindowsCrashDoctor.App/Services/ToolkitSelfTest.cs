using System.Security.Cryptography;
using System.Text.Json;
using WindowsCrashDoctor.Models;

namespace WindowsCrashDoctor.Services;

public static class ToolkitSelfTest
{
    public static void Run(string root)
    {
        var service = new ToolkitService(Path.Combine(root, "toolkit-paths.json"));
        if (service.Tools.Count < 208 || service.Tools.Select(t => t.Name).Distinct().Count() != service.Tools.Count)
            throw new InvalidOperationException("Toolkit catalog is incomplete or contains duplicate names.");
        if (service.Tools.Count(t => t.Definition.Actions.Count > 0) < 45)
            throw new InvalidOperationException("Toolkit action definitions did not load.");
        service.Refresh();
        var events = service.Tools.Single(t => t.Name == "Event Viewer");
        if (events.Executable is null) throw new InvalidOperationException("Built-in Event Viewer launcher was not detected.");
        var fixture = new ToolkitTool { Name = "Toolkit self-test", Category = "Fixture" };
        var action = new ToolkitAction { Name = "Read-only fixture", Command = "Write-Output 'toolkit-capture-ok'" };
        fixture.Definition.Actions.Add(action);
        var runner = new PowerShellRunner();
        var success = service.RunReadOnlyAsync(fixture, action, root, runner, null, CancellationToken.None).GetAwaiter().GetResult();
        if (!success.Result.Succeeded || !File.ReadAllText(Path.Combine(success.Directory, "output.txt")).Contains("toolkit-capture-ok"))
            throw new InvalidOperationException("Toolkit action output was not captured.");

        var failure = new ToolkitAction { Name = "Native failure fixture", Command = "cmd.exe /c exit 7" };
        fixture.Definition.Actions.Add(failure);
        var failed = service.RunReadOnlyAsync(fixture, failure, root, runner, null, CancellationToken.None).GetAwaiter().GetResult();
        if (failed.Result.Succeeded || failed.Result.ExitCode != 7)
            throw new InvalidOperationException("Toolkit reported a failed native command as success.");
        var repair = new ToolkitAction { Name = "Must not run", ChangesSystem = true, Command = "throw 'must not execute'" };
        fixture.Definition.Actions.Add(repair);
        Expect<InvalidOperationException>(() => service.RunReadOnlyAsync(fixture, repair, root, runner, null, CancellationToken.None).GetAwaiter().GetResult());
        Expect<InvalidOperationException>(() => service.RunReadOnlyAsync(fixture, new ToolkitAction { Command = "Write-Output 'unregistered'" }, root, runner, null, CancellationToken.None).GetAwaiter().GetResult());

        var original = Path.Combine(root, "external-report.txt");
        const string privateFixture = "Operator person@example.com; Password=private-fixture-value";
        File.WriteAllText(original, privateFixture);
        var attachment = service.ImportEvidenceAsync(fixture, original, root).GetAwaiter().GetResult();
        if (File.ReadAllText(original) != privateFixture || File.ReadAllText(attachment.Artifact) != privateFixture)
            throw new InvalidOperationException("Toolkit import modified the original report.");
        if (attachment.Sha256 != Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(original))).ToLowerInvariant())
            throw new InvalidOperationException("Toolkit attachment hash does not match the source.");
        using (var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(attachment.Directory, "toolkit-evidence.json"))))
            if (manifest.RootElement.GetProperty("tool").GetString() != fixture.Name)
                throw new InvalidOperationException("Toolkit report provenance was lost.");
        var privacy = new PrivacyExportService();
        var plan = privacy.CreatePlan(attachment.Directory);
        if (plan.SensitiveMatchCount < 2) throw new InvalidOperationException("Toolkit report privacy review missed known secrets.");

        var large = Path.Combine(root, "oversized-report.txt");
        using (var file = File.Create(large)) file.SetLength(100L * 1024 * 1024 + 1);
        Expect<InvalidDataException>(() => service.ImportEvidenceAsync(fixture, large, root).GetAwaiter().GetResult());
        Expect<InvalidDataException>(() => service.ConfigureExecutable(fixture, original));
        var malformedSettings = Path.Combine(root, "invalid-paths.json");
        File.WriteAllText(malformedSettings, "not-json");
        Expect<JsonException>(() => new ToolkitService(malformedSettings));
    }

    private static void Expect<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Toolkit self-test expected {typeof(T).Name}.");
    }
}
