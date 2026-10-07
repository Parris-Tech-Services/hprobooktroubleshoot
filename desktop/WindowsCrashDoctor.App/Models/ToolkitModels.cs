namespace WindowsCrashDoctor.Models;

public sealed class ToolkitTool
{
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Url { get; set; } = "";
    public string Todo { get; set; } = "";
    public string Note { get; set; } = "";
    public string Status { get; set; } = "Not detected";
    public string? Executable { get; set; }
    public string? Version { get; set; }
    public ToolkitDefinition Definition { get; set; } = new();
    public override string ToString() => Name;
}

public sealed class ToolkitDefinition
{
    public string[] Executables { get; set; } = [];
    public string[] Arguments { get; set; } = [];
    public string? ProviderId { get; set; }
    public string? PackageId { get; set; }
    public string? ConsoleHint { get; set; }
    public List<ToolkitAction> Actions { get; set; } = [];
}

public sealed class ToolkitAction
{
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public bool ChangesSystem { get; set; }
    public bool RequiresAdmin { get; set; }
    public int TimeoutSeconds { get; set; } = 45;
    public override string ToString() => Name;
}

public sealed record ToolkitEvidence(string Directory, string Artifact, string Sha256);
