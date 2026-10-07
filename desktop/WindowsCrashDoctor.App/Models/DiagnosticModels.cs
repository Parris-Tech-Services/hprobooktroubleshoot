using System.Text.Json.Serialization;
using System.Windows.Media;

namespace WindowsCrashDoctor.Models;

public sealed class CrashDoctorReport
{
    public string? SchemaVersion { get; set; }
    public DateTimeOffset? GeneratedAt { get; set; }
    public string? EvidencePath { get; set; }
    public ProductInfo Product { get; set; } = new();
    public CoverageInfo Coverage { get; set; } = new();
    public InventoryInfo Inventory { get; set; } = new();
    public EventSummaryInfo EventSummary { get; set; } = new();
    public List<DiagnosticFinding> Findings { get; set; } = new();
    public RunMetadata? Run { get; set; }
    public PreflightReport? Preflight { get; set; }
    public List<CollectorExecutionRecord> CollectorExecutions { get; set; } = new();
    public RunComparisonSummary? Comparison { get; set; }
    public RegistryProvenance? DiagnosticRegistry { get; set; }
    public List<CrashHistoryRecord> CrashHistory { get; set; } = new();
}

public sealed class ProductInfo
{
    public string? ProductVersion { get; set; }
    public string? EngineVersion { get; set; }
    public string? CollectorVersion { get; set; }
    public string? RuleSetVersion { get; set; }
    public string? SchemaVersion { get; set; }
    public string? Commit { get; set; }
}

public sealed class CoverageInfo
{
    public List<string> PresentFiles { get; set; } = new();
    public List<string> MissingFiles { get; set; } = new();
    public int PresentCount { get; set; }
    public int ExpectedCount { get; set; }
    public double Percent { get; set; }
}

public sealed class InventoryInfo
{
    public string? Model { get; set; }
    public string? BIOS { get; set; }
    public double? PhysicalMemoryGiB { get; set; }
}

public sealed class EventSummaryInfo
{
    public int WHEAReferences { get; set; }
    public int KernelPower41Records { get; set; }
    public int Volmgr161Records { get; set; }
}

public sealed class DiagnosticFinding
{
    public string Id { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string Confidence { get; set; } = "Medium";
    public string Title { get; set; } = "";
    public string Evidence { get; set; } = "";
    public string Interpretation { get; set; } = "";
    public string NextStep { get; set; } = "";
    public string? Fingerprint { get; set; }
    public string? RuleVersion { get; set; }
    public string? SourceCollector { get; set; }
    public string? ComparisonState { get; set; }

    [JsonIgnore]
    public Brush SeverityBrush => Severity switch
    {
        "Critical" or "High" => new SolidColorBrush(Color.FromRgb(217, 45, 32)),
        "Medium" => new SolidColorBrush(Color.FromRgb(220, 104, 3)),
        "Low" => new SolidColorBrush(Color.FromRgb(37, 99, 235)),
        _ => new SolidColorBrush(Color.FromRgb(3, 152, 85))
    };

    [JsonIgnore]
    public Brush SeverityBackground => Severity switch
    {
        "Critical" or "High" => new SolidColorBrush(Color.FromRgb(254, 243, 242)),
        "Medium" => new SolidColorBrush(Color.FromRgb(255, 246, 232)),
        "Low" => new SolidColorBrush(Color.FromRgb(234, 241, 255)),
        _ => new SolidColorBrush(Color.FromRgb(236, 253, 243))
    };
}

public sealed class RunMetadata
{
    public string RunId { get; set; } = "";
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset FinishedAt { get; set; }
    public long DurationMs { get; set; }
    public string DeviceFingerprint { get; set; } = "";
    public string EvidenceBundleHash { get; set; } = "";
    public string Status { get; set; } = "completed";
}

public sealed class RegistryProvenance
{
    public string RegistryVersion { get; set; } = "unknown";
    public string SchemaVersion { get; set; } = "unknown";
    public int DiagnosticCount { get; set; }
}

public sealed class CollectorExecutionRecord
{
    public string DiagnosticId { get; set; } = "";
    public string Name { get; set; } = "";
    public string EvidenceFile { get; set; } = "";
    public string Status { get; set; } = "unavailable";
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public long DurationMs { get; set; }
    public int? ExitCode { get; set; }
    public int RetryCount { get; set; }
    public string? FailureReason { get; set; }
}

public sealed class PreflightReport
{
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.UtcNow;
    public string OverallState { get; set; } = "unknown";
    public List<PreflightItem> Items { get; set; } = new();

    [JsonIgnore]
    public int BlockingCount => Items.Count(x => x.Blocking && x.State is "unavailable");

    [JsonIgnore]
    public int DegradedCount => Items.Count(x => x.State is "degraded" or "unavailable" or "not-configured");
}

public sealed class PreflightItem
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string State { get; set; } = "unknown";
    public string Detail { get; set; } = "";
    public bool Blocking { get; set; }
}

public sealed class FindingSnapshot
{
    public string FindingId { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string Confidence { get; set; } = "Medium";
    public string Title { get; set; } = "";
    public string Evidence { get; set; } = "";
    public string SourceCollector { get; set; } = "";
    public string RuleVersion { get; set; } = "";
}

public sealed class ComparisonItem
{
    public string FindingId { get; set; } = "";
    public string Title { get; set; } = "";
    public string State { get; set; } = "UNKNOWN";
    public string? PreviousFingerprint { get; set; }
    public string? CurrentFingerprint { get; set; }
    public string? Explanation { get; set; }
}

public sealed class RunComparisonSummary
{
    public string? PreviousRunId { get; set; }
    public bool HasBaseline { get; set; }
    public string Trust { get; set; } = "unknown";
    public int NewCount { get; set; }
    public int ResolvedCount { get; set; }
    public int ImprovedCount { get; set; }
    public int WorsenedCount { get; set; }
    public int UnchangedCount { get; set; }
    public int UnknownCount { get; set; }
    public List<ComparisonItem> Items { get; set; } = new();

    [JsonIgnore]
    public string SummaryText => HasBaseline
        ? $"Δ {NewCount} new • {ResolvedCount} resolved • {ImprovedCount} improved • {WorsenedCount} worsened"
        : "Baseline run — no previous comparable diagnosis";
}

public sealed class DiagnosticRunHistory
{
    public string RunId { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset RanAt { get; set; }
    public string Status { get; set; } = "completed";
    public string HealthLabel { get; set; } = "Unknown";
    public string EvidencePath { get; set; } = "";
    public string ReportPath { get; set; } = "";
    public string Model { get; set; } = "Unknown device";
    public string DeviceFingerprint { get; set; } = "";
    public string EvidenceBundleHash { get; set; } = "";
    public string ProductVersion { get; set; } = "";
    public string RuleSetVersion { get; set; } = "";
    public long DurationMs { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int FindingCount { get; set; }
    public double CoveragePercent { get; set; }
    public int CollectorSuccessCount { get; set; }
    public int CollectorFailureCount { get; set; }
    public string ComparisonSummary { get; set; } = "";
    public List<FindingSnapshot> Findings { get; set; } = new();
    public List<CollectorExecutionRecord> CollectorExecutions { get; set; } = new();
    public List<ComparisonItem> Comparisons { get; set; } = new();

    [JsonIgnore]
    public string WhenText => RanAt.LocalDateTime.ToString("ddd d MMM, h:mm tt");

    [JsonIgnore]
    public string SummaryText => string.IsNullOrWhiteSpace(ComparisonSummary)
        ? $"{FindingCount} findings • {CoveragePercent:0}% coverage"
        : $"{FindingCount} findings • {CoveragePercent:0}% coverage • {ComparisonSummary}";
}

public sealed class CrashHistoryRecord
{
    public string Path { get; set; } = "";
    public string FileName { get; set; } = "";
    public long FileSize { get; set; }
    public string? CrashTimeUtc { get; set; }
    public string? CrashTimeLocal { get; set; }
    public string Format { get; set; } = "";
    public string? Architecture { get; set; }
    public string? BugCheckCode { get; set; }
    public string? BugCheckName { get; set; }
    public List<string> BugCheckParameters { get; set; } = new();
    public string? FaultingModule { get; set; }
    public string? ExceptionAddress { get; set; }
    public ProblemClassificationRecord? ProblemClassification { get; set; }
    public BugCheckAnalysisRecord? BugCheckAnalysis { get; set; }
    public CallStackRecord? FaultingCallStack { get; set; }
    public List<CallStackRecord> CallStacks { get; set; } = new();
    public List<StackDriverRecord> StackDrivers { get; set; } = new();
    public bool Valid { get; set; }
    public string? Error { get; set; }
}

public sealed class BugCheckAnalysisRecord
{
    public string? FailureBucket { get; set; }
    public uint BugCheckCode { get; set; }
    public string? BugCheckHex { get; set; }
    public string? BugCheckName { get; set; }
    public string ProblemFamily { get; set; } = "Unknown";
    public string Summary { get; set; } = "";
    public string Explanation { get; set; } = "";
    public string RecommendedAction { get; set; } = "";
    public string? FaultingModule { get; set; }
    public string? ExceptionAddress { get; set; }
    public List<BugCheckParameterDetail> Parameters { get; set; } = new();
}

public sealed class BugCheckParameterDetail
{
    public int Index { get; set; }
    public string RawHex { get; set; } = "";
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
}

public sealed class CallStackRecord
{
    public uint ThreadId { get; set; }
    public bool IsFaultingThread { get; set; }
    public int Rank { get; set; }
    public string Tag { get; set; } = "";
    public int FrameCount { get; set; }
    public string TopFrame { get; set; } = "";
    public List<StackFrameRecord> Frames { get; set; } = new();
}

public sealed class StackFrameRecord
{
    public int FrameNumber { get; set; }
    public string InstructionPointer { get; set; } = "";
    public string? StackPointer { get; set; }
    public string? FramePointer { get; set; }
    public string ModuleName { get; set; } = "";
    public string? Offset { get; set; }
    public string Symbol { get; set; } = "";
    public string? ReturnAddress { get; set; }
}

public sealed class ProblemClassificationRecord
{
    public string Family { get; set; } = "Unknown";
    public string Confidence { get; set; } = "Low";
    public string Summary { get; set; } = "";
    public string Explanation { get; set; } = "";
    public string RecommendedAction { get; set; } = "";
    public List<string> ContributingFactors { get; set; } = new();
}

public sealed class StackDriverRecord
{
    public string Name { get; set; } = "";
    public string? FullPath { get; set; }
    public string? BaseAddress { get; set; }
    public string? StackAddress { get; set; }
    public string? Offset { get; set; }
    public uint ThreadId { get; set; }
    public bool IsCoreComponent { get; set; }
}

public sealed class AppSettings
{
    public bool DarkMode { get; set; }
    public string? LastEvidencePath { get; set; }
}
