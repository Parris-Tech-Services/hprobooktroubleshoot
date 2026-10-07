using System.Windows;
using WindowsCrashDoctor.Services;

namespace WindowsCrashDoctor;

public partial class MainWindow
{
    private readonly PrivacyExportService _privacyExport = new();

    private void ExportPrivacyReviewedBundle_Click(object sender, RoutedEventArgs e)
    {
        if (_latestEvidencePath is null || !Directory.Exists(_latestEvidencePath))
        {
            MessageBox.Show(this, "There is no completed diagnostic run to export yet.", "Windows Doctor", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            var plan = _privacyExport.CreatePlan(_latestEvidencePath);
            var excludedPreview = plan.Entries
                .Where(x => !x.Included)
                .Take(6)
                .Select(x => $"• {x.RelativePath} — {x.Reason}")
                .ToList();
            var preview = excludedPreview.Count == 0
                ? "No files need exclusion under the current policy."
                : string.Join(Environment.NewLine, excludedPreview) +
                  (plan.ExcludedCount > excludedPreview.Count ? $"{Environment.NewLine}• …and {plan.ExcludedCount - excludedPreview.Count} more" : string.Empty);

            var answer = MessageBox.Show(this,
                $"Windows Doctor reviewed this bundle before export.\n\n" +
                $"Include: {plan.IncludedCount} file(s)\n" +
                $"Exclude: {plan.ExcludedCount} high-risk/unscannable file(s)\n" +
                $"Text files requiring redaction: {plan.RedactedFileCount}\n" +
                $"Sensitive matches to redact: {plan.SensitiveMatchCount}\n\n" +
                $"Excluded by default:\n{preview}\n\n" +
                "The secret scanner records pattern type and line only; it never shows the matched secret. The exported ZIP is a derivative and your original evidence is not changed. Continue?",
                "Privacy-reviewed diagnostic export",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes) return;

            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var zip = Path.Combine(desktop, $"WindowsCrashDoctor-Shareable-{DateTime.Now:yyyyMMdd-HHmmss}.zip");
            var result = _privacyExport.Export(plan, zip);
            OpenPath(desktop);
            MessageBox.Show(this,
                $"Created privacy-reviewed bundle:\n{result.ZipPath}\n\n" +
                $"Included {result.IncludedCount}; excluded {result.ExcludedCount}; " +
                $"redacted {result.TotalRedactions} value(s) across {result.RedactedFileCount} file(s).\n\n" +
                "See export-manifest.json inside the ZIP for the inclusion/exclusion record and secret-pattern metadata.",
                "Export complete",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, _redaction.RedactForLog(ex.Message), "Export failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
