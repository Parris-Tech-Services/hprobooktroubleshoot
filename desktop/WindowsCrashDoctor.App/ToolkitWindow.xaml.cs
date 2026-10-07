using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using WindowsCrashDoctor.Models;
using WindowsCrashDoctor.Services;

namespace WindowsCrashDoctor;

public partial class ToolkitWindow : Window
{
    private readonly ToolkitService _toolkit;
    private readonly PowerShellRunner _runner = new();
    private readonly EngineExtractor _engine = new();
    private readonly RedactionService _redaction = new();
    private readonly string _outputRoot;
    private CancellationTokenSource? _operation;
    private string? _latestEvidence;
    private bool _refreshing;
    private ToolkitTool? Selected => ToolsGrid.SelectedItem as ToolkitTool;

    public ToolkitWindow(string outputRoot)
    {
        _toolkit = new ToolkitService();
        _outputRoot = outputRoot;
        InitializeComponent();
        CategoryBox.ItemsSource = new[] { "All categories" }.Concat(_toolkit.Tools.Select(x => x.Category).Distinct());
        CategoryBox.SelectedIndex = 0;
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e) => await RefreshAsync();
    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_refreshing) return;
        _refreshing = true;
        RefreshButton.IsEnabled = false;
        UpdateButtons();
        try
        {
            StatusText.Text = "Checking installed executables and package locations…";
            await Task.Run(_toolkit.Refresh);
            ApplyFilter();
            StatusText.Text = $"{_toolkit.Tools.Count} tools • {_toolkit.Tools.Count(x => x.Executable is not null)} detected. Availability does not confirm commercial licensing.";
        }
        catch (Exception ex) { ShowError(ex); }
        finally { _refreshing = false; RefreshButton.IsEnabled = true; UpdateButtons(); }
    }

    private void Filter_Changed(object sender, RoutedEventArgs e)
    {
        if (ToolsGrid is not null && CategoryBox is not null) ApplyFilter();
    }

    private void ApplyFilter()
    {
        var selected = Selected;
        var query = SearchBox.Text.Trim();
        var category = CategoryBox.SelectedItem as string;
        ToolsGrid.ItemsSource = _toolkit.Tools.Where(x => (category is null or "All categories" || x.Category == category) &&
            $"{x.Name} {x.Category} {x.Todo} {x.Note}".Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
        if (selected is not null && ToolsGrid.Items.Contains(selected)) ToolsGrid.SelectedItem = selected;
        else if (ToolsGrid.Items.Count > 0) ToolsGrid.SelectedIndex = 0;
    }

    private void ToolsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        => RefreshSelectedTool();

    private void RefreshSelectedTool()
    {
        var tool = Selected;
        SelectedName.Text = tool?.Name ?? "Select a tool";
        SelectedDetails.Text = tool is null ? "" : tool.Definition.Actions.Count > 0
            ? "Launch integration and diagnostic actions available. " + tool.Definition.ConsoleHint
            : "Launch/link and external report attachment available. Tool-specific interpretation remains on the integration roadmap.";
        SelectedNote.Text = tool is null ? "" : tool.Note + (tool.Executable is null ? "" : "\n" + tool.Executable);
        ActionBox.ItemsSource = tool?.Definition.Actions;
        ActionBox.SelectedIndex = tool?.Definition.Actions.Count > 0 ? 0 : -1;
        UpdateButtons();
    }

    private void Action_Changed(object sender, SelectionChangedEventArgs e)
    {
        CommandPreview.Text = (ActionBox.SelectedItem as ToolkitAction)?.Command ?? "No automated action for this tool. Use its launcher, instructions or attach a report.";
        UpdateButtons();
    }

    private void UpdateButtons()
    {
        var idle = _operation is null;
        OpenButton.IsEnabled = idle && !_refreshing && Selected?.Executable is not null;
        LocateButton.IsEnabled = idle && !_refreshing && Selected is not null;
        WebsiteButton.IsEnabled = Selected is not null;
        ImportButton.IsEnabled = idle && Selected is not null;
        var installable = Selected?.Definition.PackageId is not null || Selected?.Definition.ProviderId is not null;
        InstallButton.Visibility = Visibility.Visible;
        InstallButton.Content = Selected?.Executable is not null ? "Installed" : installable ? "Download & Install" : "Manual setup required";
        InstallButton.IsEnabled = idle && !_refreshing && Selected?.Executable is null && installable;
        DumpButton.Visibility = Selected?.Name == "WinDbg / cdb" ? Visibility.Visible : Visibility.Collapsed;
        DumpButton.IsEnabled = idle && Selected?.Executable is not null;
        RunButton.IsEnabled = idle && ActionBox.SelectedItem is ToolkitAction;
        ExportButton.IsEnabled = idle && _latestEvidence is not null;
        CancelButton.IsEnabled = !idle;
    }

    private void Website_Click(object sender, RoutedEventArgs e)
    {
        try { if (Selected is { } tool) ToolkitService.OpenWebsite(tool); }
        catch (Exception ex) { ShowError(ex); }
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (Selected is not { } tool) return;
            if (tool.Category is "Data erasure and ITAD" or "Hardware bench tests" or "Malware investigation" or "Remote support and MSP" &&
                MessageBox.Show(this, $"Open {tool.Name}?\n\n{tool.Note}\n\nChoose any test, repair, erase or remote operation in the tool itself.",
                    "Open external tool", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            _toolkit.Launch(tool);
            StatusText.Text = $"Opened {tool.Name}; results are not automatically verified. Attach the tool's report when finished.";
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void Locate_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } tool) return;
        var dialog = new OpenFileDialog { Title = $"Locate trusted installed {tool.Name} executable", Filter = "Windows executable (*.exe)|*.exe", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        try { _toolkit.ConfigureExecutable(tool, dialog.FileName); ToolsGrid.Items.Refresh(); RefreshSelectedTool(); }
        catch (Exception ex) { ShowError(ex); }
    }

    private void Dump_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } tool) return;
        var dialog = new OpenFileDialog { Title = "Open crash dump with configured debugger and symbols", Filter = "Crash dumps|*.dmp;*.mdmp", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        try { _toolkit.OpenDump(tool, dialog.FileName); StatusText.Text = "Dump handed to debugger with configured symbols; analysis completion not observed."; }
        catch (Exception ex) { ShowError(ex); }
    }

    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } tool || _operation is not null) return;
        var dialog = new OpenFileDialog { Title = $"Attach {tool.Name} report (up to 100 MiB)", Filter = "Reports and evidence|*.txt;*.log;*.json;*.csv;*.xml;*.html;*.nfo;*.etl;*.dmp;*.zip;*.pdf;*.png;*.jpg|All files|*.*", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        _operation = new(); UpdateButtons();
        try
        {
            var evidence = await _toolkit.ImportEvidenceAsync(tool, dialog.FileName, _outputRoot, _operation.Token);
            _latestEvidence = evidence.Directory;
            Log($"Attached {tool.Name} report. SHA-256: {evidence.Sha256}");
            StatusText.Text = "Report preserved locally with provenance. Vendor conclusions have not been independently verified.";
        }
        catch (OperationCanceledException) { StatusText.Text = "Report import cancelled."; }
        catch (Exception ex) { ShowError(ex); }
        finally { FinishOperation(); }
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } tool || _operation is not null || _refreshing || tool.Executable is not null) return;
        if (tool.Definition.PackageId is null && tool.Definition.ProviderId is null) return;
        _operation = new(); UpdateButtons();
        OutputBox.Clear();
        try
        {
            StatusText.Text = $"Downloading and installing {tool.Name}… Windows may request administrator approval.";
            Log($"Installing {tool.Name}. {tool.Note}");
            ProcessResult result;
            if (tool.Definition.PackageId is not null)
                result = await ToolkitInstaller.InstallAsync(tool, _runner, Log, _operation.Token);
            else
            {
                _engine.EnsureExtracted();
                result = await _runner.RunFileAsync(_engine.IntegrationManagerPath, ["-Action", "install", "-Id", tool.Definition.ProviderId!], Log,
                    _operation.Token, new ProcessRunOptions(TimeSpan.FromMinutes(3), OperationId: "toolkit.install." + tool.Definition.ProviderId));
            }
            await RefreshAsync();
            StatusText.Text = result.Succeeded
                ? tool.Executable is not null ? $"{tool.Name} installed and ready to open." : $"Installer completed for {tool.Name}; executable not detected. Use Locate executable or official instructions."
                : $"{tool.Name} installation {result.Status} (exit {result.ExitCode}). {result.FailureReason} See output below; retry or use official instructions.";
        }
        catch (OperationCanceledException) { StatusText.Text = "Installation cancelled. A started installer may have made changes; detection will refresh on the next check."; }
        catch (Exception ex) { ShowError(ex); }
        finally { FinishOperation(); }
    }

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } tool || ActionBox.SelectedItem is not ToolkitAction action || _operation is not null) return;
        var elevatedConsole = action.ChangesSystem || (action.RequiresAdmin && !IsAdmin());
        var details = $"{action.Name}\n\n{action.Command}\n\n{tool.Note}\n\n" +
            (elevatedConsole ? "A visible PowerShell console will open. Administrator approval may be requested. Review its output; console completion is not automatically diagnosed." : "Output will be captured locally. This diagnostic has a timeout and can be cancelled.");
        if (MessageBox.Show(this, details, action.ChangesSystem ? "Confirm system-changing action" : "Run diagnostic action",
            MessageBoxButton.YesNo, action.ChangesSystem ? MessageBoxImage.Warning : MessageBoxImage.Information) != MessageBoxResult.Yes) return;
        if (elevatedConsole)
        {
            try
            {
                _latestEvidence = _toolkit.LaunchActionConsole(tool, action, _outputRoot);
                StatusText.Text = "Console launched; action completion not observed. Transcript is in the evidence folder.";
                UpdateButtons();
            }
            catch (Exception ex) { ShowError(ex); }
            return;
        }
        _operation = new(); UpdateButtons(); OutputBox.Clear();
        try
        {
            StatusText.Text = "Running " + action.Name + "…";
            _engine.EnsureExtracted();
            var run = await _toolkit.RunReadOnlyAsync(tool, action, _outputRoot, _runner, Log, _operation.Token);
            _latestEvidence = run.Directory;
            StatusText.Text = $"{action.Name}: {run.Result.Status} (exit {run.Result.ExitCode}). " + run.Result.FailureReason;
        }
        catch (Exception ex) { ShowError(ex); }
        finally { FinishOperation(); }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _operation?.Cancel();
    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_operation is null) return;
        e.Cancel = true; _operation.Cancel();
        StatusText.Text = "Cancelling the diagnostic. Close after it stops.";
    }

    private void FinishOperation() { _operation?.Dispose(); _operation = null; UpdateButtons(); }
    private static bool IsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void Evidence_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var directory = _latestEvidence ?? Path.Combine(_outputRoot, "Toolkit");
            Directory.CreateDirectory(directory);
            Process.Start(new ProcessStartInfo(directory) { UseShellExecute = true });
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_latestEvidence is null) return;
        try
        {
            var exporter = new PrivacyExportService();
            var plan = exporter.CreatePlan(_latestEvidence);
            if (MessageBox.Show(this, $"Export a privacy-reviewed derivative?\n\nInclude: {plan.IncludedCount} files\nExclude: {plan.ExcludedCount} files\nSensitive matches: {plan.SensitiveMatchCount}\n\nBinary/unsupported artifacts may be excluded. Review the ZIP before sharing.",
                    "Privacy-reviewed toolkit export", MessageBoxButton.YesNo, MessageBoxImage.Information) != MessageBoxResult.Yes) return;
            var dialog = new SaveFileDialog { Filter = "ZIP archive (*.zip)|*.zip", FileName = "WindowsDoctor-toolkit-reviewed.zip" };
            if (dialog.ShowDialog(this) != true) return;
            var result = exporter.Export(plan, dialog.FileName);
            StatusText.Text = $"Exported {result.IncludedCount} files; excluded {result.ExcludedCount}; redactions {result.TotalRedactions}.";
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void Log(string line) => Dispatcher.Invoke(() =>
    {
        OutputBox.AppendText(_redaction.RedactForLog(line) + Environment.NewLine);
        OutputBox.ScrollToEnd();
    });
    private void ShowError(Exception ex)
    {
        StatusText.Text = _redaction.RedactForLog(ex.Message);
        MessageBox.Show(this, StatusText.Text, "Technician toolkit", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
