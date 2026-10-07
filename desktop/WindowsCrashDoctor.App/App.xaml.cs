using System.Windows;
using WindowsCrashDoctor.Services;

namespace WindowsCrashDoctor;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Any(a => string.Equals(a, "--self-test", StringComparison.OrdinalIgnoreCase)))
        {
            // DesktopSelfTest includes synchronous calls into async process-runner code.
            // Keep it off the WPF dispatcher so library awaits cannot deadlock by trying
            // to resume on the UI thread that is synchronously waiting for completion.
            var exitCode = await Task.Run(DesktopSelfTest.Run);
            Shutdown(exitCode);
            return;
        }

        var autoRun = e.Args.Any(a => string.Equals(a, "--run-diagnostics", StringComparison.OrdinalIgnoreCase));
        var window = new MainWindow(autoRun);
        MainWindow = window;
        window.Show();
        if (e.Args.Any(a => string.Equals(a, "--toolkit", StringComparison.OrdinalIgnoreCase)))
            new ToolkitWindow(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                "Windows Crash Doctor Results")) { Owner = window }.Show();
    }
}
