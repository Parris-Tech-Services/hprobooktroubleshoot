using System.Windows;

namespace WindowsCrashDoctor;

public partial class MainWindow
{
    private void OpenToolkitCatalog_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var toolkit = new ToolkitWindow(_outputRoot) { Owner = this };
            toolkit.Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, _redaction.RedactForLog(ex.Message), "Technician toolkit",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
