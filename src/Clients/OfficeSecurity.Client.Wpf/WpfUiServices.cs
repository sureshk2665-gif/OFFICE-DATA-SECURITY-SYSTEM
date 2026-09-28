using System.Runtime.InteropServices;
using System.Windows;
using OfficeSecurity.Client.Core.ViewModels;

namespace OfficeSecurity.Client.Wpf;

public sealed class WpfUiServices : IUiServices
{
    public bool Confirm(string title, string message) =>
        MessageBox.Show(Application.Current?.MainWindow!, message, title, MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;

    public void CopyToClipboard(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch (COMException)
        {
            // The clipboard is briefly locked by another program; the code remains visible to copy manually.
        }
    }

    public string? PickFile(string title, string filter)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true, Multiselect = false };
        return dialog.ShowDialog(Application.Current?.MainWindow) == true ? dialog.FileName : null;
    }

    public string? PickSaveFile(string title, string filter, string suggestedName)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog { Title = title, Filter = filter, FileName = suggestedName, OverwritePrompt = true, AddExtension = true };
        return dialog.ShowDialog(Application.Current?.MainWindow) == true ? dialog.FileName : null;
    }

    public void OpenFile(string path)
    {
        try
        {
            using var _ = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // No program is set up for this file type; the file is saved and can be opened from File Explorer.
        }
    }
}
