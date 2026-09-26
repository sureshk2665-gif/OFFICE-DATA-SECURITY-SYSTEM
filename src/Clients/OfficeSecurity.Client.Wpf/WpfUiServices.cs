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
}
