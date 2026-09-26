using System.Windows;
using System.Windows.Threading;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Client.Wpf;
using OfficeSecurity.StaffApp.ViewModels;

namespace OfficeSecurity.StaffApp;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var smokeTest = Array.IndexOf(e.Args, "--smoke-test");
        if (smokeTest >= 0)
        {
            Shutdown(SmokeTest.Run(smokeTest + 1 < e.Args.Length ? e.Args[smokeTest + 1] : null));
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;

        var shell = new StaffShellViewModel(ClientSettingsStore.ForApplication("StaffApp"), new WpfUiServices());
        var window = new MainWindow { DataContext = shell };
        MainWindow = window;
        window.Show();
        shell.Start();
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(MainWindow!, "An unexpected error occurred:\n\n" + e.Exception.Message, "Office Security", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
