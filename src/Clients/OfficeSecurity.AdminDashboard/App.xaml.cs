using System.Windows;
using System.Windows.Threading;
using OfficeSecurity.AdminDashboard.ViewModels;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Client.Wpf;

namespace OfficeSecurity.AdminDashboard;

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

        var shell = new ShellViewModel(ClientSettingsStore.ForApplication("AdminDashboard"), new WpfUiServices());
        var window = new MainWindow { DataContext = shell };
        MainWindow = window;
        window.Show();
        _ = shell.StartAsync();
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(MainWindow!, "An unexpected error occurred:\n\n" + e.Exception.Message + "\n\nThe dashboard will keep running. If the problem continues, restart it.",
            "Office Security", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
