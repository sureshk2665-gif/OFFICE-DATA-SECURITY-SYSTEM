using System.Windows;
using OfficeSecurity.AdminDashboard.ViewModels;
using OfficeSecurity.Client.Core;

namespace OfficeSecurity.AdminDashboard;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var settings = new SettingsService(ClientSettingsStore.ForApplication("AdminDashboard"));
        var window = new MainWindow { DataContext = new MainViewModel(settings) };
        MainWindow = window;
        window.Show();
    }
}
