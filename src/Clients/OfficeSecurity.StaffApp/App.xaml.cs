using System.Windows;
using OfficeSecurity.Client.Core;
using OfficeSecurity.StaffApp.ViewModels;

namespace OfficeSecurity.StaffApp;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var settings = ClientSettingsStore.ForApplication("StaffApp").Load();
        var window = new MainWindow { DataContext = new StaffMainViewModel(settings) };
        MainWindow = window;
        window.Show();
    }
}
