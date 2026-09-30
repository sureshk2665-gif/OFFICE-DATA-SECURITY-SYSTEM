using System.IO;
using System.Windows;
using System.Windows.Threading;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Client.Wpf;

namespace OfficeSecurity.Desktop;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var smokeTest = Array.IndexOf(e.Args, "--smoke-test");
        if (smokeTest >= 0)
        {
            Shutdown(RunSmokeTest(smokeTest + 1 < e.Args.Length ? e.Args[smokeTest + 1] : null));
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;

        var start = new StartWindow(InstalledRoles.Read());
        start.PartChosen += (_, part) => Open(start, part);
        start.Closed += (_, _) =>
        {
            if (MainWindow == start)
            {
                Shutdown();
            }
        };
        MainWindow = start;
        start.Show();
    }

    // Each part keeps its own settings, sign-in and screens, exactly as the separate programs do.
    private void Open(Window start, Part part)
    {
        Window window;
        if (part == Part.Administrator)
        {
            var shell = new AdminDashboard.ViewModels.ShellViewModel(ClientSettingsStore.ForApplication("AdminDashboard"), new WpfUiServices());
            window = new AdminDashboard.MainWindow { DataContext = shell };
            _ = shell.StartAsync();
        }
        else
        {
            var shell = new StaffApp.ViewModels.StaffShellViewModel(ClientSettingsStore.ForApplication("StaffApp"), new WpfUiServices());
            window = new StaffApp.MainWindow { DataContext = shell };
            _ = shell.StartAsync();
        }

        window.Closed += (_, _) => Shutdown();
        MainWindow = window;
        window.Show();
        start.Close();
    }

    // "--smoke-test [log file]": builds the start screen and every administrator and staff screen off-screen.
    private static int RunSmokeTest(string? logPath)
    {
        var dir = Path.Combine(Path.GetTempPath(), "OfficeSecuritySmokeTest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var result = 0;
        var log = new System.Text.StringBuilder();
        try
        {
            new StartWindow(InstalledRole.Unknown).Close();
            new StartWindow(InstalledRole.StaffComputer).Close();
            log.AppendLine("PASS Start screen");
        }
#pragma warning disable CA1031 // The self-test must report every failure, whatever its type.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            log.AppendLine("FAIL Start screen: " + ex);
            result = 1;
        }

        var adminLog = Path.Combine(dir, "admin.txt");
        var staffLog = Path.Combine(dir, "staff.txt");
        result |= AdminDashboard.SmokeTest.Run(adminLog);
        result |= StaffApp.SmokeTest.Run(staffLog);
        log.AppendLine("---- Administrator part").Append(File.ReadAllText(adminLog));
        log.AppendLine("---- Staff part").Append(File.ReadAllText(staffLog));
        log.AppendLine(result == 0 ? "RESULT: combined program - all screens built successfully" : "RESULT: combined program - some screens failed");
        if (!string.IsNullOrEmpty(logPath))
        {
            File.WriteAllText(logPath, log.ToString());
        }

        return result;
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(MainWindow!, "An unexpected error occurred:\n\n" + e.Exception.Message + "\n\nThe program will keep running. If the problem continues, restart it.",
            "Office Security", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
