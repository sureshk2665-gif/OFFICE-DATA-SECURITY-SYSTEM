using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using OfficeSecurity.AdminDashboard.ViewModels;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Client.Core.ViewModels;
using OfficeSecurity.Client.Wpf;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard;

/// <summary>
/// "--smoke-test [log file]": builds every screen off-screen (no window is shown, no server is
/// contacted) and fails if any screen's layout cannot be created. Used by the Windows build pipeline.
/// </summary>
internal static class SmokeTest
{
    public static int Run(string? logPath)
    {
        var log = new StringBuilder();
        var failures = 0;

        void Check(string name, Func<object> build)
        {
            try
            {
                var viewModel = build();
                if (viewModel is Window window)
                {
                    window.Close();
                    log.AppendLine(CultureInfo.InvariantCulture, $"PASS {name}");
                    return;
                }

                var root = Render(viewModel);
                if (root is null || (root is TextBlock text && text.Text == viewModel.ToString()))
                {
                    failures++;
                    log.AppendLine(CultureInfo.InvariantCulture, $"FAIL {name}: no view is defined for {viewModel.GetType().Name}");
                }
                else
                {
                    log.AppendLine(CultureInfo.InvariantCulture, $"PASS {name} ({root.GetType().Name})");
                }
            }
#pragma warning disable CA1031 // The self-test must report every failure, whatever its type.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                failures++;
                log.AppendLine(CultureInfo.InvariantCulture, $"FAIL {name}: {ex}");
            }
        }

        var store = new ClientSettingsStore(Path.Combine(Path.GetTempPath(), "OfficeSecuritySmokeTest", Guid.NewGuid().ToString("N"), "settings.json"));
        var shell = new ShellViewModel(store, new WpfUiServices());
        shell.AttachApiForSelfTest(new ApiClient(new HttpClient { BaseAddress = new Uri("https://127.0.0.1:9/") }));
        var enrollment = new MfaEnrollmentResponse("ticket", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "otpauth://totp/Office%20Security:test?secret=JBSWY3DPEHPK3PXP&issuer=Office%20Security");
        var superAdmin = new CurrentUserResponse(Guid.NewGuid(), AccountTypes.Admin, "owner", "Owner", AdminRoles.SuperAdmin);

        Check("Main window", () => new MainWindow());
        Check("Connect", () => new ConnectViewModel(store, _ => { }));
        Check("First-time setup", () => new FirstSetupViewModel(shell));
        Check("Activate administrator", () => new ActivateAdminViewModel(shell));
        Check("Two-step enrollment (QR code)", () => new MfaEnrollmentViewModel(shell, enrollment));
        Check("Sign-in", () => new LoginViewModel(shell));
        Check("Sign-in, code step", () => new LoginViewModel(shell) { IsCodeStep = true, ErrorMessage = "Example error" });
        Check("Change password", () => new ChangePasswordViewModel(shell.Api));

        var workspace = new WorkspaceViewModel(shell, superAdmin);
        Check("Workspace", () => workspace);
        foreach (var section in workspace.Sections)
        {
            Check("Section: " + section.Title, () => section);
        }

        Check("Staff with issued code", () => new StaffViewModel(shell, canWrite: true)
        {
            IssuedCode = new SetupCodeResponse(Guid.NewGuid(), "EMP001", "ABCD-EFGH-JKMN", DateTimeOffset.UtcNow.AddDays(3)),
            IsCreateOpen = true,
        });
        Check("Staff read-only", () => new StaffViewModel(shell, canWrite: false));

        var summary = new ComputerSummary(Guid.NewGuid(), "PC-01", ComputerStatuses.Trusted, true, DateTimeOffset.UtcNow, "Windows 11 Pro", "Professional", "0.1.0", "Default policy", 1, 1, 0, DateTimeOffset.UtcNow);
        var detail = new ComputerDetail(summary,
            new HardwareInventory("PC-01", "Windows 11 Pro", "24H2", "26100.1", "Professional", "Contoso", "Model", "SN", "CPU", 8192, 256, true, false, "WORKGROUP"),
            [new ControlStatus(SecurityControl.RemovableStorage, ControlState.NotImplemented, null, DateTimeOffset.UtcNow)],
            [new DeviceSummary(@"USBSTOR\DISK", "USB drive", "DiskDrive", "Vendor", true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow)],
            [new StaffReference(Guid.NewGuid(), "EMP001", "Sample")], null, "192.168.1.5", "ab", DateTimeOffset.UtcNow.AddYears(2));
        Check("Computers with details and install instructions", () =>
        {
            var computers = new ComputersViewModel(shell, canWrite: true);
            computers.ShowSampleForSelfTest(detail, new EnrollmentCodeResponse("ABCD-EFGH-JKMN", DateTimeOffset.UtcNow.AddDays(1), "1234-5678-9ABC-DEF0-1234"));
            return computers;
        });
        Check("Software management with all panels", () =>
        {
            var software = new SoftwareViewModel(shell, canWrite: true);
            software.ShowSampleForSelfTest();
            return software;
        });
        Check("Installation request decision", () =>
        {
            var requests = new SoftwareRequestsViewModel(shell, canWrite: true);
            requests.ShowSampleForSelfTest();
            return requests;
        });
        Check("Policy editor", () =>
        {
            var policies = new PoliciesViewModel(shell, canWrite: true);
            policies.NewCommand.Execute(null);
            return policies;
        });

        log.AppendLine(failures == 0 ? "RESULT: all screens built successfully" : string.Create(CultureInfo.InvariantCulture, $"RESULT: {failures} screen(s) failed"));
        if (!string.IsNullOrEmpty(logPath))
        {
            File.WriteAllText(logPath, log.ToString());
        }

        return failures == 0 ? 0 : 1;
    }

    private static DependencyObject? Render(object viewModel)
    {
        var host = new ContentControl { Content = viewModel };
        host.Measure(new Size(1280, 900));
        host.Arrange(new Rect(0, 0, 1280, 900));
        host.UpdateLayout();

        var presenter = FindChild<ContentPresenter>(host);
        return presenter is not null && VisualTreeHelper.GetChildrenCount(presenter) > 0 ? VisualTreeHelper.GetChild(presenter, 0) : null;
    }

    private static T? FindChild<T>(DependencyObject parent)
        where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match)
            {
                return match;
            }

            if (FindChild<T>(child) is { } nested)
            {
                return nested;
            }
        }

        return null;
    }
}
