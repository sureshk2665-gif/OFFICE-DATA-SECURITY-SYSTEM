using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core.ViewModels;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>A page reachable from the sidebar.</summary>
public abstract class SectionViewModel(string title) : BusyViewModel
{
    public string Title { get; } = title;

    /// <summary>The name in the sidebar (a page may add a count, e.g. open alerts).</summary>
    public virtual string NavTitle => Title;

    /// <summary>Loads data when the page is opened.</summary>
    public virtual Task ActivateAsync() => Task.CompletedTask;
}

/// <summary>
/// A section whose functionality is not built yet. It states the delivery phase and shows no sample data.
/// </summary>
public sealed class PlannedSectionViewModel(string title, int phase, string description) : SectionViewModel(title)
{
    public int Phase { get; } = phase;

    public string Description { get; } = description;

    public string PhaseText => $"Not available yet — scheduled for development Phase {Phase}.";
}

/// <summary>The signed-in dashboard: sidebar navigation and the selected page.</summary>
public sealed partial class WorkspaceViewModel : ObservableObject
{
    private readonly ShellViewModel _shell;

    public WorkspaceViewModel(ShellViewModel shell, CurrentUserResponse user)
    {
        _shell = shell;
        User = user;
        var canWrite = user.Role is AdminRoles.SuperAdmin or AdminRoles.Admin;

        var sections = new List<SectionViewModel>
        {
            new OverviewViewModel(shell),
            new ComputersViewModel(shell, canWrite, canRevealKeys: user.Role == AdminRoles.SuperAdmin),
            new StaffViewModel(shell, canWrite),
        };
        if (user.Role == AdminRoles.SuperAdmin)
        {
            sections.Add(new AdministratorsViewModel(shell, user.Id));
        }

        sections.AddRange(
        [
            new PoliciesViewModel(shell, canWrite),
            new SoftwareViewModel(shell, canWrite),
            new SoftwareRequestsViewModel(shell, canWrite),
            Alerts = new AlertsViewModel(shell, canWrite),
            new EventsViewModel(shell),
            new ReportsViewModel(shell),
            new AuditViewModel(shell),
            new PlannedSectionViewModel("Backup", 7, "Backup of company files and of the server, with the status of each backup. (Protected company folders, file access records and ransomware protection are set in 'Security Policies'.)"),
            new SettingsViewModel(shell),
        ]);

        foreach (var section in sections)
        {
            section.SessionEnded = shell.SessionEnded;
        }

        Sections = new ObservableCollection<SectionViewModel>(sections);
        SelectedSection = sections[0];
    }

    /// <summary>The alerts page; its sidebar entry shows the number of new alerts.</summary>
    public AlertsViewModel Alerts { get; }

    /// <summary>Keeps the alert count in the sidebar current (every 30 seconds) while this workspace is shown.</summary>
    public async Task WatchAlertsAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        do
        {
            if (!ReferenceEquals(_shell.Current, this) || _shell.Api.CurrentUser is null)
            {
                return; // signed out, or the session ended
            }

            await Alerts.RefreshSummaryAsync();
        }
        while (await timer.WaitForNextTickAsync().ConfigureAwait(true));
    }

    public CurrentUserResponse User { get; }

    public string UserText => $"{User.DisplayName} ({User.Role switch { AdminRoles.SuperAdmin => "Super administrator", AdminRoles.Auditor => "Auditor (read-only)", _ => "Administrator" }})";

    public ObservableCollection<SectionViewModel> Sections { get; }

    [ObservableProperty]
    public partial SectionViewModel SelectedSection { get; set; }

    // Each page loads its data when it is opened (including the first page, when the workspace is created).
    partial void OnSelectedSectionChanged(SectionViewModel value) => _ = value?.ActivateAsync();

    [RelayCommand]
    private Task SignOutAsync() => _shell.SignOutAsync();
}
