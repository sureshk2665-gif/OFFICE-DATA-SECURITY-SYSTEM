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
            new ComputersViewModel(shell, canWrite),
            new StaffViewModel(shell, canWrite),
        };
        if (user.Role == AdminRoles.SuperAdmin)
        {
            sections.Add(new AdministratorsViewModel(shell, user.Id));
        }

        sections.AddRange(
        [
            new PoliciesViewModel(shell, canWrite),
            new PlannedSectionViewModel("USB Device Control", 5, "Block removable storage and phones; approve specific USB devices by hardware ID."),
            new PlannedSectionViewModel("Software Management", 4, "Software inventory of every computer and the list of approved applications."),
            new PlannedSectionViewModel("Installation Requests", 4, "Review, approve or reject software requests from staff; deploy approved software."),
            new PlannedSectionViewModel("File Safety", 5, "Protected company folders, file access auditing, and backup status."),
            new EventsViewModel(shell),
            new PlannedSectionViewModel("Security Alerts", 6, "Alerts for blocked devices, failed logins, stopped agents and policy violations."),
            new AuditViewModel(shell),
            new PlannedSectionViewModel("Reports", 6, "USB, blocked transfer, software, login and weekly/monthly security reports (CSV/PDF)."),
            new SettingsViewModel(shell),
        ]);

        foreach (var section in sections)
        {
            section.SessionEnded = shell.SessionEnded;
        }

        Sections = new ObservableCollection<SectionViewModel>(sections);
        SelectedSection = sections[0];
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
