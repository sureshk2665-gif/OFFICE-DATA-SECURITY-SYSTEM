using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace OfficeSecurity.AdminDashboard.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    public MainViewModel(SettingsService settings)
    {
        var overview = new OverviewViewModel(settings);
        Sections =
        [
            overview,
            new PlannedSectionViewModel("Computers", 3, "Register office computers, see online/offline status, agent health and applied policy."),
            new PlannedSectionViewModel("Staff Accounts", 2, "Create staff accounts, assign them to computers, issue one-time password codes, disable accounts."),
            new PlannedSectionViewModel("Security Policies", 3, "Create security policies and apply them to all or selected computers."),
            new PlannedSectionViewModel("USB Device Control", 5, "Block removable storage and phones; approve specific USB devices by hardware ID."),
            new PlannedSectionViewModel("Software Management", 4, "Software inventory of every computer and the list of approved applications."),
            new PlannedSectionViewModel("Installation Requests", 4, "Review, approve or reject software requests from staff; deploy approved software."),
            new PlannedSectionViewModel("File Safety", 5, "Protected company folders, file access auditing, and backup status."),
            new PlannedSectionViewModel("Security Alerts", 6, "Alerts for blocked devices, failed logins, stopped agents and policy violations."),
            new PlannedSectionViewModel("Audit Logs", 6, "Search, filter and export the tamper-evident audit trail."),
            new PlannedSectionViewModel("Reports", 6, "USB, blocked transfer, software, login and weekly/monthly security reports (CSV/PDF)."),
            new SettingsViewModel(settings),
        ];
        SelectedSection = overview;
        overview.CheckServerCommand.Execute(null);
    }

    public ObservableCollection<SectionViewModel> Sections { get; }

    [ObservableProperty]
    public partial SectionViewModel SelectedSection { get; set; }
}
