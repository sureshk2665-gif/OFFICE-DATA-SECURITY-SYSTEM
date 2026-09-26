using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Overview page showing real figures from the server; nothing is estimated or invented.</summary>
public sealed partial class OverviewViewModel(ShellViewModel shell) : SectionViewModel("Overview")
{
    [ObservableProperty]
    public partial DashboardOverviewResponse? Overview { get; set; }

    [ObservableProperty]
    public partial bool? IsServerReachable { get; set; }

    [ObservableProperty]
    public partial string ServerText { get; set; } = "Checking…";

    public string ServerAddress => shell.Settings.ServerAddress;

    public override Task ActivateAsync() => RefreshAsync();

    [RelayCommand]
    private Task RefreshAsync() => RunAsync(async () =>
    {
        var health = await shell.Api.CheckHealthAsync();
        IsServerReachable = health.IsReachable;
        ServerText = health.IsReachable
            ? $"Connected · server version {health.Health!.ServerVersion.Split('+')[0]} · checked {DateTime.Now:HH:mm:ss}"
            : "Not reachable: " + health.Error;
        if (health.IsReachable)
        {
            Overview = await shell.Api.GetOverviewAsync();
        }
    });
}
