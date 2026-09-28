using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>An approved computer that can be ticked as a destination for an installation.</summary>
public sealed partial class ComputerChoice(ComputerSummary computer) : ObservableObject
{
    public Guid Id { get; } = computer.Id;

    public string Label { get; } = $"{computer.Hostname}{(computer.IsOnline ? string.Empty : " (offline)")}";

    [ObservableProperty]
    public partial bool IsSelected { get; set; }
}

/// <summary>
/// Software Management: the approved software list, installer files, installations on computers, and the
/// programs actually found on the computers.
/// </summary>
public sealed partial class SoftwareViewModel(ShellViewModel shell, bool canWrite) : SectionViewModel("Software Management")
{
    public bool CanWrite { get; } = canWrite;

    // ---------------------------------------------------------------- approved list

    public ObservableCollection<ApprovedSoftwareResponse> Approved { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelectedTitle), nameof(SelectedPackages))]
    public partial ApprovedSoftwareResponse? SelectedTitle { get; set; }

    public bool HasSelectedTitle => SelectedTitle is not null;

    public IReadOnlyList<SoftwarePackageResponse> SelectedPackages => SelectedTitle?.Packages ?? [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelectedPackage))]
    public partial SoftwarePackageResponse? SelectedPackage { get; set; }

    public bool HasSelectedPackage => SelectedPackage is not null;

    // ---- add / edit form
    [ObservableProperty]
    public partial bool IsTitleFormOpen { get; set; }

    [ObservableProperty]
    public partial Guid? EditingTitleId { get; set; }

    [ObservableProperty]
    public partial string TitleName { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string TitlePublisher { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string TitleNotes { get; set; } = string.Empty;

    // ---- upload form
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsExe), nameof(CanAllowUnsigned))]
    public partial bool IsUploadOpen { get; set; }

    [ObservableProperty]
    public partial string UploadPath { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsExe))]
    public partial string UploadType { get; set; } = InstallerTypes.Msi;

    public bool IsExe => UploadType == InstallerTypes.Exe;

    [ObservableProperty]
    public partial string UploadSilentArguments { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanAllowUnsigned), nameof(IsSignatureBroken))]
    public partial SignatureCheck? UploadSignature { get; set; }

    public bool CanAllowUnsigned => UploadSignature?.State is SignatureState.NotSigned or SignatureState.Unavailable;

    public bool IsSignatureBroken => UploadSignature?.State == SignatureState.Invalid;

    [ObservableProperty]
    public partial string SignatureText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool AllowUnsigned { get; set; }

    [ObservableProperty]
    public partial string UploadProgressText { get; set; } = string.Empty;

    // ---- install on computers
    [ObservableProperty]
    public partial bool IsDeployOpen { get; set; }

    public ObservableCollection<ComputerChoice> DeployChoices { get; } = [];

    // ---------------------------------------------------------------- installations

    public ObservableCollection<DeploymentResponse> Deployments { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanCancelDeployment))]
    public partial DeploymentResponse? SelectedDeployment { get; set; }

    public bool CanCancelDeployment => CanWrite && SelectedDeployment?.Status == JobStatuses.Queued;

    // ---------------------------------------------------------------- found on computers

    public ObservableCollection<SoftwareTitleSummary> Titles { get; } = [];

    [ObservableProperty]
    public partial string InventorySearch { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool UnapprovedOnly { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanApproveFoundTitle))]
    public partial SoftwareTitleSummary? SelectedFound { get; set; }

    public bool CanApproveFoundTitle => CanWrite && SelectedFound is { IsApproved: false };

    public ObservableCollection<InstalledSoftwareResponse> FoundOn { get; } = [];

    public override Task ActivateAsync() => LoadAsync();

    /// <summary>Used by the start-up self-test to render every panel without a server.</summary>
    internal void ShowSampleForSelfTest()
    {
        var package = new SoftwarePackageResponse(Guid.NewGuid(), Guid.NewGuid(), "viewer.msi", new string('a', 64), 12_345_678, InstallerTypes.Msi, null, "CN=Contoso Ltd", false, DateTimeOffset.UtcNow);
        Approved.Add(new ApprovedSoftwareResponse(package.ApprovedSoftwareId, "Contoso Viewer", "Contoso Ltd", "For reports", DateTimeOffset.UtcNow, [package]));
        SelectedTitle = Approved[0];
        Deployments.Add(new DeploymentResponse(Guid.NewGuid(), package.Id, "Contoso Viewer", "viewer.msi", Guid.NewGuid(), "PC-01", null, JobStatuses.Succeeded, 1, 0, "Installed successfully.", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        Titles.Add(new SoftwareTitleSummary("Free Game", "Games Ltd", 2, ["2.0"], false));
        FoundOn.Add(new InstalledSoftwareResponse(Guid.NewGuid(), "PC-01", "Free Game", "2.0", "Games Ltd", "User", false, DateTimeOffset.UtcNow));
        IsTitleFormOpen = true;
        IsUploadOpen = true;
        UploadPath = @"C:\Installers\viewer.msi";
        UploadSignature = new SignatureCheck(SignatureState.NotSigned, null, null);
        SignatureText = DescribeSignature(UploadSignature);
        IsDeployOpen = true;
        DeployChoices.Add(new ComputerChoice(new ComputerSummary(Guid.NewGuid(), "PC-01", ComputerStatuses.Trusted, true, DateTimeOffset.UtcNow, null, null, null, null, 1, 1, 0, DateTimeOffset.UtcNow)));
    }

    [RelayCommand]
    private Task LoadAsync() => RunAsync(async () =>
    {
        await FetchApprovedAsync();
        await FetchDeploymentsAsync();
        await FetchTitlesAsync();
    });

    [RelayCommand]
    private Task SearchInventoryAsync() => RunAsync(FetchTitlesAsync);

    partial void OnSelectedFoundChanged(SoftwareTitleSummary? value)
    {
        FoundOn.Clear();
        if (value is not null)
        {
            _ = RunAsync(async () =>
            {
                var rows = await shell.Api.ListInstalledSoftwareAsync(null, value.Name);
                if (SelectedFound == value)
                {
                    foreach (var row in rows)
                    {
                        FoundOn.Add(row);
                    }
                }
            });
        }
    }

    partial void OnSelectedTitleChanged(ApprovedSoftwareResponse? value)
    {
        SelectedPackage = null;
        IsUploadOpen = false;
        IsDeployOpen = false;
    }

    // ---- approved list

    [RelayCommand]
    private void OpenAddTitle()
    {
        EditingTitleId = null;
        TitleName = TitlePublisher = TitleNotes = string.Empty;
        IsTitleFormOpen = true;
    }

    [RelayCommand]
    private void OpenEditTitle()
    {
        if (SelectedTitle is { } title)
        {
            EditingTitleId = title.Id;
            TitleName = title.Name;
            TitlePublisher = title.Publisher ?? string.Empty;
            TitleNotes = title.Notes ?? string.Empty;
            IsTitleFormOpen = true;
        }
    }

    [RelayCommand]
    private void ApproveFoundTitle()
    {
        if (SelectedFound is { } found)
        {
            EditingTitleId = null;
            TitleName = found.Name;
            TitlePublisher = found.Publisher ?? string.Empty;
            TitleNotes = string.Empty;
            IsTitleFormOpen = true;
        }
    }

    [RelayCommand]
    private void CloseForms()
    {
        IsTitleFormOpen = false;
        IsUploadOpen = false;
        IsDeployOpen = false;
    }

    [RelayCommand]
    private Task SaveTitleAsync() => RunAsync(async () =>
    {
        var request = new SaveApprovedSoftwareRequest(TitleName, NullIfEmpty(TitlePublisher), NullIfEmpty(TitleNotes));
        var saved = EditingTitleId is { } id
            ? await shell.Api.UpdateApprovedSoftwareAsync(id, request)
            : await shell.Api.CreateApprovedSoftwareAsync(request);
        IsTitleFormOpen = false;
        InfoMessage = $"\"{saved.Name}\" is on the approved list. Programs whose name starts with this text{(saved.Publisher is null ? string.Empty : " and whose publisher is " + saved.Publisher)} count as approved.";
        await FetchApprovedAsync(saved.Id);
        await FetchTitlesAsync();
    });

    [RelayCommand]
    private Task RemoveTitleAsync() => RunAsync(async () =>
    {
        if (SelectedTitle is { } title && shell.Ui.Confirm("Remove from approved list", $"Remove \"{title.Name}\" from the approved software list? Computers that have it will show it as not approved."))
        {
            await shell.Api.DeleteApprovedSoftwareAsync(title.Id);
            InfoMessage = $"\"{title.Name}\" removed from the approved list.";
            await FetchApprovedAsync();
            await FetchTitlesAsync();
        }
    });

    // ---- installer files

    [RelayCommand]
    private void ChooseInstaller()
    {
        if (SelectedTitle is null || shell.Ui.PickFile("Choose the installer file", "Installers (*.msi;*.exe)|*.msi;*.exe") is not { } path)
        {
            return;
        }

        UploadPath = path;
        UploadType = string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase) ? InstallerTypes.Exe : InstallerTypes.Msi;
        UploadSilentArguments = string.Empty;
        UploadSignature = Authenticode.Check(path);
        SignatureText = DescribeSignature(UploadSignature);
        AllowUnsigned = false;
        UploadProgressText = string.Empty;
        IsDeployOpen = false;
        IsUploadOpen = true;
    }

    [RelayCommand]
    private Task UploadAsync() => RunAsync(async () =>
    {
        if (SelectedTitle is not { } title || UploadSignature is not { } signature)
        {
            return;
        }

        if (signature.State == SignatureState.Invalid)
        {
            ErrorMessage = "This file's digital signature is broken. It may have been modified; download it again from the publisher.";
            return;
        }

        var options = new UploadPackageOptions(Path.GetFileName(UploadPath), UploadType, NullIfEmpty(UploadSilentArguments),
            signature.State == SignatureState.Valid ? signature.SignerSubject : null, AllowUnsigned);
        FileStream file;
        try
        {
            file = File.OpenRead(UploadPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ErrorMessage = "The file cannot be opened: " + ex.Message;
            return;
        }

        await using (file)
        {
            var total = Math.Max(1, file.Length);
            var progress = new Progress<long>(sent => UploadProgressText = string.Create(CultureInfo.CurrentCulture, $"Uploading… {sent * 100 / total}% of {FormatSize(total)}"));
            var package = await shell.Api.UploadPackageAsync(title.Id, options, file, progress);
            IsUploadOpen = false;
            UploadProgressText = string.Empty;
            InfoMessage = $"Installer {package.FileName} uploaded (SHA-256 fingerprint {package.Sha256[..16]}…). Computers verify this fingerprint{(package.SignerSubject is null ? string.Empty : " and the publisher's signature")} before installing.";
            await FetchApprovedAsync(title.Id);
        }
    });

    [RelayCommand]
    private Task DeletePackageAsync() => RunAsync(async () =>
    {
        if (SelectedPackage is { } package && SelectedTitle is { } title && shell.Ui.Confirm("Delete installer", $"Delete the installer file {package.FileName}?"))
        {
            await shell.Api.DeletePackageAsync(package.Id);
            await FetchApprovedAsync(title.Id);
        }
    });

    // ---- install on computers

    [RelayCommand]
    private Task OpenDeployAsync() => RunAsync(async () =>
    {
        if (SelectedPackage is null)
        {
            ErrorMessage = "Select one of the installer files first.";
            return;
        }

        var computers = await shell.Api.ListComputersAsync(1, 200, null, ComputerStatuses.Trusted);
        DeployChoices.Clear();
        foreach (var computer in computers.Items)
        {
            DeployChoices.Add(new ComputerChoice(computer));
        }

        IsUploadOpen = false;
        IsDeployOpen = true;
    });

    [RelayCommand]
    private Task DeployAsync() => RunAsync(async () =>
    {
        var selected = DeployChoices.Where(c => c.IsSelected).Select(c => c.Id).ToList();
        if (SelectedPackage is not { } package || selected.Count == 0)
        {
            ErrorMessage = "Tick at least one computer.";
            return;
        }

        if (!shell.Ui.Confirm("Install software", $"Install {package.FileName} on {selected.Count} computer(s)? It is installed silently by the security agent at its next check-in."))
        {
            return;
        }

        var jobs = await shell.Api.CreateDeploymentsAsync(new CreateDeploymentRequest(package.Id, selected));
        IsDeployOpen = false;
        InfoMessage = $"{jobs.Count} installation(s) queued. Progress is shown under 'Installations'.";
        await FetchDeploymentsAsync();
    });

    [RelayCommand]
    private Task RefreshDeploymentsAsync() => RunAsync(FetchDeploymentsAsync);

    [RelayCommand]
    private Task CancelDeploymentAsync() => RunAsync(async () =>
    {
        if (SelectedDeployment is { } job && shell.Ui.Confirm("Cancel installation", $"Cancel the installation of {job.FileName} on {job.ComputerName}?"))
        {
            await shell.Api.CancelDeploymentAsync(job.Id);
            await FetchDeploymentsAsync();
        }
    });

    // ---- helpers

    private async Task FetchApprovedAsync(Guid? select = null)
    {
        var selectedId = select ?? SelectedTitle?.Id;
        var items = await shell.Api.ListApprovedSoftwareAsync();
        Approved.Clear();
        foreach (var item in items)
        {
            Approved.Add(item);
        }

        SelectedTitle = Approved.FirstOrDefault(a => a.Id == selectedId);
    }

    private async Task FetchDeploymentsAsync()
    {
        var result = await shell.Api.ListDeploymentsAsync(1, 100, null, null);
        Deployments.Clear();
        foreach (var item in result.Items)
        {
            Deployments.Add(item);
        }
    }

    private async Task FetchTitlesAsync()
    {
        var items = await shell.Api.ListSoftwareTitlesAsync(InventorySearch, UnapprovedOnly);
        Titles.Clear();
        foreach (var item in items)
        {
            Titles.Add(item);
        }
    }

    internal static string DescribeSignature(SignatureCheck check) => check.State switch
    {
        SignatureState.Valid => $"Digitally signed by: {check.SignerSubject}. Computers install this file only if it carries this publisher's valid signature.",
        SignatureState.NotSigned => "This file is NOT digitally signed, so its publisher cannot be confirmed. Only continue if you downloaded it yourself from the publisher's official website.",
        SignatureState.Invalid => "The digital signature of this file is BROKEN — the file may have been modified. Do not use it.",
        _ => "The signature could not be checked on this computer.",
    };

    private static string FormatSize(long bytes) => bytes >= 1024 * 1024
        ? string.Create(CultureInfo.CurrentCulture, $"{bytes / (1024.0 * 1024):0.#} MB")
        : string.Create(CultureInfo.CurrentCulture, $"{bytes / 1024.0:0.#} KB");

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
