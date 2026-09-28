namespace OfficeSecurity.Client.Core.ViewModels;

/// <summary>User-interface services the view models need, implemented by each desktop application.</summary>
public interface IUiServices
{
    /// <summary>Asks a yes/no question; returns true for yes.</summary>
    bool Confirm(string title, string message);

    void CopyToClipboard(string text);

    /// <summary>Lets the user choose a file to open; returns its full path, or null when cancelled.</summary>
    /// <param name="filter">File types, e.g. "Installers (*.msi;*.exe)|*.msi;*.exe".</param>
    string? PickFile(string title, string filter);
}
