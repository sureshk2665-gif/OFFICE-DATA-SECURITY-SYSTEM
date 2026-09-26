namespace OfficeSecurity.Client.Core.ViewModels;

/// <summary>User-interface services the view models need, implemented by each desktop application.</summary>
public interface IUiServices
{
    /// <summary>Asks a yes/no question; returns true for yes.</summary>
    bool Confirm(string title, string message);

    void CopyToClipboard(string text);
}
