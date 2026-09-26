using CommunityToolkit.Mvvm.ComponentModel;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Base class for a page shown from the sidebar.</summary>
public abstract class SectionViewModel(string title) : ObservableObject
{
    public string Title { get; } = title;
}

/// <summary>
/// A dashboard section whose functionality has not been built yet. It states the delivery phase
/// explicitly and shows no sample or fake data.
/// </summary>
public sealed class PlannedSectionViewModel(string title, int phase, string description) : SectionViewModel(title)
{
    public int Phase { get; } = phase;

    public string Description { get; } = description;

    public string PhaseText => $"Not available yet — scheduled for development Phase {Phase}.";
}
