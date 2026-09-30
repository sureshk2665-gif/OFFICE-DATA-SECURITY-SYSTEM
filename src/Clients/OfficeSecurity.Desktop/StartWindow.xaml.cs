using System.Windows;

namespace OfficeSecurity.Desktop;

public partial class StartWindow : Window
{
    public StartWindow(InstalledRole role)
    {
        InitializeComponent();
        if (role == InstalledRole.StaffComputer)
        {
            // Staff computers only offer the staff sign-in; administrators use the main office computer.
            Choices.Children.Remove(AdminCard);
            StaffCard.Margin = new Thickness(0);
            Footer.Text = "This is a staff computer. The administrator signs in on the main office computer.";
        }
        else
        {
            Footer.Text = "Administrator and staff sign-ins are separate: each has its own account and its own screens.";
        }
    }

    public event EventHandler<Part>? PartChosen;

    private void OnAdministrator(object sender, RoutedEventArgs e) => PartChosen?.Invoke(this, Part.Administrator);

    private void OnStaff(object sender, RoutedEventArgs e) => PartChosen?.Invoke(this, Part.Staff);
}

public enum Part
{
    Administrator,
    Staff,
}
