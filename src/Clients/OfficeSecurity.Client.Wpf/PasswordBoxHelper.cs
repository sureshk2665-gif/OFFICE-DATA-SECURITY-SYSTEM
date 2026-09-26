using System.Windows;
using System.Windows.Controls;

namespace OfficeSecurity.Client.Wpf;

/// <summary>Lets a <see cref="PasswordBox"/> bind its password to a view-model property.</summary>
public static class PasswordBoxHelper
{
    // Default is null so the first binding update (to "") always attaches the change handler.
    public static readonly DependencyProperty BoundPasswordProperty = DependencyProperty.RegisterAttached(
        "BoundPassword", typeof(string), typeof(PasswordBoxHelper),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnBoundPasswordChanged));

    private static readonly DependencyProperty IsUpdatingProperty = DependencyProperty.RegisterAttached(
        "IsUpdating", typeof(bool), typeof(PasswordBoxHelper));

    public static string? GetBoundPassword(DependencyObject element) => (string?)element?.GetValue(BoundPasswordProperty);

    public static void SetBoundPassword(DependencyObject element, string? value) => element?.SetValue(BoundPasswordProperty, value);

    private static void OnBoundPasswordChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not PasswordBox box)
        {
            return;
        }

        box.PasswordChanged -= OnPasswordChanged;
        if (!(bool)box.GetValue(IsUpdatingProperty))
        {
            box.Password = e.NewValue as string ?? string.Empty;
        }

        box.PasswordChanged += OnPasswordChanged;
    }

    private static void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        var box = (PasswordBox)sender;
        box.SetValue(IsUpdatingProperty, true);
        SetBoundPassword(box, box.Password);
        box.SetValue(IsUpdatingProperty, false);
    }
}
