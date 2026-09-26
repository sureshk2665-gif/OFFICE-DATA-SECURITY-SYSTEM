using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace OfficeSecurity.Client.Wpf;

/// <summary>Maps a boolean "healthy" flag to the theme's success or danger brush.</summary>
public sealed class StatusToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var key = value switch
        {
            true => "Brush.Success",
            false => "Brush.Danger",
            _ => "Brush.TextMuted",
        };
        return Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
