using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using OfficeSecurity.Contracts;
using QRCoder;

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

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Shows a UTC timestamp in the computer's local time, or a dash when empty.</summary>
public sealed class LocalTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is DateTimeOffset time
            ? time.ToLocalTime().ToString(parameter as string ?? "dd MMM yyyy HH:mm", CultureInfo.CurrentCulture)
            : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Translates account status codes into plain language.</summary>
public sealed class AccountStatusTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        AccountStatuses.Active => "Active",
        AccountStatuses.PendingActivation => "Waiting for first sign-in",
        AccountStatuses.Disabled => "Disabled",
        _ => value?.ToString() ?? string.Empty,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Renders a text (e.g. an otpauth:// URI) as a QR code image.</summary>
public sealed class QrCodeConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string { Length: > 0 } text)
        {
            return null;
        }

        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(8);

        var image = new BitmapImage();
        using var stream = new MemoryStream(png);
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return image;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
