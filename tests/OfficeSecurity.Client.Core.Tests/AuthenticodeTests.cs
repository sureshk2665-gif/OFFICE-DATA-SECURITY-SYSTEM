using OfficeSecurity.Client.Core;

namespace OfficeSecurity.Client.Core.Tests;

public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows only (uses the Windows signature check).";
        }
    }
}

/// <summary>Checks the real Windows signature verification against files that ship with .NET.</summary>
public sealed class AuthenticodeTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("ocss-sig-").FullName;

    /// <summary>A Microsoft-signed file (the .NET runtime library).</summary>
    private static string SignedFile => typeof(object).Assembly.Location;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [WindowsFact]
    public void Microsoft_signed_file_is_valid_and_names_its_signer()
    {
        var check = Authenticode.Check(SignedFile);

        Assert.Equal(SignatureState.Valid, check.State);
        Assert.Contains("Microsoft Corporation", check.SignerSubject, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void Modified_copy_of_a_signed_file_is_invalid()
    {
        var copy = Path.Combine(_dir, "modified.dll");
        var bytes = File.ReadAllBytes(SignedFile);
        bytes[bytes.Length / 2] ^= 0xFF;
        File.WriteAllBytes(copy, bytes);

        var check = Authenticode.Check(copy);

        Assert.Equal(SignatureState.Invalid, check.State);
        Assert.Null(check.SignerSubject);
    }

    [WindowsFact]
    public void File_without_a_signature_is_reported_as_not_signed()
    {
        var file = Path.Combine(_dir, "plain.msi");
        File.WriteAllText(file, "not an installer");

        Assert.Equal(SignatureState.NotSigned, Authenticode.Check(file).State);
    }

    [Fact]
    public void Other_operating_systems_report_the_check_as_unavailable()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(SignatureState.Unavailable, Authenticode.Check(SignedFile).State);
        }
    }
}
