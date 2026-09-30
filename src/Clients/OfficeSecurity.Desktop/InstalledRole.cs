using System.IO;

namespace OfficeSecurity.Desktop;

/// <summary>What the installer set this computer up as ("role.txt" next to the program).</summary>
public enum InstalledRole
{
    /// <summary>Not installed by the setup program (for example run from the extracted files): offer both sign-ins.</summary>
    Unknown,
    MainOfficeComputer,
    StaffComputer,
}

public static class InstalledRoles
{
    public static InstalledRole Read()
    {
        try
        {
            var file = Path.Combine(AppContext.BaseDirectory, "role.txt");
            var text = File.Exists(file) ? File.ReadAllText(file).Trim() : string.Empty;
            return text.ToUpperInvariant() switch
            {
                "MAIN" => InstalledRole.MainOfficeComputer,
                "STAFF" => InstalledRole.StaffComputer,
                _ => InstalledRole.Unknown,
            };
        }
        catch (IOException)
        {
            return InstalledRole.Unknown;
        }
        catch (UnauthorizedAccessException)
        {
            return InstalledRole.Unknown;
        }
    }
}
