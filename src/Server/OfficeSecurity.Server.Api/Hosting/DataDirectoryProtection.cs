using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace OfficeSecurity.Server.Api.Hosting;

/// <summary>
/// Restricts the server data directory (database, keys, certificates) to SYSTEM, Administrators and the
/// account running the server. Standard users cannot read or change it.
/// </summary>
public static class DataDirectoryProtection
{
    public static void CreateAndProtect(string directory)
    {
        Directory.CreateDirectory(directory);
        if (OperatingSystem.IsWindows())
        {
            ApplyWindowsAcl(directory);
        }
        else
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyWindowsAcl(string directory)
    {
        var info = new DirectoryInfo(directory);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var owners = new List<SecurityIdentifier>
        {
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
        };

        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (identity.User is { } current && !owners.Contains(current))
            {
                owners.Add(current);
            }
        }

        foreach (var sid in owners)
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));
        }

        info.SetAccessControl(security);
    }
}
