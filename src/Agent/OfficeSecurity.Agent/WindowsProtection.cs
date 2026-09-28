using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using OfficeSecurity.Agent.Enforcement;

namespace OfficeSecurity.Agent;

/// <summary>Runs a Windows tool without a window and returns its exit code and output.</summary>
internal static class Tool
{
    public static (int ExitCode, string Output) Run(string fileName, params string[] arguments)
    {
        var start = new ProcessStartInfo(fileName) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {fileName}.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromMinutes(5)))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{Path.GetFileName(fileName)} did not finish within 5 minutes.");
        }

        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    public static string System32(string file) => Path.Combine(Environment.SystemDirectory, file);

    /// <summary>Runs a PowerShell script (Windows PowerShell 5.1, no profile) passed as an encoded command.</summary>
    public static (int ExitCode, string Output) PowerShell(string script) =>
        Run(System32(@"WindowsPowerShell\v1.0\powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));

    /// <summary>A PowerShell single-quoted string literal.</summary>
    public static string Quote(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
}

/// <summary>
/// Windows App Control for Business, using Microsoft's documented tools: the ConfigCI PowerShell cmdlets to build
/// the policy from the "Allow Microsoft" example policy that ships with Windows, and CiTool.exe to activate,
/// list and remove it without a restart.
/// </summary>
internal sealed class WindowsAppControl(string workDirectory) : IAppControlPlatform
{
    private string? _unsupported;
    private bool _checked;

    public string? UnsupportedReason()
    {
        if (_checked)
        {
            return _unsupported;
        }

        _checked = true;
        if (!File.Exists(Tool.System32("CiTool.exe")))
        {
            return _unsupported = "Application Control needs Windows 11 version 22H2 or later (CiTool.exe is not available on this computer).";
        }

        var example = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml");
        if (!File.Exists(example))
        {
            return _unsupported = "Windows' example App Control policies are missing on this computer.";
        }

        var (code, output) = Tool.PowerShell("if (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue) { 'ok' } else { 'missing' }");
        return _unsupported = code == 0 && output.Contains("ok", StringComparison.Ordinal) ? null : "The Windows App Control PowerShell tools (ConfigCI) are not available on this Windows edition.";
    }

    public AppControlPolicyState? Query(Guid policyId)
    {
        var (code, output) = Tool.Run(Tool.System32("CiTool.exe"), "--list-policies", "-json");
        if (code != 0)
        {
            throw new InvalidOperationException($"CiTool --list-policies failed ({code}): {Short(output)}");
        }

        var json = output[output.IndexOf('{', StringComparison.Ordinal)..];
        using var doc = JsonDocument.Parse(json);
        foreach (var policy in Policies(doc.RootElement))
        {
            if (Text(policy, "PolicyID", "PolicyId") is { } id && Guid.TryParse(id.Trim('{', '}'), out var g) && g == policyId)
            {
                var active = Bool(policy, "IsEnforced") ?? Bool(policy, "IsCurrentlyEnforced") ?? false;
                return new AppControlPolicyState(active, Text(policy, "VersionString", "Version"));
            }
        }

        return null;
    }

    public void Deploy(Guid policyId, AppControlBuild build)
    {
        ArgumentNullException.ThrowIfNull(build);
        Directory.CreateDirectory(workDirectory);
        var id = "{" + policyId.ToString("D").ToUpperInvariant() + "}";
        var script = new StringBuilder();
        script.AppendLine("$ErrorActionPreference = 'Stop'");
        script.AppendLine(CultureInfo.InvariantCulture, $"$dir = {Tool.Quote(workDirectory)}");
        script.AppendLine("$base = Join-Path $dir 'base.xml'; $policy = Join-Path $dir 'policy.xml'");
        script.AppendLine("Copy-Item (Join-Path $env:windir 'schemas\\CodeIntegrity\\ExamplePolicies\\AllowMicrosoft.xml') $base -Force");
        script.AppendLine("$rules = @()");
        foreach (var folder in build.AllowedFolders)
        {
            script.AppendLine(CultureInfo.InvariantCulture, $"$rules += New-CIPolicyRule -FilePathRule {Tool.Quote(folder)}");
        }

        script.AppendLine("Merge-CIPolicy -PolicyPaths $base -Rules $rules -OutputFilePath $policy | Out-Null");
        // 0 UMCI, 6 unsigned policy, 11 scripts not restricted, 16 update without restart; 3 audit mode.
        foreach (var option in new[] { 0, 6, 11, 16 })
        {
            script.AppendLine(CultureInfo.InvariantCulture, $"Set-RuleOption -FilePath $policy -Option {option}");
        }

        script.AppendLine(build.AuditOnly ? "Set-RuleOption -FilePath $policy -Option 3" : "Set-RuleOption -FilePath $policy -Option 3 -Delete");
        script.AppendLine(CultureInfo.InvariantCulture, $"Set-CIPolicyIdInfo -FilePath $policy -PolicyName {Tool.Quote(AppControlEnforcer.PolicyName)}");
        script.AppendLine("[xml]$doc = Get-Content -Raw $policy");
        script.AppendLine(CultureInfo.InvariantCulture, $"$doc.SiPolicy.PolicyID = {Tool.Quote(id)}; $doc.SiPolicy.BasePolicyID = {Tool.Quote(id)}");
        script.AppendLine("$doc.Save($policy)");
        script.AppendLine(CultureInfo.InvariantCulture, $"Set-CIPolicyVersion -FilePath $policy -Version {Tool.Quote(build.Version)}");
        script.AppendLine(CultureInfo.InvariantCulture, $"$bin = Join-Path $dir {Tool.Quote(id + ".cip")}");
        script.AppendLine("ConvertFrom-CIPolicy -XmlFilePath $policy -BinaryFilePath $bin | Out-Null");
        script.AppendLine("& (Join-Path $env:windir 'System32\\CiTool.exe') --update-policy $bin -json");
        script.AppendLine("if ($LASTEXITCODE -ne 0) { throw \"CiTool --update-policy failed with exit code $LASTEXITCODE\" }");

        var (code, output) = Tool.PowerShell(script.ToString());
        if (code != 0)
        {
            throw new InvalidOperationException($"The Application Control policy could not be activated ({code}): {Short(output)}");
        }
    }

    public void Remove(Guid policyId)
    {
        var (code, output) = Tool.Run(Tool.System32("CiTool.exe"), "--remove-policy", "{" + policyId.ToString("D") + "}", "-json");
        if (code != 0)
        {
            throw new InvalidOperationException($"CiTool --remove-policy failed ({code}): {Short(output)}");
        }
    }

    private static List<JsonElement> Policies(JsonElement root) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty("Policies", out var list) && list.ValueKind == JsonValueKind.Array ? [.. list.EnumerateArray()] : [];

    private static string? Text(JsonElement e, params string[] names)
    {
        foreach (var name in names)
        {
            if (e.TryGetProperty(name, out var v))
            {
                return v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString();
            }
        }

        return null;
    }

    private static bool? Bool(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : null;

    private static string Short(string text) => text.Length > 1500 ? text[^1500..] : text.Trim();
}

/// <summary>Advanced audit policy: read with the Windows audit API, changed with auditpol.exe (a Windows tool).</summary>
internal sealed partial class WindowsAuditPolicy : IAuditPolicy
{
    public int Query(Guid subcategory)
    {
        if (!AuditQuerySystemPolicy(in subcategory, 1, out var buffer))
        {
            throw new InvalidOperationException($"Could not read the Windows audit policy (error {Marshal.GetLastPInvokeError()}).");
        }

        try
        {
            return (int)(Marshal.PtrToStructure<AuditPolicyInformation>(buffer).AuditingInformation & 3);
        }
        finally
        {
            AuditFree(buffer);
        }
    }

    public void Change(Guid subcategory, bool success, bool failure)
    {
        var (code, output) = Tool.Run(Tool.System32("auditpol.exe"), "/set", $"/subcategory:{{{subcategory:D}}}",
            $"/success:{(success ? "enable" : "disable")}", $"/failure:{(failure ? "enable" : "disable")}");
        if (code != 0)
        {
            throw new InvalidOperationException($"auditpol failed ({code}): {output.Trim()}");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AuditQuerySystemPolicy(in Guid subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

    [LibraryImport("advapi32.dll")]
    private static partial void AuditFree(IntPtr buffer);
}

/// <summary>Audit entries on folders: Everyone, successful read/write/delete, inherited by files and subfolders.</summary>
internal sealed class WindowsFolderAudit : IFolderAudit
{
    private const FileSystemRights Rights = FileSystemRights.ReadData | FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete;
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    public bool Exists(string folder) => Directory.Exists(folder);

    public bool HasRule(string folder) =>
        new DirectoryInfo(folder).GetAccessControl(AccessControlSections.Audit).GetAuditRules(true, false, typeof(SecurityIdentifier))
            .OfType<FileSystemAuditRule>()
            .Any(r => r.IdentityReference == Everyone && (r.FileSystemRights & Rights) == Rights && r.AuditFlags.HasFlag(AuditFlags.Success)
                && r.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit));

    public void AddRule(string folder) => Change(folder, (s, r) => s.AddAuditRule(r));

    public void RemoveRule(string folder) => Change(folder, (s, r) => s.RemoveAuditRuleSpecific(r));

    private static void Change(string folder, Action<DirectorySecurity, FileSystemAuditRule> change)
    {
        var directory = new DirectoryInfo(folder);
        var security = directory.GetAccessControl(AccessControlSections.Audit);
        change(security, new FileSystemAuditRule(Everyone, Rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AuditFlags.Success));
        directory.SetAccessControl(security);
    }
}

/// <summary>Microsoft Defender Antivirus status through its documented WMI classes.</summary>
internal sealed class WindowsDefenderStatus : IDefenderStatus
{
    private const string Namespace = @"root\Microsoft\Windows\Defender";

    public string? InactiveReason()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(Namespace, "SELECT AMServiceEnabled, RealTimeProtectionEnabled, AMRunningMode FROM MSFT_MpComputerStatus");
            foreach (ManagementObject status in searcher.Get())
            {
                using (status)
                {
                    if (status["AMServiceEnabled"] is not true || status["RealTimeProtectionEnabled"] is not true)
                    {
                        return "Microsoft Defender Antivirus real-time protection is off on this computer, so ransomware protection cannot work.";
                    }

                    if (status["AMRunningMode"] is string mode && !mode.Equals("Normal", StringComparison.OrdinalIgnoreCase))
                    {
                        return $"Microsoft Defender Antivirus runs in '{mode}' (another antivirus is active), so ransomware protection cannot work.";
                    }

                    return null;
                }
            }
        }
        catch (ManagementException ex)
        {
            return "Microsoft Defender Antivirus is not available: " + ex.Message;
        }

        return "Microsoft Defender Antivirus is not available on this computer.";
    }

    public int? EffectiveControlledFolderAccess()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(Namespace, "SELECT EnableControlledFolderAccess FROM MSFT_MpPreference");
            foreach (ManagementObject preference in searcher.Get())
            {
                using (preference)
                {
                    return preference["EnableControlledFolderAccess"] is { } v ? Convert.ToInt32(v, CultureInfo.InvariantCulture) : null;
                }
            }
        }
        catch (ManagementException)
        {
            return null;
        }

        return null;
    }
}

/// <summary>BitLocker state of fixed drives (Win32_EncryptableVolume, administrators and SYSTEM only).</summary>
internal sealed class WindowsDiskEncryption : IDiskEncryptionStatus
{
    private const string Namespace = @"root\CIMV2\Security\MicrosoftVolumeEncryption";

    public string? UnavailableReason()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(Namespace, "SELECT DriveLetter FROM Win32_EncryptableVolume");
            _ = searcher.Get().Count;
            return null;
        }
        catch (ManagementException ex)
        {
            return "BitLocker is not available on this computer (" + ex.Message.Trim() + "). Windows Home editions do not include BitLocker.";
        }
    }

    public IReadOnlyList<(string Drive, bool Protected)> Drives()
    {
        var fixedDrives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed).Select(d => d.Name.TrimEnd('\\')).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var result = new List<(string, bool)>();
        using var searcher = new ManagementObjectSearcher(Namespace, "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume");
        foreach (ManagementObject volume in searcher.Get())
        {
            using (volume)
            {
                if (volume["DriveLetter"] is string letter && fixedDrives.Contains(letter))
                {
                    result.Add((letter, Convert.ToInt32(volume["ProtectionStatus"] ?? 0, CultureInfo.InvariantCulture) == 1));
                }
            }
        }

        return result.OrderBy(d => d.Item1, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
