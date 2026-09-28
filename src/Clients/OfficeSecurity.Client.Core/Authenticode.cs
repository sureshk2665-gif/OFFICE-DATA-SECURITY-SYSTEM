using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace OfficeSecurity.Client.Core;

public enum SignatureState
{
    /// <summary>The file carries a valid signature from a trusted code-signing certificate.</summary>
    Valid,

    /// <summary>The file has no digital signature.</summary>
    NotSigned,

    /// <summary>The file has a signature, but it is broken (file modified) or not trusted.</summary>
    Invalid,

    /// <summary>Checking signatures is not possible on this operating system.</summary>
    Unavailable,
}

public sealed record SignatureCheck(SignatureState State, string? SignerSubject, string? Detail);

/// <summary>
/// Authenticode signature check using the Windows WinVerifyTrust API (the same check Windows performs
/// before running signed programs). Revocation is not checked online, so it works on offices without
/// internet access.
/// </summary>
public static partial class Authenticode
{
    private const uint TrustENoSignature = 0x800B0100;
    private const uint TrustESubjectFormUnknown = 0x800B0003;
    private const uint TrustEProviderUnknown = 0x800B0001;

    public static SignatureCheck Check(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return OperatingSystem.IsWindows() ? CheckWindows(path) : new SignatureCheck(SignatureState.Unavailable, null, "Signature checks require Windows.");
    }

    [SupportedOSPlatform("windows")]
    private static SignatureCheck CheckWindows(string path)
    {
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
        var pathPointer = Marshal.StringToHGlobalUni(Path.GetFullPath(path));
        var fileInfoPointer = IntPtr.Zero;
        try
        {
            var fileInfo = new WintrustFileInfo { CbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>(), FilePath = pathPointer };
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var data = new WintrustData
            {
                CbStruct = (uint)Marshal.SizeOf<WintrustData>(),
                UiChoice = 2,              // WTD_UI_NONE
                RevocationChecks = 0,      // WTD_REVOKE_NONE
                UnionChoice = 1,           // WTD_CHOICE_FILE
                File = fileInfoPointer,
                StateAction = 1,           // WTD_STATEACTION_VERIFY
                ProvFlags = 0x00001000,    // WTD_CACHE_ONLY_URL_RETRIEVAL (no network access)
            };

            var result = unchecked((uint)WinVerifyTrust(IntPtr.Zero, ref action, ref data));
            data.StateAction = 2; // WTD_STATEACTION_CLOSE
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            return result switch
            {
                0 => new SignatureCheck(SignatureState.Valid, SignerSubject(path), null),
                TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown => new SignatureCheck(SignatureState.NotSigned, null, "The file is not digitally signed."),
                _ => new SignatureCheck(SignatureState.Invalid, null, $"The digital signature is not valid (0x{result:X8}). The file may have been modified."),
            };
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPointer);
            }

            Marshal.FreeHGlobal(pathPointer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? SignerSubject(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // No replacement API reads the Authenticode signer; the signature itself was verified by WinVerifyTrust.
            using var certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return certificate.Subject;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustFileInfo
    {
        public uint CbStruct;
        public IntPtr FilePath;
        public IntPtr File;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint CbStruct;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr File;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [LibraryImport("wintrust.dll")]
    private static partial int WinVerifyTrust(IntPtr window, ref Guid action, ref WintrustData data);
}
