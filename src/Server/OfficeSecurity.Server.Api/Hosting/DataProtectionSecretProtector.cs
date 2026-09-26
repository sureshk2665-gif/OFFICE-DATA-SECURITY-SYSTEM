using Microsoft.AspNetCore.DataProtection;
using OfficeSecurity.Server.Application.Abstractions;

namespace OfficeSecurity.Server.Api.Hosting;

/// <summary>
/// <see cref="ISecretProtector"/> backed by ASP.NET Core Data Protection. On Windows the key ring is
/// encrypted with machine-wide DPAPI, so secrets cannot be decrypted on another computer.
/// </summary>
public sealed class DataProtectionSecretProtector : ISecretProtector
{
    private readonly IDataProtector _protector;

    private DataProtectionSecretProtector(IDataProtector protector) => _protector = protector;

    public static DataProtectionSecretProtector Create(string keysDirectory)
    {
        Directory.CreateDirectory(keysDirectory);
        var provider = DataProtectionProvider.Create(new DirectoryInfo(keysDirectory), builder =>
        {
            builder.SetApplicationName("OfficeSecurity.Server");
            if (OperatingSystem.IsWindows())
            {
                builder.ProtectKeysWithDpapi(protectToLocalMachine: true);
            }
        });
        return new DataProtectionSecretProtector(provider.CreateProtector("OfficeSecurity.Server.Secrets.v1"));
    }

    public byte[] Protect(byte[] plaintext) => _protector.Protect(plaintext);

    public byte[] Unprotect(byte[] protectedData) => _protector.Unprotect(protectedData);
}
