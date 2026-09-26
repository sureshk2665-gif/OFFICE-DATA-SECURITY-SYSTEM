namespace OfficeSecurity.Server.Application.Abstractions;

/// <summary>
/// Encrypts secrets stored in the database (e.g. TOTP secrets). On Windows the key is protected with
/// DPAPI for the local machine, so a copied database file alone cannot reveal them.
/// </summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);

    byte[] Unprotect(byte[] protectedData);
}
