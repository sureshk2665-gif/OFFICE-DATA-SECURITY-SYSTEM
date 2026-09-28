using System.Security.Cryptography;
using OfficeSecurity.Server.Application.Abstractions;

namespace OfficeSecurity.Server.Infrastructure.Persistence;

/// <summary>Installer files in the server's protected data folder (packages\{id}.pkg).</summary>
public sealed class FilePackageStorage(string directory) : IPackageStorage
{
    public async Task<StoredPackage> SaveAsync(Guid packageId, Stream content, long maxBytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        Directory.CreateDirectory(directory);
        var temp = PathFor(packageId) + ".uploading";
        long total = 0;
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            await using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                var buffer = new byte[81920];
                int read;
                while ((read = await content.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    total += read;
                    if (total > maxBytes)
                    {
                        throw new InvalidDataException("The installer file is too large.");
                    }

                    sha.AppendData(buffer, 0, read);
                    await file.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }
            }

            File.Move(temp, PathFor(packageId), overwrite: false);
            return new StoredPackage(Convert.ToHexStringLower(sha.GetHashAndReset()), total);
        }
        catch
        {
            File.Delete(temp);
            throw;
        }
    }

    public Stream OpenRead(Guid packageId) =>
        new FileStream(PathFor(packageId), FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);

    public void Delete(Guid packageId) => File.Delete(PathFor(packageId));

    private string PathFor(Guid packageId) => Path.Combine(directory, packageId.ToString("N") + ".pkg");
}
