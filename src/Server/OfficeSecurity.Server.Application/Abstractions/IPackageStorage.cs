namespace OfficeSecurity.Server.Application.Abstractions;

public sealed record StoredPackage(string Sha256, long SizeBytes);

/// <summary>Stores installer files on the server (outside the database).</summary>
public interface IPackageStorage
{
    /// <summary>Streams the upload to storage, computing its SHA-256. Throws <see cref="InvalidDataException"/> if it exceeds <paramref name="maxBytes"/>.</summary>
    Task<StoredPackage> SaveAsync(Guid packageId, Stream content, long maxBytes, CancellationToken cancellationToken);

    Stream OpenRead(Guid packageId);

    void Delete(Guid packageId);
}
