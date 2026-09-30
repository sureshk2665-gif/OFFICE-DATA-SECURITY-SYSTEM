using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;

namespace OfficeSecurity.Server.Api.Hosting;

public sealed record BackupManifest(int Format, DateTimeOffset CreatedUtc, string MachineName, string ServerVersion, Dictionary<string, string> Sha256);

/// <summary>
/// Password-protected backup of everything the server needs: the database, the key ring that protects the
/// stored secrets, the certificates and signing key, uploaded installers and saved reports.
/// <para>
/// On Windows the key ring is normally locked to this computer (DPAPI). The backup contains it unlocked, so it
/// can be restored on a new server PC after a failure; that is why the whole file is encrypted
/// (AES-256-GCM, key from the password with PBKDF2-SHA256, 600,000 iterations). Restoring locks the key ring to
/// the new computer again.
/// </para>
/// </summary>
public static class ServerBackup
{
    public const int MinimumPasswordLength = 12;
    private const int Iterations = 600_000;
    private const int ChunkSize = 1 << 20;
    private static readonly byte[] Magic = "OCSSBACKUP1\n"u8.ToArray();
    private static readonly XNamespace DataProtectionNs = "http://schemas.asp.net/2015/03/dataProtection";
    private static readonly string[] Folders = ["keys", "certificates", "packages", "reports"];
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>Writes the backup file. The server can keep running (the database is copied consistently).</summary>
    public static BackupManifest Create(ServerPaths paths, string password, string outputFile, string serverVersion)
    {
        ArgumentNullException.ThrowIfNull(paths);
        CheckPassword(password);
        if (!File.Exists(paths.DatabaseFile))
        {
            throw new InvalidOperationException($"No database found in {paths.DataDirectory}.");
        }

        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        var archivePath = Path.Combine(paths.DataDirectory, $"backup-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
            {
                // A consistent copy of the database while the server may be using it (SQLite online backup).
                var dbCopy = Path.Combine(paths.DataDirectory, $"backup-{Guid.NewGuid():N}.db");
                try
                {
                    using (var source = new SqliteConnection($"Data Source={paths.DatabaseFile};Mode=ReadOnly;Pooling=False"))
                    using (var target = new SqliteConnection($"Data Source={dbCopy};Pooling=False"))
                    {
                        source.Open();
                        target.Open();
                        source.BackupDatabase(target);
                    }

                    Add(archive, "database/office-security.db", File.ReadAllBytes(dbCopy), hashes);
                }
                finally
                {
                    File.Delete(dbCopy);
                }

                foreach (var folder in Folders)
                {
                    var directory = Path.Combine(paths.DataDirectory, folder);
                    if (!Directory.Exists(directory))
                    {
                        continue;
                    }

                    foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
                    {
                        var relative = folder + "/" + Path.GetRelativePath(directory, file).Replace('\\', '/');
                        var content = File.ReadAllBytes(file);
                        if (folder == "keys" && file.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                        {
                            content = UnlockKey(content);
                        }

                        Add(archive, relative, content, hashes);
                    }
                }

                var manifest = new BackupManifest(1, DateTimeOffset.UtcNow, Environment.MachineName, serverVersion, hashes);
                Add(archive, "manifest.json", JsonSerializer.SerializeToUtf8Bytes(manifest, Json), null);
            }

            using (var plain = File.OpenRead(archivePath))
            using (var output = new FileStream(outputFile + ".tmp", FileMode.Create, FileAccess.Write, FileShare.None))
            {
                Encrypt(plain, output, password);
            }

            File.Move(outputFile + ".tmp", outputFile, overwrite: true);
            return new BackupManifest(1, DateTimeOffset.UtcNow, Environment.MachineName, serverVersion, hashes);
        }
        finally
        {
            File.Delete(archivePath);
        }
    }

    /// <summary>
    /// Restores a backup into the (stopped) server's data directory. An existing data directory is moved aside to
    /// "…before-restore-&lt;time&gt;" first; nothing is deleted.
    /// </summary>
    public static (BackupManifest Manifest, string? PreviousDataMovedTo) Restore(ServerPaths paths, string password, string backupFile)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(password);
        var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(paths.DataDirectory))!;
        Directory.CreateDirectory(parent);
        var archivePath = Path.Combine(parent, $"restore-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var input = File.OpenRead(backupFile))
            using (var plain = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                Decrypt(input, plain, password);
            }

            using var archive = ZipFile.OpenRead(archivePath);
            var manifestEntry = archive.GetEntry("manifest.json") ?? throw new InvalidDataException("The backup has no manifest.");
            BackupManifest manifest;
            using (var stream = manifestEntry.Open())
            {
                manifest = JsonSerializer.Deserialize<BackupManifest>(stream, Json) ?? throw new InvalidDataException("The backup manifest is empty.");
            }

            // Everything listed must be present and unchanged before anything is replaced.
            foreach (var (name, hash) in manifest.Sha256)
            {
                var entry = archive.GetEntry(name) ?? throw new InvalidDataException($"The backup is missing {name}.");
                using var stream = entry.Open();
                if (!string.Equals(Convert.ToHexString(SHA256.HashData(stream)), hash, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException($"{name} in the backup is damaged.");
                }
            }

            string? movedTo = null;
            if (Directory.Exists(paths.DataDirectory) && Directory.EnumerateFileSystemEntries(paths.DataDirectory).Any())
            {
                movedTo = Path.TrimEndingDirectorySeparator(paths.DataDirectory) + ".before-restore-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
                Directory.Move(paths.DataDirectory, movedTo);
            }

            DataDirectoryProtection.CreateAndProtect(paths.DataDirectory);
            var root = Path.GetFullPath(paths.DataDirectory) + Path.DirectorySeparatorChar;
            foreach (var name in manifest.Sha256.Keys)
            {
                var target = Path.GetFullPath(Path.Combine(paths.DataDirectory, name == "database/office-security.db" ? "office-security.db" : name));
                if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException($"The backup contains an invalid path: {name}");
                }

                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                using var stream = archive.GetEntry(name)!.Open();
                using var memory = new MemoryStream();
                stream.CopyTo(memory);
                var content = memory.ToArray();
                if (name.StartsWith("keys/", StringComparison.Ordinal) && name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                {
                    content = LockKey(content);
                }

                File.WriteAllBytes(target, content);
            }

            return (manifest, movedTo);
        }
        finally
        {
            File.Delete(archivePath);
        }
    }

    public static void CheckPassword(string? password)
    {
        if (password is null || password.Length < MinimumPasswordLength)
        {
            throw new ArgumentException($"The backup password must have at least {MinimumPasswordLength} characters.", nameof(password));
        }
    }

    // ---------------------------------------------------------------- key ring (DPAPI on Windows)

    /// <summary>Replaces a DPAPI-locked master key with the plain one (only inside the encrypted backup).</summary>
    private static byte[] UnlockKey(byte[] xml)
    {
        var doc = XDocument.Parse(Encoding.UTF8.GetString(xml));
        foreach (var secret in doc.Descendants(DataProtectionNs + "encryptedSecret").ToList())
        {
            var decryptorType = (string?)secret.Attribute("decryptorType") ?? string.Empty;
            if (!decryptorType.Contains(nameof(DpapiXmlDecryptor), StringComparison.Ordinal) || !OperatingSystem.IsWindows())
            {
                throw new InvalidOperationException("The key ring is protected in a way this backup cannot handle: " + decryptorType);
            }

            secret.ReplaceWith(new DpapiXmlDecryptor().Decrypt(secret.Elements().First()));
        }

        return Encoding.UTF8.GetBytes(doc.ToString(SaveOptions.DisableFormatting));
    }

    /// <summary>Locks plain master keys to this computer again (Windows); elsewhere they stay as the server keeps them.</summary>
    private static byte[] LockKey(byte[] xml)
    {
        if (!OperatingSystem.IsWindows())
        {
            return xml;
        }

        var doc = XDocument.Parse(Encoding.UTF8.GetString(xml));
        var encryptor = new DpapiXmlEncryptor(protectToLocalMachine: true, NullLoggerFactory.Instance);
        foreach (var masterKey in doc.Descendants("masterKey").ToList())
        {
            var info = encryptor.Encrypt(masterKey);
            masterKey.ReplaceWith(new XElement(DataProtectionNs + "encryptedSecret",
                new XAttribute("decryptorType", info.DecryptorType.AssemblyQualifiedName!), info.EncryptedElement));
        }

        return Encoding.UTF8.GetBytes(doc.ToString(SaveOptions.DisableFormatting));
    }

    // ---------------------------------------------------------------- encryption

    // File: magic | salt (16) | iterations (4) | nonce prefix (4) | chunks.
    // Chunk: length (4) | ciphertext | tag (16); nonce = prefix | chunk number (8); the header, chunk number and
    // a "last chunk" flag are authenticated, so reordering, removing or cutting off chunks is detected.
    private static void Encrypt(Stream plain, Stream output, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var prefix = RandomNumberGenerator.GetBytes(4);
        var header = Header(salt, Iterations, prefix);
        output.Write(header);
        using var aes = new AesGcm(DeriveKey(password, salt, Iterations), 16);
        var buffer = new byte[ChunkSize];
        var next = new byte[ChunkSize];
        var length = ReadFull(plain, buffer);
        long index = 0;
        Span<byte> size = stackalloc byte[4];
        while (true)
        {
            var nextLength = length == ChunkSize ? ReadFull(plain, next) : 0;
            var last = nextLength == 0;
            var cipher = new byte[length];
            var tag = new byte[16];
            aes.Encrypt(Nonce(prefix, index), buffer.AsSpan(0, length), cipher, tag, Aad(header, index, last));
            BinaryPrimitives.WriteInt32BigEndian(size, length);
            output.Write(size);
            output.Write(cipher);
            output.Write(tag);
            if (last)
            {
                return;
            }

            (buffer, next) = (next, buffer);
            length = nextLength;
            index++;
        }
    }

    private static void Decrypt(Stream input, Stream plain, string password)
    {
        var header = new byte[Magic.Length + 16 + 4 + 4];
        if (ReadFull(input, header) != header.Length || !header.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new InvalidDataException("This is not an Office Security server backup.");
        }

        var salt = header.AsSpan(Magic.Length, 16).ToArray();
        var iterations = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(Magic.Length + 16, 4));
        var prefix = header.AsSpan(Magic.Length + 20, 4).ToArray();
        if (iterations is < 100_000 or > 10_000_000)
        {
            throw new InvalidDataException("The backup header is damaged.");
        }

        using var aes = new AesGcm(DeriveKey(password, salt, iterations), 16);
        var size = new byte[4];
        long index = 0;
        var finished = false;
        while (ReadFull(input, size) == 4)
        {
            if (finished)
            {
                throw new InvalidDataException("The backup has extra data at the end.");
            }

            var length = BinaryPrimitives.ReadInt32BigEndian(size);
            if (length is < 0 or > ChunkSize)
            {
                throw new InvalidDataException("The backup is damaged.");
            }

            var cipher = new byte[length];
            var tag = new byte[16];
            if (ReadFull(input, cipher) != length || ReadFull(input, tag) != 16)
            {
                throw new InvalidDataException("The backup is incomplete.");
            }

            var data = new byte[length];
            try
            {
                aes.Decrypt(Nonce(prefix, index), cipher, tag, data, Aad(header, index, last: false));
            }
            catch (AuthenticationTagMismatchException)
            {
                try
                {
                    aes.Decrypt(Nonce(prefix, index), cipher, tag, data, Aad(header, index, last: true));
                    finished = true;
                }
                catch (AuthenticationTagMismatchException)
                {
                    throw new CryptographicException(index == 0 ? "Wrong password, or the backup file was changed." : "The backup file was changed or damaged.");
                }
            }

            plain.Write(data);
            index++;
        }

        if (!finished)
        {
            throw new InvalidDataException("The backup is incomplete (it was cut off).");
        }
    }

    private static byte[] Header(byte[] salt, int iterations, byte[] prefix)
    {
        var header = new byte[Magic.Length + 16 + 4 + 4];
        Magic.CopyTo(header, 0);
        salt.CopyTo(header, Magic.Length);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(Magic.Length + 16), iterations);
        prefix.CopyTo(header, Magic.Length + 20);
        return header;
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);

    private static byte[] Nonce(byte[] prefix, long index)
    {
        var nonce = new byte[12];
        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteInt64BigEndian(nonce.AsSpan(4), index);
        return nonce;
    }

    private static byte[] Aad(byte[] header, long index, bool last)
    {
        var aad = new byte[header.Length + 9];
        header.CopyTo(aad, 0);
        BinaryPrimitives.WriteInt64BigEndian(aad.AsSpan(header.Length), index);
        aad[^1] = last ? (byte)1 : (byte)0;
        return aad;
    }

    private static int ReadFull(Stream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = stream.Read(buffer, total, buffer.Length - total);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static void Add(ZipArchive archive, string name, byte[] content, Dictionary<string, string>? hashes)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using (var stream = entry.Open())
        {
            stream.Write(content);
        }

        if (hashes is not null)
        {
            hashes[name] = Convert.ToHexString(SHA256.HashData(content));
        }
    }
}
