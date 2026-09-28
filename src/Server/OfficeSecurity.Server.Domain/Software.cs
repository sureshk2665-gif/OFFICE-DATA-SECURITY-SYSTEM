namespace OfficeSecurity.Server.Domain;

/// <summary>A program reported as installed on a computer.</summary>
public sealed class SoftwareInventoryItem
{
    public long Id { get; set; }

    public Guid ComputerId { get; set; }

    public required string Name { get; set; }

    /// <summary>Empty string when unknown (keeps the unique index simple).</summary>
    public required string Version { get; set; }

    public string? Publisher { get; set; }

    public DateOnly? InstallDate { get; set; }

    /// <summary>"Machine" or "User".</summary>
    public required string Scope { get; set; }

    public bool IsPresent { get; set; }

    public DateTimeOffset FirstSeenUtc { get; set; }

    public DateTimeOffset LastSeenUtc { get; set; }
}

public sealed class ApprovedSoftware
{
    public Guid Id { get; set; }

    public required string Name { get; set; }

    public string? Publisher { get; set; }

    public string? Notes { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public Guid CreatedByAdminId { get; set; }

    /// <summary>Case-insensitive match of an installed program against this catalog entry.</summary>
    public bool Matches(string name, string? publisher) =>
        name.StartsWith(Name, StringComparison.OrdinalIgnoreCase) &&
        (string.IsNullOrWhiteSpace(Publisher) || string.Equals(Publisher.Trim(), publisher?.Trim(), StringComparison.OrdinalIgnoreCase));
}

/// <summary>An installer file stored on the server for an approved program.</summary>
public sealed class SoftwarePackage
{
    public Guid Id { get; set; }

    public Guid ApprovedSoftwareId { get; set; }

    public required string FileName { get; set; }

    /// <summary>SHA-256 (lower-case hex) computed by the server while receiving the file.</summary>
    public required string Sha256 { get; set; }

    public long SizeBytes { get; set; }

    public required string InstallerType { get; set; }

    public string? SilentArguments { get; set; }

    public string? SignerSubject { get; set; }

    public bool AllowUnsigned { get; set; }

    public DateTimeOffset UploadedAtUtc { get; set; }

    public Guid UploadedByAdminId { get; set; }
}

public sealed class SoftwareRequest
{
    public Guid Id { get; set; }

    public Guid StaffId { get; set; }

    /// <summary>The computer the request was made on (verified by the agent's ticket at sign-in), if known.</summary>
    public Guid? ComputerId { get; set; }

    public required string SoftwareName { get; set; }

    public required string Reason { get; set; }

    public SoftwareRequestStatus Status { get; set; }

    public string? ReviewNote { get; set; }

    public Guid? ReviewedByAdminId { get; set; }

    public Guid? DeploymentJobId { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset? DecidedAtUtc { get; set; }
}

/// <summary>One installation of one package on one computer.</summary>
public sealed class DeploymentJob
{
    public Guid Id { get; set; }

    public Guid PackageId { get; set; }

    public Guid ComputerId { get; set; }

    public Guid? RequestId { get; set; }

    public DeploymentStatus Status { get; set; }

    public int Attempts { get; set; }

    public int? ExitCode { get; set; }

    public string? Message { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public Guid CreatedByAdminId { get; set; }

    public DateTimeOffset? StartedAtUtc { get; set; }

    public DateTimeOffset? FinishedAtUtc { get; set; }
}
