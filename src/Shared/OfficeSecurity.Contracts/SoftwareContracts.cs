namespace OfficeSecurity.Contracts;

// ---------------------------------------------------------------- approved software catalog and packages

/// <summary>
/// A program the office allows. Installed programs whose name starts with <see cref="Name"/> (and whose
/// publisher matches, if given) count as approved in the inventory.
/// </summary>
public sealed record ApprovedSoftwareResponse(Guid Id, string Name, string? Publisher, string? Notes, DateTimeOffset CreatedAtUtc, IReadOnlyList<SoftwarePackageResponse> Packages);

public sealed record SaveApprovedSoftwareRequest(string Name, string? Publisher, string? Notes);

/// <param name="SignerSubject">Code-signing certificate subject recorded at upload; the agent requires the same signer.</param>
public sealed record SoftwarePackageResponse(
    Guid Id,
    Guid ApprovedSoftwareId,
    string FileName,
    string Sha256,
    long SizeBytes,
    string InstallerType,
    string? SilentArguments,
    string? SignerSubject,
    bool AllowUnsigned,
    DateTimeOffset UploadedAtUtc);

/// <summary>Package details sent as query parameters of the upload; the request body is the installer file.</summary>
public sealed record UploadPackageOptions(string FileName, string InstallerType, string? SilentArguments, string? SignerSubject, bool AllowUnsigned);

// ---------------------------------------------------------------- deployments

public sealed record CreateDeploymentRequest(Guid PackageId, IReadOnlyList<Guid> ComputerIds);

public sealed record DeploymentResponse(
    Guid Id,
    Guid PackageId,
    string SoftwareName,
    string FileName,
    Guid ComputerId,
    string ComputerName,
    Guid? RequestId,
    string Status,
    int Attempts,
    int? ExitCode,
    string? Message,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? FinishedAtUtc);

// ---------------------------------------------------------------- staff requests

public sealed record CreateSoftwareRequest(string SoftwareName, string Reason);

public static class SoftwareRequestStatuses
{
    public const string Pending = "Pending";
    public const string Approved = "Approved";
    public const string Rejected = "Rejected";
}

/// <param name="InstallStatus">Status of the installation job created at approval, if any.</param>
public sealed record SoftwareRequestResponse(
    Guid Id,
    Guid StaffId,
    string StaffName,
    string EmployeeCode,
    Guid? ComputerId,
    string? ComputerName,
    string SoftwareName,
    string Reason,
    string Status,
    string? ReviewNote,
    string? InstallStatus,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? DecidedAtUtc);

/// <param name="ComputerId">Target computer; defaults to the computer the request was made on.</param>
public sealed record ApproveSoftwareRequest(Guid PackageId, Guid? ComputerId, string? Note);

public sealed record RejectSoftwareRequest(string? Note);

// ---------------------------------------------------------------- inventory

public sealed record SoftwareTitleSummary(string Name, string? Publisher, int ComputerCount, IReadOnlyList<string> Versions, bool IsApproved);

public sealed record InstalledSoftwareResponse(
    Guid ComputerId,
    string ComputerName,
    string Name,
    string? Version,
    string? Publisher,
    string Scope,
    bool IsApproved,
    DateTimeOffset FirstSeenUtc);
