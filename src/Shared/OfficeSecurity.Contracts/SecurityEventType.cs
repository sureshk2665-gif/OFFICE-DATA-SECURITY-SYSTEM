namespace OfficeSecurity.Contracts;

/// <summary>
/// Security event types collected by agents and the server. Values are persisted and must never be renumbered.
/// </summary>
public enum SecurityEventType
{
    UnauthorizedUsbConnection = 1,
    RemovableStorageBlocked = 2,
    UnauthorizedSoftwareInstallAttempt = 3,
    UnauthorizedApplicationBlocked = 4,
    AgentStoppedOrUnavailable = 5,
    PolicyTamperAttempt = 6,
    FailedLogin = 7,
    ComputerOffline = 8,
    UnauthorizedDeviceRegistration = 9,
    FileTransferBlocked = 10,
    PolicyViolation = 11,
    ApprovedDeviceConnected = 12,
    SoftwareInstalled = 13,
    ProtectedFileAccess = 14,
    StaffIsLocalAdministrator = 15,
    PolicyApplied = 16,
    SuccessfulLogin = 17,
    Logout = 18,
}
