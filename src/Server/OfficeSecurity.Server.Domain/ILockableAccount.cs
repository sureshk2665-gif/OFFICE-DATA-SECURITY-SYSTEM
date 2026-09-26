namespace OfficeSecurity.Server.Domain;

/// <summary>An account that is temporarily locked after repeated failed sign-in attempts.</summary>
public interface ILockableAccount
{
    int FailedLoginCount { get; set; }

    DateTimeOffset? LockedUntilUtc { get; set; }
}
