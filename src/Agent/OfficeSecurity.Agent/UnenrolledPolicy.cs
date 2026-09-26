using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent;

/// <summary>Policy used before the computer is enrolled: every control is off.</summary>
internal static class UnenrolledPolicy
{
    public static SecurityPolicyDocument Create() => new()
    {
        Version = 0,
        ComputerId = Guid.Empty,
        IssuedAtUtc = DateTimeOffset.UnixEpoch,
    };
}
