using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>Where enforcers report security events (e.g. a protection that was changed and restored).</summary>
public interface IEnforcementEvents
{
    void Raise(SecurityEventType type, string severity, string details);
}

public sealed class NoEnforcementEvents : IEnforcementEvents
{
    public static readonly NoEnforcementEvents Instance = new();

    public void Raise(SecurityEventType type, string severity, string details)
    {
    }
}
