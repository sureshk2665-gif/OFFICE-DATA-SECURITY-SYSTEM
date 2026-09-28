using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.Core;

/// <summary>Sends enforcement events through the agent's offline-safe event queue.</summary>
public sealed class QueuedEnforcementEvents(PendingEventStore events) : IEnforcementEvents
{
    public void Raise(SecurityEventType type, string severity, string details) => events.Enqueue(type, severity, details);
}
