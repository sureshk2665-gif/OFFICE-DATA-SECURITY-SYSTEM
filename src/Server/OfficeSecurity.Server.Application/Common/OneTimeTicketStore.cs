using System.Collections.Concurrent;
using OfficeSecurity.Server.Application.Security;

namespace OfficeSecurity.Server.Application.Common;

/// <summary>
/// Short-lived, in-memory tickets for multi-step sign-in (password → two-step code). Tickets are
/// lost on server restart, which only means the user has to start the sign-in again.
/// </summary>
public sealed class OneTimeTicketStore<T>(TimeProvider clock)
    where T : notnull
{
    private const int MaxAttemptsPerTicket = 5;
    private readonly ConcurrentDictionary<string, Entry> _tickets = new(StringComparer.Ordinal);

    public string Issue(T value, TimeSpan lifetime)
    {
        RemoveExpired();
        var ticket = SecretCodes.NewToken();
        _tickets[SecretCodes.HashForStorage(ticket)] = new Entry(value, clock.GetUtcNow() + lifetime);
        return ticket;
    }

    /// <summary>Returns the value without consuming the ticket (used while a code is being checked).</summary>
    public bool TryPeek(string? ticket, out T value)
    {
        value = default!;
        if (string.IsNullOrEmpty(ticket) || !_tickets.TryGetValue(SecretCodes.HashForStorage(ticket), out var entry))
        {
            return false;
        }

        if (entry.ExpiresAtUtc <= clock.GetUtcNow() || entry.Attempts >= MaxAttemptsPerTicket)
        {
            _tickets.TryRemove(SecretCodes.HashForStorage(ticket), out _);
            return false;
        }

        value = entry.Value;
        return true;
    }

    /// <summary>Counts a wrong code against the ticket; the ticket is discarded after too many attempts.</summary>
    public void RecordFailedAttempt(string ticket)
    {
        var key = SecretCodes.HashForStorage(ticket);
        if (_tickets.TryGetValue(key, out var entry))
        {
            _tickets[key] = entry with { Attempts = entry.Attempts + 1 };
        }
    }

    public void Consume(string ticket) => _tickets.TryRemove(SecretCodes.HashForStorage(ticket), out _);

    private void RemoveExpired()
    {
        var now = clock.GetUtcNow();
        foreach (var (key, entry) in _tickets)
        {
            if (entry.ExpiresAtUtc <= now)
            {
                _tickets.TryRemove(key, out _);
            }
        }
    }

    private sealed record Entry(T Value, DateTimeOffset ExpiresAtUtc, int Attempts = 0);
}
