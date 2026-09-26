using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace OfficeSecurity.Server.Infrastructure.Persistence;

/// <summary>Stores <see cref="DateTimeOffset"/> as UTC ticks without loss of precision.</summary>
public sealed class UtcTicksConverter() : ValueConverter<DateTimeOffset, long>(
    value => value.UtcTicks,
    ticks => new DateTimeOffset(ticks, TimeSpan.Zero));
