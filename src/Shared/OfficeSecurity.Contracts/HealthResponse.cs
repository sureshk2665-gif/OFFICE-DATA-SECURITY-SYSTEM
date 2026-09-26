namespace OfficeSecurity.Contracts;

/// <summary>Response of <see cref="ApiRoutes.Health"/>. Contains no sensitive information.</summary>
public sealed record HealthResponse(string Status, string ServerVersion, DateTimeOffset ServerTimeUtc);
