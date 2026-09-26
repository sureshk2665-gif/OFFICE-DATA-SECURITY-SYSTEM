namespace OfficeSecurity.Policy;

/// <summary>
/// Transport format for a signed policy. The signature covers the exact payload bytes, so no JSON
/// canonicalisation is needed: the agent verifies the bytes first and only then deserialises them.
/// </summary>
/// <param name="KeyId">Identifier of the signing key (SHA-256 of its public key, hex).</param>
/// <param name="Payload">UTF-8 JSON of <see cref="SecurityPolicyDocument"/>.</param>
/// <param name="Signature">ECDSA P-256 / SHA-256 signature in IEEE P1363 format.</param>
public sealed record SignedPolicyEnvelope(string KeyId, byte[] Payload, byte[] Signature);
