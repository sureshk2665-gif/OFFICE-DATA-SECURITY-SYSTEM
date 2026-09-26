using System.Text.Json;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Core;

/// <summary>
/// The last valid signed policy, kept on disk so it is enforced after a restart even when the server is
/// unreachable. It is re-verified on every load; a modified file is rejected.
/// </summary>
public sealed class PolicyCache(AgentPaths paths)
{
    private sealed record StoredEnvelope(string KeyId, string Payload, string Signature);

    public void Save(SignedPolicyEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var stored = new StoredEnvelope(envelope.KeyId, Convert.ToBase64String(envelope.Payload), Convert.ToBase64String(envelope.Signature));
        var temp = paths.PolicyCacheFile + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(stored));
        File.Move(temp, paths.PolicyCacheFile, overwrite: true);
    }

    /// <summary>Loads and verifies the cached policy. Returns the verification result, or null if there is no cache.</summary>
    public PolicyVerificationResult? Load(PolicyVerifier verifier, Guid computerId)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        if (!File.Exists(paths.PolicyCacheFile))
        {
            return null;
        }

        try
        {
            var stored = JsonSerializer.Deserialize<StoredEnvelope>(File.ReadAllText(paths.PolicyCacheFile));
            if (stored is null)
            {
                return new PolicyVerificationResult(null, PolicyRejectionReason.MalformedDocument, "Cached policy file is empty.");
            }

            var envelope = new SignedPolicyEnvelope(stored.KeyId, Convert.FromBase64String(stored.Payload), Convert.FromBase64String(stored.Signature));
            return verifier.Verify(envelope, computerId, currentVersion: null);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return new PolicyVerificationResult(null, PolicyRejectionReason.MalformedDocument, "Cached policy file is damaged: " + ex.Message);
        }
    }

    public void Delete() => File.Delete(paths.PolicyCacheFile);
}
