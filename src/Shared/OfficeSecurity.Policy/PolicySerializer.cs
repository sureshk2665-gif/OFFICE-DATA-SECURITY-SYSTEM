using System.Text.Json;
using System.Text.Json.Serialization;

namespace OfficeSecurity.Policy;

/// <summary>Single place that defines how policy documents are converted to and from bytes.</summary>
public static class PolicySerializer
{
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    public static byte[] ToUtf8Bytes(SecurityPolicyDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        return JsonSerializer.SerializeToUtf8Bytes(document, Options);
    }

    public static SecurityPolicyDocument FromUtf8Bytes(ReadOnlySpan<byte> utf8Json) =>
        JsonSerializer.Deserialize<SecurityPolicyDocument>(utf8Json, Options)
        ?? throw new JsonException("Policy document is empty.");

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
        options.Converters.Add(new JsonStringEnumConverter(allowIntegerValues: false));
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}
