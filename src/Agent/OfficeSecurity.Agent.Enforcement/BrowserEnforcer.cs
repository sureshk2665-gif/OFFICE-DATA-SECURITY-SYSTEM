using System.Globalization;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>
/// Website blocking and private browsing for Microsoft Edge, Google Chrome and Mozilla Firefox, through their
/// documented machine policies (HKLM\SOFTWARE\Policies\...). Other browsers are not covered.
/// </summary>
public sealed class BrowserEnforcer(RegistryPolicyEngine engine, IEnforcementEvents events, TimeProvider clock)
    : RegistryPolicyEnforcer(engine, events, clock)
{
    public const string EdgeKey = @"SOFTWARE\Policies\Microsoft\Edge";
    public const string ChromeKey = @"SOFTWARE\Policies\Google\Chrome";
    public const string FirefoxKey = @"SOFTWARE\Policies\Mozilla\Firefox";

    public override SecurityControl Control => SecurityControl.BrowserRestrictions;

    protected override string Description => "Website restrictions";

    protected override RegistryPlan Plan(SecurityPolicyDocument policy)
    {
        var b = policy.Browser;
        if (b.BlockedUrls.Count == 0 && b.AllowedUrls.Count == 0 && !b.DisablePrivateBrowsing)
        {
            return RegistryPlan.NotConfigured();
        }

        var values = new List<PolicyValue>();
        foreach (var key in new[] { EdgeKey, ChromeKey })
        {
            values.AddRange(List($@"{key}\URLBlocklist", b.BlockedUrls));
            values.AddRange(List($@"{key}\URLAllowlist", b.AllowedUrls));
        }

        values.AddRange(List($@"{FirefoxKey}\WebsiteFilter\Block", b.BlockedUrls.Select(ToFirefoxPattern).Distinct().ToList()));
        values.AddRange(List($@"{FirefoxKey}\WebsiteFilter\Exceptions", b.AllowedUrls.Select(ToFirefoxPattern).Distinct().ToList()));

        if (b.DisablePrivateBrowsing)
        {
            values.Add(new PolicyValue(EdgeKey, "InPrivateModeAvailability", 1)); // 1 = InPrivate mode disabled
            values.Add(new PolicyValue(ChromeKey, "IncognitoModeAvailability", 1)); // 1 = Incognito mode disabled
            values.Add(new PolicyValue(FirefoxKey, "DisablePrivateBrowsing", 1));
        }

        var parts = new List<string>();
        if (b.BlockedUrls.Count > 0)
        {
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"{b.BlockedUrls.Count} blocked website pattern(s)"));
        }

        if (b.AllowedUrls.Count > 0)
        {
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"{b.AllowedUrls.Count} always-allowed pattern(s)"));
        }

        if (b.DisablePrivateBrowsing)
        {
            parts.Add("private browsing disabled");
        }

        return new RegistryPlan(ControlState.Enforced,
            $"Applied to Microsoft Edge, Google Chrome and Mozilla Firefox: {string.Join(", ", parts)}. Browsers pick up changes within minutes or at restart. Other browsers are not restricted.",
            values);
    }

    /// <summary>Chromium-style list policy: values "1", "2", ... under the list's key.</summary>
    private static IEnumerable<PolicyValue> List(string key, IReadOnlyList<string> entries) =>
        entries.Select((entry, i) => new PolicyValue(key, (i + 1).ToString(CultureInfo.InvariantCulture), entry));

    /// <summary>
    /// Firefox uses WebExtension match patterns: "example.com" becomes "*://*.example.com/*" (the site and its
    /// subdomains) and "*" becomes "&lt;all_urls&gt;". Entries that already contain "://" get "/*" appended.
    /// </summary>
    public static string ToFirefoxPattern(string entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var e = entry.Trim();
        if (e == "*")
        {
            return "<all_urls>";
        }

        if (e.Contains("://", StringComparison.Ordinal))
        {
            return e.EndsWith('*') ? e : e.TrimEnd('/') + "/*";
        }

        var slash = e.IndexOf('/', StringComparison.Ordinal);
        var host = (slash < 0 ? e : e[..slash]).TrimStart('.');
        var path = slash < 0 ? "/" : e[slash..].TrimEnd('*');
        return $"*://*.{host}{path}*";
    }
}
