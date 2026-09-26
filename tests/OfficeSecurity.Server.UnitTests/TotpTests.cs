using System.Text;
using OfficeSecurity.Server.Application.Security;

namespace OfficeSecurity.Server.UnitTests;

public sealed class TotpTests
{
    // RFC 6238 Appendix B test secret (SHA-1).
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    [InlineData(1111111111L, "050471")]
    [InlineData(1234567890L, "005924")]
    [InlineData(2000000000L, "279037")]
    public void Matches_rfc6238_test_vectors(long unixSeconds, string expected)
    {
        var step = Totp.GetTimeStep(DateTimeOffset.FromUnixTimeSeconds(unixSeconds));

        Assert.Equal(expected, Totp.ComputeCode(RfcSecret, step));
    }

    [Fact]
    public void Current_code_is_accepted_and_returns_its_step()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = Totp.GetTimeStep(now);

        Assert.Equal(step, Totp.Verify(RfcSecret, Totp.ComputeCode(RfcSecret, step), now, lastUsedTimeStep: 0));
    }

    [Fact]
    public void Code_from_one_step_ago_is_accepted_but_not_two()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = Totp.GetTimeStep(now);

        Assert.NotNull(Totp.Verify(RfcSecret, Totp.ComputeCode(RfcSecret, step - 1), now, 0));
        Assert.Null(Totp.Verify(RfcSecret, Totp.ComputeCode(RfcSecret, step - 2), now, 0));
    }

    [Fact]
    public void Already_used_code_is_rejected()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = Totp.GetTimeStep(now);

        Assert.Null(Totp.Verify(RfcSecret, Totp.ComputeCode(RfcSecret, step), now, lastUsedTimeStep: step));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("abcdef")]
    public void Malformed_codes_are_rejected(string? code) =>
        Assert.Null(Totp.Verify(RfcSecret, code, DateTimeOffset.UtcNow, 0));

    [Fact]
    public void Otpauth_uri_contains_issuer_account_and_secret()
    {
        var uri = Totp.BuildOtpAuthUri("Office Security", "admin", "JBSWY3DPEHPK3PXP");

        Assert.StartsWith("otpauth://totp/Office%20Security:admin?", uri, StringComparison.Ordinal);
        Assert.Contains("secret=JBSWY3DPEHPK3PXP", uri, StringComparison.Ordinal);
        Assert.Contains("issuer=Office%20Security", uri, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32_matches_rfc4648_vectors(string input, string expected)
    {
        Assert.Equal(expected, Base32.Encode(Encoding.ASCII.GetBytes(input)));
        Assert.Equal(input, Encoding.ASCII.GetString(Base32.Decode(expected)));
    }
}
