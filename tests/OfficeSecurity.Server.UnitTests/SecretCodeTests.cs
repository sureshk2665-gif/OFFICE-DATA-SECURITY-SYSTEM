using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Security;

namespace OfficeSecurity.Server.UnitTests;

public sealed class SecretCodeTests
{
    [Fact]
    public void Setup_code_has_readable_format_without_ambiguous_characters()
    {
        for (var i = 0; i < 200; i++)
        {
            var code = SecretCodes.NewSetupCode();
            Assert.Matches("^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$", code);
            Assert.DoesNotContain(code, c => c is 'O' or 'I' or 'L' or '0' or '1');
        }
    }

    [Fact]
    public void Setup_codes_are_unique() =>
        Assert.Equal(500, Enumerable.Range(0, 500).Select(_ => SecretCodes.NewSetupCode()).Distinct().Count());

    [Fact]
    public void Setup_code_normalization_ignores_case_spaces_and_dashes() =>
        Assert.Equal(SecretCodes.NormalizeSetupCode("K7QM-2XRP-9FTA"), SecretCodes.NormalizeSetupCode(" k7qm 2xrp 9fta "));

    [Fact]
    public void Tokens_are_long_and_url_safe()
    {
        var token = SecretCodes.NewToken();

        Assert.True(token.Length >= 43);
        Assert.Matches("^[A-Za-z0-9_-]+$", token);
    }

    [Fact]
    public void Pairing_code_format_and_matching()
    {
        var der = new byte[] { 1, 2, 3, 4, 5 };
        var code = PairingCode.Compute(der);

        Assert.Matches("^[0-9A-F]{4}(-[0-9A-F]{4}){4}$", code);
        Assert.True(PairingCode.Matches(der, code.ToLowerInvariant().Replace("-", " ", StringComparison.Ordinal)));
        Assert.False(PairingCode.Matches(new byte[] { 9, 9, 9 }, code));
        Assert.False(PairingCode.Matches(der, code[..10]));
    }
}
