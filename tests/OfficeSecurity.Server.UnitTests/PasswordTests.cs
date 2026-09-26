using OfficeSecurity.Server.Application.Security;

namespace OfficeSecurity.Server.UnitTests;

public sealed class PasswordTests
{
    private readonly PasswordHasher _hasher = new(iterations: 1_000);

    [Fact]
    public void Correct_password_verifies_and_hash_does_not_contain_it()
    {
        var hash = _hasher.Hash("Correct horse battery 42");

        Assert.True(_hasher.Verify("Correct horse battery 42", hash));
        Assert.DoesNotContain("Correct horse", hash, StringComparison.Ordinal);
        Assert.StartsWith("pbkdf2-sha512$1000$", hash, StringComparison.Ordinal);
    }

    [Fact]
    public void Wrong_password_fails() =>
        Assert.False(_hasher.Verify("wrong password!", _hasher.Hash("Correct horse battery 42")));

    [Fact]
    public void Same_password_gets_different_salts() =>
        Assert.NotEqual(_hasher.Hash("Correct horse battery 42"), _hasher.Hash("Correct horse battery 42"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("pbkdf2-sha512$abc$AAAA$AAAA")]
    [InlineData("pbkdf2-sha512$1000$not-base64$AAAA")]
    public void Missing_or_malformed_hash_fails(string? stored) =>
        Assert.False(_hasher.Verify("anything at all", stored));

    [Fact]
    public void Default_iterations_meet_owasp_recommendation() =>
        Assert.True(PasswordHasher.DefaultIterations >= 210_000);

    [Fact]
    public void Hash_with_fewer_iterations_needs_rehash()
    {
        var weak = new PasswordHasher(500).Hash("Correct horse battery 42");

        Assert.True(_hasher.NeedsRehash(weak));
        Assert.False(_hasher.NeedsRehash(_hasher.Hash("Correct horse battery 42")));
    }

    [Theory]
    [InlineData("short", false)]
    [InlineData("password1234", false)]
    [InlineData("aaaaaaaaaaaaaaaa", false)]
    [InlineData("xx-suresh-2026-xx", false)]
    [InlineData("Blue tractor at noon", true)]
    [InlineData("r7!Kp2#vQ9mZ", true)]
    public void Password_policy(string password, bool acceptable) =>
        Assert.Equal(acceptable, PasswordPolicy.Validate(password, "suresh") is null);
}
