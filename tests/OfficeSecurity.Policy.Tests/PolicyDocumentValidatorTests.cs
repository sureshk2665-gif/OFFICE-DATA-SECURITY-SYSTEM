using OfficeSecurity.Contracts;

namespace OfficeSecurity.Policy.Tests;

public sealed class PolicyDocumentValidatorTests
{
    private static SecurityPolicyDocument Valid() => new()
    {
        Version = 1,
        ComputerId = Guid.NewGuid(),
        IssuedAtUtc = DateTimeOffset.UtcNow,
    };

    [Fact]
    public void Default_policy_is_valid() => Assert.Empty(PolicyDocumentValidator.Validate(Valid()));

    [Fact]
    public void Empty_computer_id_is_invalid() =>
        Assert.NotEmpty(PolicyDocumentValidator.Validate(Valid() with { ComputerId = Guid.Empty }));

    [Theory]
    [InlineData("not-a-hash")]
    [InlineData("ZZ00000000000000000000000000000000000000000000000000000000000000")]
    public void Bad_file_hash_is_invalid(string hash) =>
        Assert.NotEmpty(PolicyDocumentValidator.Validate(Valid() with
        {
            ApplicationControl = new ApplicationControlSettings { AllowedFileHashes = [hash] },
        }));

    [Theory]
    [InlineData(@"C:\Company")]
    [InlineData(@"\\fileserver\company")]
    public void Absolute_folder_paths_are_valid(string path) =>
        Assert.Empty(PolicyDocumentValidator.Validate(Valid() with
        {
            FileProtection = new FileProtectionSettings { ProtectedFolders = [new ProtectedFolder(path, true, false)] },
        }));

    [Theory]
    [InlineData("Company")]
    [InlineData(@"..\Company")]
    [InlineData("")]
    public void Relative_folder_paths_are_invalid(string path) =>
        Assert.NotEmpty(PolicyDocumentValidator.Validate(Valid() with
        {
            FileProtection = new FileProtectionSettings { ProtectedFolders = [new ProtectedFolder(path, true, false)] },
        }));

    [Fact]
    public void Exception_must_expire_after_start()
    {
        var now = DateTimeOffset.UtcNow;
        var policy = Valid() with
        {
            Exceptions = [new PolicyExemption(Guid.NewGuid(), SecurityControl.RemovableStorage, "Audit transfer", now, now)],
        };

        Assert.NotEmpty(PolicyDocumentValidator.Validate(policy));
    }

    [Fact]
    public void Exception_is_active_only_inside_its_window()
    {
        var start = new DateTimeOffset(2026, 9, 26, 9, 0, 0, TimeSpan.Zero);
        var exception = new PolicyExemption(Guid.NewGuid(), SecurityControl.RemovableStorage, "Audit transfer", start, start.AddHours(2));

        Assert.False(exception.IsActiveAt(start.AddMinutes(-1)));
        Assert.True(exception.IsActiveAt(start));
        Assert.True(exception.IsActiveAt(start.AddHours(1)));
        Assert.False(exception.IsActiveAt(start.AddHours(2)));
    }
}
