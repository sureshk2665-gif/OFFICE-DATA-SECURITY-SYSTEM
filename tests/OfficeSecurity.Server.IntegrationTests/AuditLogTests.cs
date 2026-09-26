using System.Net.Http.Json;
using Microsoft.Data.Sqlite;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class AuditLogTests
{
    [Fact]
    public async Task Security_actions_are_recorded_without_secrets()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var anonymous = server.Client();
        var code = await (await admin.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest("EMP500", "Audit Person", null)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SetupCodeResponse>();
        await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP500", "Typed wrong password"));

        var entries = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"{ApiRoutes.Audit}?pageSize=200");
        var actions = entries!.Items.Select(e => e.Action).ToList();

        Assert.Contains("setup.first-admin", actions);
        Assert.Contains("auth.admin.mfa-enroll", actions);
        Assert.Contains("auth.admin.login", actions);
        Assert.Contains("staff.create", actions);
        Assert.Contains(entries.Items, e => e.Action == "auth.staff.login" && e.Outcome == "Failure");

        var everything = string.Join('\n', entries.Items.Select(e => $"{e.ActorName} {e.TargetId} {e.Details}"));
        Assert.DoesNotContain(ServerFactory.AdminPassword, everything, StringComparison.Ordinal);
        Assert.DoesNotContain("Typed wrong password", everything, StringComparison.Ordinal);
        Assert.DoesNotContain(code!.SetupCode, everything, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Passwords_and_codes_are_never_stored_in_plain_text()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        var code = await (await admin.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest("EMP501", "Plain Text Check", null)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SetupCodeResponse>();

        var wal = server.DatabaseFile + "-wal";
        var all = await ReadSharedAsync(server.DatabaseFile) + (File.Exists(wal) ? await ReadSharedAsync(wal) : string.Empty);

        Assert.DoesNotContain(ServerFactory.AdminPassword, all, StringComparison.Ordinal);
        Assert.DoesNotContain(code!.SetupCode, all, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretCodesNormalized(code.SetupCode), all, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Database_refuses_to_update_or_delete_audit_entries()
    {
        await using var server = new ServerFactory();
        await server.OwnerTokenAsync();

        await using var connection = new SqliteConnection($"Data Source={server.DatabaseFile}");
        await connection.OpenAsync();
        await using var update = connection.CreateCommand();
        update.CommandText = "UPDATE audit_log SET Details = 'changed' WHERE Id = 1";
        await using var delete = connection.CreateCommand();
        delete.CommandText = "DELETE FROM audit_log WHERE Id = 1";

        Assert.Contains("append-only", (await Assert.ThrowsAsync<SqliteException>(() => update.ExecuteNonQueryAsync())).Message, StringComparison.Ordinal);
        Assert.Contains("append-only", (await Assert.ThrowsAsync<SqliteException>(() => delete.ExecuteNonQueryAsync())).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Direct_tampering_is_detected_by_chain_verification()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);

        var before = await admin.GetFromJsonAsync<AuditVerificationResponse>(ApiRoutes.AuditVerify);
        Assert.True(before!.IsIntact, before.Message);
        Assert.True(before.EntriesChecked >= 3);

        // Simulate an attacker with direct file access who removes the protection and edits a record.
        await using (var connection = new SqliteConnection($"Data Source={server.DatabaseFile}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "DROP TRIGGER audit_log_no_update; UPDATE audit_log SET ActorName = 'someone-else' WHERE Id = 2;";
            await command.ExecuteNonQueryAsync();
        }

        var after = await admin.GetFromJsonAsync<AuditVerificationResponse>(ApiRoutes.AuditVerify);
        Assert.False(after!.IsIntact);
        Assert.Equal(2, after.FirstBrokenEntryId);
    }

    // The server keeps the database open; Windows requires sharing read/write access to read it alongside.
    private static async Task<string> ReadSharedAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    private static string SecretCodesNormalized(string code) => code.Replace("-", string.Empty, StringComparison.Ordinal);
}
