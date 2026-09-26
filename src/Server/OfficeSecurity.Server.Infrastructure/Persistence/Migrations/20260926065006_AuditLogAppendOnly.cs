using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OfficeSecurity.Server.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AuditLogAppendOnly : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The audit log is append-only: the database itself refuses to change or delete entries.
            // Tampering by editing the file directly is detected by the hash chain (AuditLog.VerifyAsync).
            migrationBuilder.Sql(
                "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log " +
                "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;");
            migrationBuilder.Sql(
                "CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log " +
                "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS audit_log_no_update;");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS audit_log_no_delete;");
        }
    }
}
