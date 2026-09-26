using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OfficeSecurity.Server.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "account_setup_codes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AccountType = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    AccountId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CodeHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UsedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    RevokedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    CreatedByAdminId = table.Column<Guid>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_account_setup_codes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "admin_accounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Username = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    NormalizedUsername = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Role = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    PasswordHash = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    TotpSecretProtected = table.Column<byte[]>(type: "BLOB", maxLength: 1024, nullable: true),
                    MfaEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    LastTotpTimeStep = table.Column<long>(type: "INTEGER", nullable: false),
                    FailedLoginCount = table.Column<int>(type: "INTEGER", nullable: false),
                    LockedUntilUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastLoginAtUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_admin_accounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "audit_log",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    OccurredAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ActorType = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    ActorId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ActorName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Action = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Outcome = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    TargetType = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    TargetId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Details = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    PreviousHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_log", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "sessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    PrincipalType = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    PrincipalId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastSeenAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    EndedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    EndReason = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_sessions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "staff_accounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    EmployeeCode = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    NormalizedEmployeeCode = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Department = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    PasswordHash = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    FailedLoginCount = table.Column<int>(type: "INTEGER", nullable: false),
                    LockedUntilUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastLoginAtUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_staff_accounts", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_account_setup_codes_AccountType_AccountId",
                table: "account_setup_codes",
                columns: new[] { "AccountType", "AccountId" });

            migrationBuilder.CreateIndex(
                name: "IX_account_setup_codes_CodeHash",
                table: "account_setup_codes",
                column: "CodeHash");

            migrationBuilder.CreateIndex(
                name: "IX_admin_accounts_NormalizedUsername",
                table: "admin_accounts",
                column: "NormalizedUsername",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_Action",
                table: "audit_log",
                column: "Action");

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_OccurredAtUtc",
                table: "audit_log",
                column: "OccurredAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_sessions_PrincipalType_PrincipalId",
                table: "sessions",
                columns: new[] { "PrincipalType", "PrincipalId" });

            migrationBuilder.CreateIndex(
                name: "IX_sessions_TokenHash",
                table: "sessions",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_staff_accounts_DisplayName",
                table: "staff_accounts",
                column: "DisplayName");

            migrationBuilder.CreateIndex(
                name: "IX_staff_accounts_NormalizedEmployeeCode",
                table: "staff_accounts",
                column: "NormalizedEmployeeCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_staff_accounts_Status",
                table: "staff_accounts",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "account_setup_codes");

            migrationBuilder.DropTable(
                name: "admin_accounts");

            migrationBuilder.DropTable(
                name: "audit_log");

            migrationBuilder.DropTable(
                name: "sessions");

            migrationBuilder.DropTable(
                name: "staff_accounts");
        }
    }
}
