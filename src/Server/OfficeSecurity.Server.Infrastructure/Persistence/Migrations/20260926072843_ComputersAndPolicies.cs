using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OfficeSecurity.Server.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ComputersAndPolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ComputerId",
                table: "sessions",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "enrollment_codes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CodeHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UsedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    CreatedByAdminId = table.Column<Guid>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_enrollment_codes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "policies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    IsDefault = table.Column<bool>(type: "INTEGER", nullable: false),
                    SettingsJson = table.Column<string>(type: "TEXT", maxLength: 64000, nullable: false),
                    Revision = table.Column<int>(type: "INTEGER", nullable: false),
                    UpdatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedByAdminId = table.Column<Guid>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_policies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "computers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Hostname = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    EnrollmentCodeId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateRequestPem = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    PollTokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CertificatePem = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    CertificateThumbprint = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CertificateExpiresAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    RegisteredAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    DecidedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    DecidedByAdminId = table.Column<Guid>(type: "TEXT", nullable: true),
                    LastSeenAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    LastSeenIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    AgentVersion = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    HardwareJson = table.Column<string>(type: "TEXT", maxLength: 8000, nullable: true),
                    OsName = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    OsEdition = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    ControlStatusJson = table.Column<string>(type: "TEXT", maxLength: 16000, nullable: true),
                    FailedControls = table.Column<int>(type: "INTEGER", nullable: false),
                    HeartbeatIntervalSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    PolicyId = table.Column<Guid>(type: "TEXT", nullable: true),
                    PolicyVersion = table.Column<long>(type: "INTEGER", nullable: false),
                    AppliedPolicyVersion = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_computers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_computers_policies_PolicyId",
                        column: x => x.PolicyId,
                        principalTable: "policies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "device_inventory",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ComputerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    InstanceId = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    DeviceClass = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Manufacturer = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    IsConnected = table.Column<bool>(type: "INTEGER", nullable: false),
                    FirstSeenUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastSeenUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_device_inventory", x => x.Id);
                    table.ForeignKey(
                        name: "FK_device_inventory_computers_ComputerId",
                        column: x => x.ComputerId,
                        principalTable: "computers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "security_events",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ComputerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EventId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EventType = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Severity = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    OccurredAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ReceivedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    Details = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_events", x => x.Id);
                    table.ForeignKey(
                        name: "FK_security_events_computers_ComputerId",
                        column: x => x.ComputerId,
                        principalTable: "computers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "staff_computer_assignments",
                columns: table => new
                {
                    StaffId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ComputerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AssignedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    AssignedByAdminId = table.Column<Guid>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_staff_computer_assignments", x => new { x.StaffId, x.ComputerId });
                    table.ForeignKey(
                        name: "FK_staff_computer_assignments_computers_ComputerId",
                        column: x => x.ComputerId,
                        principalTable: "computers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_staff_computer_assignments_staff_accounts_StaffId",
                        column: x => x.StaffId,
                        principalTable: "staff_accounts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_computers_CertificateThumbprint",
                table: "computers",
                column: "CertificateThumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_computers_Hostname",
                table: "computers",
                column: "Hostname");

            migrationBuilder.CreateIndex(
                name: "IX_computers_PolicyId",
                table: "computers",
                column: "PolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_computers_Status",
                table: "computers",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_device_inventory_ComputerId_InstanceId",
                table: "device_inventory",
                columns: new[] { "ComputerId", "InstanceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_codes_CodeHash",
                table: "enrollment_codes",
                column: "CodeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_policies_Name",
                table: "policies",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_security_events_ComputerId_EventId",
                table: "security_events",
                columns: new[] { "ComputerId", "EventId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_security_events_ComputerId_OccurredAtUtc",
                table: "security_events",
                columns: new[] { "ComputerId", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_security_events_EventType_OccurredAtUtc",
                table: "security_events",
                columns: new[] { "EventType", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_staff_computer_assignments_ComputerId",
                table: "staff_computer_assignments",
                column: "ComputerId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "device_inventory");

            migrationBuilder.DropTable(
                name: "enrollment_codes");

            migrationBuilder.DropTable(
                name: "security_events");

            migrationBuilder.DropTable(
                name: "staff_computer_assignments");

            migrationBuilder.DropTable(
                name: "computers");

            migrationBuilder.DropTable(
                name: "policies");

            migrationBuilder.DropColumn(
                name: "ComputerId",
                table: "sessions");
        }
    }
}
