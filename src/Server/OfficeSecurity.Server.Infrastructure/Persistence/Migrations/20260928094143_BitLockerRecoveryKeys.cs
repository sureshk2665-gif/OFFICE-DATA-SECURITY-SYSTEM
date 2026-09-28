using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OfficeSecurity.Server.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class BitLockerRecoveryKeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "bitlocker_recovery_keys",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ComputerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Drive = table.Column<string>(type: "TEXT", maxLength: 8, nullable: false),
                    ProtectorId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ProtectedPassword = table.Column<byte[]>(type: "BLOB", nullable: false),
                    FirstReportedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastReportedUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_bitlocker_recovery_keys", x => x.Id);
                    table.ForeignKey(
                        name: "FK_bitlocker_recovery_keys_computers_ComputerId",
                        column: x => x.ComputerId,
                        principalTable: "computers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_bitlocker_recovery_keys_ComputerId_ProtectorId",
                table: "bitlocker_recovery_keys",
                columns: new[] { "ComputerId", "ProtectorId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "bitlocker_recovery_keys");
        }
    }
}
