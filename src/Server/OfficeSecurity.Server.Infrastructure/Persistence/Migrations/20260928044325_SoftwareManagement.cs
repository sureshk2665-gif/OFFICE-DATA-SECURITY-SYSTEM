using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OfficeSecurity.Server.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SoftwareManagement : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "approved_software",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Publisher = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    Notes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedByAdminId = table.Column<Guid>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_approved_software", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "software_inventory",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ComputerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Publisher = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    InstallDate = table.Column<DateOnly>(type: "TEXT", nullable: true),
                    Scope = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    IsPresent = table.Column<bool>(type: "INTEGER", nullable: false),
                    FirstSeenUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastSeenUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_software_inventory", x => x.Id);
                    table.ForeignKey(
                        name: "FK_software_inventory_computers_ComputerId",
                        column: x => x.ComputerId,
                        principalTable: "computers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "software_requests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    StaffId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ComputerId = table.Column<Guid>(type: "TEXT", nullable: true),
                    SoftwareName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    ReviewNote = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    ReviewedByAdminId = table.Column<Guid>(type: "TEXT", nullable: true),
                    DeploymentJobId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    DecidedAtUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_software_requests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_software_requests_staff_accounts_StaffId",
                        column: x => x.StaffId,
                        principalTable: "staff_accounts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "software_packages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ApprovedSoftwareId = table.Column<Guid>(type: "TEXT", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
                    Sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    SizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    InstallerType = table.Column<string>(type: "TEXT", maxLength: 8, nullable: false),
                    SilentArguments = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    SignerSubject = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    AllowUnsigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    UploadedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UploadedByAdminId = table.Column<Guid>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_software_packages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_software_packages_approved_software_ApprovedSoftwareId",
                        column: x => x.ApprovedSoftwareId,
                        principalTable: "approved_software",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "deployment_jobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    PackageId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ComputerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RequestId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    ExitCode = table.Column<int>(type: "INTEGER", nullable: true),
                    Message = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedByAdminId = table.Column<Guid>(type: "TEXT", nullable: false),
                    StartedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    FinishedAtUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_deployment_jobs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_deployment_jobs_computers_ComputerId",
                        column: x => x.ComputerId,
                        principalTable: "computers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_deployment_jobs_software_packages_PackageId",
                        column: x => x.PackageId,
                        principalTable: "software_packages",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_approved_software_Name",
                table: "approved_software",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_deployment_jobs_ComputerId_Status",
                table: "deployment_jobs",
                columns: new[] { "ComputerId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_deployment_jobs_PackageId",
                table: "deployment_jobs",
                column: "PackageId");

            migrationBuilder.CreateIndex(
                name: "IX_software_inventory_ComputerId_Name_Version_Scope",
                table: "software_inventory",
                columns: new[] { "ComputerId", "Name", "Version", "Scope" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_software_inventory_Name",
                table: "software_inventory",
                column: "Name");

            migrationBuilder.CreateIndex(
                name: "IX_software_packages_ApprovedSoftwareId",
                table: "software_packages",
                column: "ApprovedSoftwareId");

            migrationBuilder.CreateIndex(
                name: "IX_software_requests_StaffId",
                table: "software_requests",
                column: "StaffId");

            migrationBuilder.CreateIndex(
                name: "IX_software_requests_Status_CreatedAtUtc",
                table: "software_requests",
                columns: new[] { "Status", "CreatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "deployment_jobs");

            migrationBuilder.DropTable(
                name: "software_inventory");

            migrationBuilder.DropTable(
                name: "software_requests");

            migrationBuilder.DropTable(
                name: "software_packages");

            migrationBuilder.DropTable(
                name: "approved_software");
        }
    }
}
