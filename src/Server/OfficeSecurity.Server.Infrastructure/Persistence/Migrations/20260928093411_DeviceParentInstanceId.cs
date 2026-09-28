using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OfficeSecurity.Server.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DeviceParentInstanceId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ParentInstanceId",
                table: "device_inventory",
                type: "TEXT",
                maxLength: 400,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ParentInstanceId",
                table: "device_inventory");
        }
    }
}
