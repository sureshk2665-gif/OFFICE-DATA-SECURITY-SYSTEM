# ADR-0002: Central database — SQLite (single-writer server) by default, PostgreSQL supported later

- Status: Accepted (2026-09-26). Supersedes the "PostgreSQL" row of the plan's technology table.

## Context

The plan recommended PostgreSQL. The owner is not a developer and wants a simple `.exe` install.
Installing, securing, patching and backing up a separate PostgreSQL service is a significant burden for a
small office without IT staff.

The specification warns against using "a local SQLite database as the central database for multiple
computers without evaluating concurrency and reliability requirements". That warning is about many
computers opening one database file over a network share. Here, that never happens.

## Evaluation

- **Only one process opens the database: the central server.** Agents, dashboards and staff apps talk
  to the server through the HTTPS API only. No client ever touches the database file.
- SQLite in **WAL mode** handles one writer and many concurrent readers inside a single process.
  Expected load: up to ~100 PCs with a heartbeat every 60 s (~2 writes/s) plus event batches. That is
  well within single-writer SQLite throughput. Writes are serialised through EF Core with short
  transactions.
- **Reliability:** SQLite is ACID. The database file stays on the server's local NTFS disk, never on a
  network share. Online backups use the SQLite backup API, scheduled by the server itself.
- **Access control:** SQLite has no database roles. Append-only audit is enforced by
  `BEFORE UPDATE/DELETE` triggers that raise errors, plus a SHA-256 hash chain that detects any direct
  file edit. The file's NTFS ACL allows only the server's service account and Administrators.
- **Encryption at rest:** BitLocker on the server PC (recommended in the deployment guide).

## Decision

- Default provider: **SQLite** (Microsoft.Data.Sqlite via EF Core), WAL mode, local disk only.
- Keep all data access behind EF Core with provider-neutral code. **PostgreSQL** becomes an optional
  provider (separate migrations assembly) if the office grows past ~100 PCs or needs a separate DB host.

## Consequences

- One-click server install with no extra database software.
- Horizontal scaling (multiple server instances) is not supported with SQLite. This is acceptable for
  the target size.
