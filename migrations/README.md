# Migrations

PostgreSQL 14+ with PostGIS 3.x. Applied in filename order; each file is a single
transaction and is never edited after it has been applied anywhere.

| File | Adds | Milestone |
| --- | --- | --- |
| `0001_airspace_zone.sql` | `airspace_zone`, `nfz_feed_state`, `nfz_bulletin_audit` | 0 |

## Not here yet, and why

`IncidentZone` — the root authorization envelope every mission is checked against — is
**open as `TM-01`** and blocks the Milestone-0 gate. It is deliberately absent rather than
sketched, because code that depends on an unreviewed shape is harder to correct than code
that does not exist.

Mission, command, and flight-plan tables are Milestone 1. Master Plan §6 forbids
flight-capable code before the Milestone-0 gate closes.

## Conventions

- **Constraints are security controls.** Altitude ordering, sequence monotonicity and
  geometry validity are enforced at the storage boundary as well as in application code.
  A direct database write must not be able to create state the application would reject.
- **Row-Level Security** is applied to every tenant-scoped table from Milestone 1
  (Zero-Trust §2.1), using session variables set by the trusted backend.
- **Privileges live in Terraform**, not in migrations, so they are version-controlled
  infrastructure rather than a manual change (Zero-Trust §6.1).
