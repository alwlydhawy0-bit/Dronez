# Tactical Drone Swarm & Recon MCP Server

A high-assurance **Model Context Protocol** server for tactical reconnaissance. Command-room
operators and field leaders express intent in natural language; an AI agent turns it into a
*proposal*; a deterministic policy engine validates it; a human authorizes it; only then is
anything dispatched to an airframe.

> **The agent proposes. A policy engine and a human dispose. The airframe's own firmware — not
> this server — is the final enforcer of physical safety.**

**Reconnaissance only.** No tool in this system accepts, validates, or dispatches a
payload-release or offensive-action command, at any phase. This is asserted against the source
tree by a test, not merely documented.

---

## ⚠️ Status: Milestone 0 (pre-engineering). The gate is open.

**No flight-capable code may be written until the Milestone-0 gate closes.** Four of six exit
criteria remain open. Read **[`CLAUDE.md`](CLAUDE.md) §2** before writing anything — it lists
exactly what is permitted right now.

| # | Milestone-0 criterion | State |
| --- | --- | --- |
| 1 | STRIDE threat model, agent→MCP→hardware | Drafted, pending review |
| 2 | Safety-envelope constants reviewed by a named owner | **Open** |
| 3 | Sovereign NFZ sync channel established and tested | Protocol + client + mock done; **live endpoint not connected** |
| 4 | `IncidentZone` / `AirspaceZone` model finalized | `AirspaceZone` done; `IncidentZone` **open** |
| 5 | GACA registration and spectrum licensing initiated | **Open** |
| 6 | Policy-engine schema defined | **Open** |

## What exists today

- **Safety envelope** — 25 constants, each recording *where it is actually enforced* (firmware /
  companion / server) and why. A kinetic bound enforced only at the server fails the build. The
  envelope is digest-pinned to `CLAUDE.md` so a constant cannot be quietly relaxed.
- **Sovereign NFZ / GACA sync channel** — signed, sequenced, freshness-bounded bulletins with a
  strict stdlib-only parser; a clearance service that cannot raise and cannot return an
  authorization on any error path; and a mock channel with 11 injectable faults.
- **STRIDE threat model** — 52 threats across 8 trust boundaries, with deep dives on prompt
  injection, command hijacking and GPS spoofing, and a matrix mapping threats to real tests.

## Documentation

| Document | What it is |
| --- | --- |
| **[`CLAUDE.md`](CLAUDE.md)** | **Project memory. Read first.** Identity, Zero-Trust rules, safety envelope, tool schemas, open items, exception log |
| [`docs/02-security-threat-model.md`](docs/02-security-threat-model.md) | STRIDE model for the full chain |
| [`docs/03-nfz-gaca-sync-channel.md`](docs/03-nfz-gaca-sync-channel.md) | NFZ channel design and how to connect the live endpoint |

## Development

Milestone-0 runtime code is **stdlib-only** — the smallest possible supply-chain surface, and it
lets the schema and clearance logic be fuzzed as pure functions.

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest tests -q          # 71 tests
python3 scripts/verify_milestone0.py # gate checks + envelope digest
```

Governed by the **Zero-Trust Adversarial Security, Hardening & Hardened Defense Master Standard
v3.0-ULTRA**. Its §11.1 release gates apply to every deployment.
