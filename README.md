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

## ⚠️ Status: Milestone-0 gate open. Nothing here actuates hardware.

**No flight-capable code may be written until the Milestone-0 gate closes.** Read
**[`CLAUDE.md`](CLAUDE.md) §2** before writing anything — it lists exactly what is permitted.

The Milestone-1 layers built so far are validation and authorization only: a proposal can be
validated and authorized, and then it goes nowhere. There is no dispatcher.

| # | Milestone-0 criterion | State |
| --- | --- | --- |
| 1 | STRIDE threat model, agent→MCP→hardware | Drafted, pending review |
| 2 | Safety-envelope constants reviewed by a named owner | **Open** |
| 3 | Sovereign NFZ sync channel established and tested | Protocol + client + mock done; **live endpoint not connected** |
| 4 | `IncidentZone` / `AirspaceZone` model finalized | Both implemented; pending review |
| 5 | GACA registration and spectrum licensing initiated | **Open** |
| 6 | Policy-engine schema defined | Implemented; **never executed** — `opa` unavailable (`TM-13`) |

## What exists today

**Milestone 0 — foundations**

- **Safety envelope** — 25 constants, each recording *where it is actually enforced* (firmware /
  companion / server) and why. A kinetic bound enforced only at the server fails the build. The
  envelope is digest-pinned to `CLAUDE.md` so a constant cannot be quietly relaxed.
- **Sovereign NFZ / GACA sync channel** — signed, sequenced, freshness-bounded bulletins with a
  strict stdlib-only parser; a clearance service that cannot raise and cannot return an
  authorization on any error path; and a mock channel with 11 injectable faults.
- **STRIDE threat model** — 52 threats across 8 trust boundaries, with deep dives on prompt
  injection, command hijacking and GPS spoofing, and a matrix mapping threats to real tests.

**Milestone 1 — validation and authorization**

- **Strict MCP tool schemas** — all 7 tools, closed-world and immutable, with bounds derived
  from the safety envelope rather than repeated as literals. An AI agent structurally cannot
  construct a signed command envelope, and a rejection cannot carry a partial flight plan.
- **`IncidentZone`** — the root authorization envelope: narrows the platform envelope but can
  never widen it, is always time-boxed, and can only be declared by the command room.
- **Guardrails** — an isolated prompt sanitizer (Llama Guard / Guardrails AI client patterns)
  that screens *tool results and sensor labels as well as user input*, fails closed on every
  error path, and scans agent output for exfiltration; plus a hard 2 proposals/second limit
  that counts rejected proposals too.
- **Deterministic policy engine** — Rego enforcing polygon-in-polygon containment against the
  incident zone, altitude/velocity bounding, and sovereign clearance validation bound to the
  requested volume. The client denies on every failure: no response, no answer, no allow.

> **Known gap (`TM-13`):** the Rego has never been executed — the OPA binary is blocked by
> egress policy in the build environment. It is verified structurally by
> `tests/policy/test_policy_bundle.py` only. Run `scripts/verify_policies.sh --require-opa`
> where `opa` is available; CI must gate on it.

## Documentation

| Document | What it is |
| --- | --- |
| **[`CLAUDE.md`](CLAUDE.md)** | **Project memory. Read first.** Identity, Zero-Trust rules, safety envelope, tool schemas, open items, exception log |
| [`docs/02-security-threat-model.md`](docs/02-security-threat-model.md) | STRIDE model for the full chain |
| [`docs/03-nfz-gaca-sync-channel.md`](docs/03-nfz-gaca-sync-channel.md) | NFZ channel design and how to connect the live endpoint |
| [`docs/04-authorization-chain.md`](docs/04-authorization-chain.md) | The Milestone-1 validation and authorization chain, layer by layer |

## Development

Milestone-0 runtime code is **stdlib-only** — the smallest possible supply-chain surface, and it
lets the schema and clearance logic be fuzzed as pure functions.

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest tests               # 244 tests
python3 scripts/verify_milestone0.py  # gate invariants + criteria status
scripts/verify_policies.sh            # opa check --strict + opa fmt + opa test
```

`dronez` stays stdlib-only so the envelope and clearance logic remain fuzzable as pure
functions. Milestone 1 adds one runtime dependency (`pydantic`); the authorization path adds
none.

Governed by the **Zero-Trust Adversarial Security, Hardening & Hardened Defense Master Standard
v3.0-ULTRA**. Its §11.1 release gates apply to every deployment.
