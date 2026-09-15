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

## ⚠️ Status: the server runs, and nothing reaches hardware.

**No flight-capable code may be written until the Milestone-0 gate closes.** Read
**[`CLAUDE.md`](CLAUDE.md) §2** before writing anything — it lists exactly what is permitted.

The MCP server is complete through the human authorization gate. A proposal is
schema-validated, airspace-cleared against the live sovereign feed, policy-authorized,
and human-confirmed with a verified hardware-bound signature — and then
[`dispatch.py`](src/mcp_server/dispatch.py) **refuses**, because the gate is open. That
refusal is the boundary of this milestone, and a test asserts it.

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

**Milestone 1 — the server**

- **FastAPI MCP server** over JSON-RPC 2.0 at `POST /rpc`, TLS 1.3 enforced (verified by real
  handshakes — a TLS 1.2 client is refused). Security headers, host allow-list, body caps, and
  an append-only audit record for *every* attempt including the rejected ones.
- **`check_airspace_clearance`** — refreshes the live NFZ/GACA feed before deciding, so the
  answer reflects the feed at decision time. Stale or unreachable ⇒ denial, never a fallback
  to the last known picture.
- **`deploy_recon_waypoint`** — obtains its own clearance (a caller cannot supply one), then
  the OPA gate, then stages a digest-addressed plan. Never dispatches.
- **`confirm_flight_plan`** — the server-enforced human gate: ES256 signature over the plan
  digest *and* the decision, bound to the operator's FIDO2 credential, with single-use nonces
  and single-use plans. Closes `TM-14` and `TM-15`.

**Milestone 2 — the evidentiary pipeline**

- **Edge frame hashing** (`edge_node/frame_hasher.py`) — every frame hashed on the Jetson
  *before* transmission and chained to its predecessor, so deletion and reordering are
  detectable and not just modification. Chain heads are sealed periodically by the secure
  element: one asymmetric operation per segment rather than per frame, because signing at
  video rate is not possible.
- **WORM chain of custody** (`dronez/evidence/`) — `ChainOfCustodyRecord` with a store that
  has **no delete method and no update method**. Not a refusal — an absence.
- **DTLS/SRTP enforcement** (`mcp_server/media/webrtc.py`) — SDES, SHA-1 fingerprints,
  plaintext profiles and missing ICE are all rejected at the signaling layer, before a
  session is allocated. The DTLS *version* floor is enforced in the media engine, because
  SDP cannot carry it — the split is documented rather than faked.
- **Graceful degradation** (`edge_node/degradation.py`) — video sheds before detection,
  always. `DETECTION_ONLY` is the floor and still tells the command room what is in the
  building. Archival is unconditional: evidence is preserved whether or not anyone is
  watching.

> **Known gap (`TM-21`):** the privacy **redaction** pipeline is not built. Master Plan §2
> requires blur/redaction before footage leaves the tactical boundary, and §6 requires
> compliance sign-off on it first. Footage must not leave that boundary until it exists.

**Milestone 1 — command signing and precedence**

- **Non-repudiation command signing** (`ros2_bridge/mavlink_signer.py`) — short-lived
  ECDSA/RSA operator tokens bound to a FIDO2 credential, plus MAVLink2 message signing with a
  monotonic replay guard. The two are bound: a frame cannot be signed without a verified
  authorization naming that exact command. No transport — the module opens no socket.
- **Role Precedence Matrix** — Tier 1 > Tier 2 > Tier 3, defined once and mirrored in Rego with
  a drift test comparing the two tables. A Tier-3 attempt to supersede any command is rejected
  *and* raised as a P1 security violation; a Tier-2-over-Tier-1 attempt is an ordinary refusal,
  because classifying both the same way buries the signal that matters.

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

**Milestones 3 & 4 — fleet management and the emergency safety paths**

- **`get_fleet_status`** — read-only, zone-scoped, and never a dispatch gate. Availability is
  *computed* from state, battery, grounding and telemetry age, not echoed from a field: a
  record older than 30 s is not authoritative, because its battery and position are guesses.
  An agent sees availability; queue depth and preemption candidates stay with the command room.
- **Priority-queue arbitration** (`fleet_manager/scheduler.py`) — ordered by incident priority,
  then role tier, then arrival, then a monotonic admission counter so two requests in the same
  clock tick still order deterministically. It distinguishes *"wait"* from *"call someone
  else"*: queueing a request no airframe could ever serve tells an operator to wait for
  something that will never happen, during an incident. **Preemption is advisory** — the
  scheduler assembles the context and recalls nothing, because choosing between two live
  incidents is a human judgement.
- **Telemetry is untrusted input** — a reported transition the airframe cannot physically make
  is rejected and counted, and the *stale* record is kept. That record then fails the freshness
  check and stops dispatch on its own; believing the impossible state would not.
- **`request_emergency_stop`** — signed, zone-bound, single-use, and broadcast over a channel
  asserted independent of the dispatcher at composition time. Deliberately **not** policy-gated:
  fail-closed means denying *authority*, not denying *safety*, and an unreachable policy engine
  must not be able to prevent a stop. Delivery is reported as `delivered` / `undelivered` /
  `complete` rather than a boolean, because an operator whose stop reached three of four
  airframes needs to know which one it missed.
- **`DEGRADED_VISUAL_INERTIAL_LANDING`** — specified in full
  ([`docs/07-degraded-landing-firmware-spec.md`](docs/07-degraded-landing-firmware-spec.md)),
  including 18 HIL acceptance cases. What this repository *implements* is the negative
  capability: `GROUND_COMMANDABLE` in `dronez/safety/states.py` is an allow-list in which no
  pair touches a fail-safe state in either direction, asserted across the full state
  cross-product. The server has no vocabulary to command entry into a fail-safe, or exit from
  one. Every state remains observable — blinding the command room during the event they most
  need to understand would be its own safety failure.

> **Known gaps (`TM-26`, `TM-27`):** the emergency-stop channel's independence is checked
> structurally (same object, shared transport) and the default is an in-memory development
> channel — real RF independence is a deployment property to verify on the rig. And all 18
> DVIL HIL cases are unexecuted, for want of that rig (`TM-12`); the descent-rate and
> obstacle-clearance constants remain engineering defaults until they run.

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
| [`docs/04-authorization-chain.md`](docs/04-authorization-chain.md) | The authorization chain, layer by layer, and where dispatch stops |
| [`docs/05-command-signing-and-precedence.md`](docs/05-command-signing-and-precedence.md) | Non-repudiation signing, MAVLink2 message signing, and the Role Precedence Matrix |
| [`docs/06-evidentiary-pipeline.md`](docs/06-evidentiary-pipeline.md) | Edge frame hashing, the WORM chain of custody, DTLS/SRTP, and degradation |
| [`docs/07-degraded-landing-firmware-spec.md`](docs/07-degraded-landing-firmware-spec.md) | The firmware-resident dual-failure landing state, and the HIL criteria that accept an implementation of it |

## Development

Milestone-0 runtime code is **stdlib-only** — the smallest possible supply-chain surface, and it
lets the schema and clearance logic be fuzzed as pure functions.

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest tests               # 880 tests
python3 scripts/verify_milestone0.py  # gate invariants + criteria status
scripts/verify_policies.sh            # opa check --strict + opa fmt + opa test
```

`dronez` stays stdlib-only so the envelope and clearance logic remain fuzzable as pure
functions. Milestone 1 adds one runtime dependency (`pydantic`); the authorization path adds
none.

Governed by the **Zero-Trust Adversarial Security, Hardening & Hardened Defense Master Standard
v3.0-ULTRA**. Its §11.1 release gates apply to every deployment.
