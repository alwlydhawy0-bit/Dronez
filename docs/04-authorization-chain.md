# The Authorization Chain

| | |
| --- | --- |
| **Milestone** | 1 |
| **Status** | The server runs. Layers 1–5 implemented; layer 6 **refuses** (Milestone-0 gate open). |
| **Code** | `src/mcp_server/`, `src/policy_engine/` |

Zero-Trust §4.2 states the design in one sentence: *"Model output NEVER directly authorizes an
action; it only proposes a tool call that is then validated by deterministic, non-LLM policy
code."* This document is how that sentence is implemented.

---

## 1. The chain

```
  agent / operator
        │
        ▼
 ┌──────────────────────┐
 │ 1. RATE LIMIT        │  2 proposals/s/session — counted on ATTEMPTS, not approvals
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐
 │ 2. SANITIZER         │  isolated service; screens user input AND tool results
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐
 │ 3. STRICT SCHEMA     │  closed-world, immutable, no lossy coercion
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐
 │ 4. POLICY ENGINE     │  ◄── the only load-bearing layer
 │    (OPA / Rego)      │      containment · envelope · clearance · precedence
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐
 │ 5. HUMAN CONFIRM     │  ES256 signature over the plan digest + decision;
 │                      │  single-use nonce; single-use staged plan
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐
 │ 6. DISPATCH          │  GatedDispatcher REFUSES — Milestone-0 gate open
 └──────────────────────┘
```

Served over JSON-RPC 2.0 at `POST /rpc`, TLS 1.3 enforced. Three tools are served:
`check_airspace_clearance`, `deploy_recon_waypoint`, `confirm_flight_plan`. The other four
have contracts but no handler, and are reported as method-not-found rather than advertised.

**Layers 1–3 are defence in depth that will eventually fail.** Rate limits can be evaded with
patience, injection classifiers are probabilistic, and a schema cannot tell a legitimate
polygon from a malicious one. They are worth having and they are not what the system's safety
rests on.

**Layer 4 is the one that has to hold.** A fully jailbroken agent, having defeated every layer
above, still cannot obtain an authorization, because the policy engine re-derives containment
from raw coordinates against the pre-authorized `IncidentZone` using non-LLM code and bounds
that arrive with the policy bundle rather than with the request.

> If a change ever makes a layer above the gate load-bearing, that change is a design
> regression regardless of how well it tests.

---

## 2. Layer by layer

### 2.1 Rate limiting — `guardrails/rate_limiter.py`

Two limits, deliberately separate instances so they cannot starve each other:

| Limit | Rate | Counts |
| --- | --- | --- |
| Agent tool proposals | 2/s/session | every attempt, approved or rejected |
| Hardware command dispatch | 2/s/agent | commands sent to ROS2/MAVLink |

**Counting rejected proposals is the point.** The expensive work — schema validation, the
sanitizer round trip, policy evaluation — all happens *before* a verdict exists. A limiter that
counted only approvals would leave an adversarially-driven agent free to hammer the policy
engine indefinitely, because every one of its probes gets rejected.

Sliding window on a monotonic clock: wall-clock time can jump backwards and a backwards jump
would hand out free capacity. The session table is bounded and LRU-evicted, because an
unbounded per-session structure is itself a resource-exhaustion vector.

### 2.2 Sanitizer — `guardrails/sanitizer.py`

An **isolated service**, not an in-context instruction. The module holds no agent-reachable
configuration: no bypass argument, no per-request threshold, no caller-supplied rule set. A
caller chooses *what* to screen, never *how strictly*.

Every inbound channel is screened, and there is no default channel — a caller must name one,
which is what stops tool results from quietly skipping the screen:

| Channel | Why it matters |
| --- | --- |
| `USER_INPUT` | Direct injection from a coerced or malicious authenticated user |
| `TOOL_RESULT` | An MCP tool result re-entering context |
| `RETRIEVED_DOCUMENT` | RAG / web content |
| `SENSOR_LABEL` | **Text physically placed in an incident zone**, reaching the agent via OCR or a detection label |
| `INTER_AGENT` | Another agent's output (Milestone 3+) |
| `AGENT_OUTPUT` | Scanned on the way *out* for exfiltration (threat T-12) |

Fail-closed on every path: unreachable classifier, timeout, malformed response, unparseable
verdict, oversized content. An unparseable verdict is treated as a *failure to classify* rather
than an implicit pass, because the classifier may itself have been injected by the content it
was asked to judge.

Two client adapters are provided — `LlamaGuardClient` (safe/unsafe + hazard codes) and
`GuardrailsAIClient` (validator guards). Which is deployed is an operational choice; the
fail-closed contract is not.

### 2.3 Strict schemas — `schemas/`

`StrictModel` is closed-world (`extra="forbid"`), immutable (`frozen=True`), and rejects lossy
coercion (`strict=True`) and non-finite floats (`allow_inf_nan=False`).

**Validate JSON, not dicts.** Pydantic's strict mode is stricter in Python mode than in JSON
mode: it rejects a list for a tuple and a string for an enum, which are JSON's only encodings
for those. Requests therefore go through `StrictModel.parse_json()` on the raw bytes.
Pre-parsing to a `dict` would also mean a non-strict JSON parser ran first, silently accepting
duplicate keys — a request-smuggling-shaped problem.

Guarantees that are structural rather than procedural:

- An **AI agent cannot construct a `SignedCommandEnvelope`** — the validator rejects it. Tier 3
  proposes; a human tier disposes.
- A **rejection cannot carry a partial plan**. There is no field for "mostly approved".
- An **accepted stream must declare DTLS 1.3/SRTP and edge-side frame hashing**, or it cannot
  be constructed.
- An **affirmative clearance must carry an expiry**, so it cannot be minted early and replayed.
- `NaN` never parses: `NaN > 120` is `False`, so a naive ceiling check would *pass*.

### 2.4 Policy engine — `policy_engine/`

Three structural properties make this a gate rather than a suggestion:

1. **Default deny.** `allow` is false unless every check passes, and `allow` additionally
   requires `input_complete` — checking only `count(deny) == 0` would allow an *empty* input,
   since no deny rule fires when there is nothing there to violate.
2. **No free text is read.** There is no rule that inspects a natural-language field, and the
   input builder does not put one in front of it. Urgency and justification are absent from the
   decision by construction.
3. **Bounds come from `data`, not `input`.** The safety envelope arrives with the policy bundle,
   generated from the Python module by `scripts/gen_policy_data.py`. A caller cannot widen the
   limits it is being judged against.

Two design choices worth stating explicitly:

**Geometry is evaluated in Rego, from raw coordinates.** The obvious alternative — have the
server compute containment in PostGIS and pass OPA `{"contained": true}` — is rejected, because
a gate that accepts a precomputed verdict from the component it is gating is not a gate.

**The clearance is bound to the requested volume.** The policy does not trust the `cleared`
boolean; it re-checks that the clearance is affirmative, unexpired, derived from fresh feed
data, free of blocking zones, **and that the cleared polygon contains the requested one**.
Without that last check, a clearance legitimately obtained for an empty patch of desert could
be presented against a mission over an aerodrome.

The client fails closed on everything: unreachable, timeout, non-200, oversized body, malformed
JSON, missing `result`, or an `allow` that is not literally `True`. An undefined policy path —
what OPA returns when a policy fails to load — is a denial, not an open gate.

### 2.5 Human confirmation — `tools/confirm.py`

Six checks, each closing a distinct hole:

| Check | What it stops |
| --- | --- |
| Principal is a human tier | An agent confirming its own proposal |
| Principal matches the envelope issuer | Submitting someone else's authorization |
| Signature verifies over plan digest **and** decision | Replaying an approval onto another plan, or as a rejection |
| Nonce unconsumed | Replaying the same approval twice |
| Staged plan matches the digest | A plan altered after it was reviewed |
| Plan consumed atomically, once | One approval dispatching twice |

Two orderings are load-bearing. The **nonce is consumed only after the signature verifies** —
consuming first would let an attacker burn a legitimate operator's nonce with a garbage
signature, turning verification into a denial-of-service primitive. And the **staged plan is
checked and removed under one lock**, so two concurrent confirmations cannot both succeed.

Closes `TM-14` and `TM-15`.

### 2.6 Dispatch — `dispatch.py`, and it refuses

Every gate above passes and the plan still does not reach an airframe. `GatedDispatcher`
returns `REFUSED_GATE` with the reason, the authorization is recorded with
`authorization_complete: true`, and the caller gets `dispatched: false` with a
`dispatch_gate_closed` rejection.

This is a named, tested seam rather than an absence, because a codebase where dispatch is
simply missing invites the next contributor to add a MAVLink publish wherever is convenient.
There is exactly one place to look and one place to change.

---

## 3. What is deliberately absent

| Absent | Why |
| --- | --- |
| MAVLink bridge behind the dispatch seam | Milestone-0 gate is open. This is the line the work stops at. |
| Real OIDC / JWKS identity provider | `TM-17`. `PrincipalResolver` is the seam; the principal is already server-derived. |
| Shared staging and nonce stores | `TM-18`. In-process today, so single-use does not hold across instances. |
| A Python reimplementation of the policy rules | Two implementations of an authorization decision drift, and the one that is wrong is the one nobody is looking at. `policy_engine.models` builds inputs and parses decisions; it holds no authorization logic. |
| A cache of affirmative decisions | Would be a way to get a "yes" without the policy having said so. |
| An `allow_on_error` flag | Same. |

---

## 4. Verification status

| Layer | Verified by | Status |
| --- | --- | --- |
| Rate limiter | `tests/adversarial/test_guardrails.py` | ✅ incl. a concurrency test asserting exactly 2 grants across 32 threads |
| Sanitizer | `tests/adversarial/test_guardrails.py` | ✅ every fail-closed path and every inbound channel |
| Schemas | `tests/unit/test_schemas.py` | ✅ |
| Policy **client** | `tests/policy/test_policy_engine.py` | ✅ every failure mode denies |
| Policy **Rego** | `scripts/verify_policies.sh` | ⚠️ **never executed** — see below |
| Signature + nonce | `tests/server/test_tools.py` | ✅ forged, wrong-plan, wrong-decision, unknown-key, replayed-nonce |
| Transport / TLS 1.3 | `tests/server/test_tls.py` | ✅ real handshakes; a 1.2 client is refused |
| Full request path | `tests/server/` | ✅ 51 tests over the real HTTP surface |

> ### ⚠️ `TM-13` — the Rego bundle is unverified
>
> The OPA binary could not be installed in the build environment (`openpolicyagent.org` is
> blocked by egress policy), so `opa check`, `opa fmt` and the 55 `*_test.rego` cases have
> never run. `tests/policy/test_policy_bundle.py` checks structure and cross-file consistency
> only — it does not evaluate Rego and cannot catch a semantic error.
>
> **The failure mode is an outage, not a bypass:** a policy that fails to load leaves the
> decision path undefined, which `PolicyEngine` treats as a denial. But an outage of the
> dispatch path is still an outage, and Milestone-0 criterion 6 cannot close until this runs.
>
> **To close:** run `scripts/verify_policies.sh --require-opa` where `opa` is available, and
> gate CI on it.
