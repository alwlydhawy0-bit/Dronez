# Sovereign NFZ / GACA Sync Channel

| | |
| --- | --- |
| **Milestone** | 0, exit criterion 3 |
| **Status** | Protocol, client and mock **complete**. Live sovereign endpoint **not connected** (`TM-04`). |
| **Wire contract** | `nfz-bulletin/1.0.0` |
| **Code** | `src/dronez/airspace/` |

Master Plan §2 requires the `AirspaceZone` entity to be *"synchronized in real time with local
sovereign No-Fly Zone (NFZ) databases over an encrypted sync channel"*, with every dispatch gated
by `check_airspace_clearance` against live GACA and emergency-management rules — *"not a cached
or assumed-current snapshot."*

---

## 1. The one rule

> **An affirmative clearance requires a validly signed, fresh, non-replayed bulletin that says
> the proposed volume is clear. There is no other way to obtain one.**

Everything else in this document is the mechanism behind that sentence. The adversarial suite
sweeps every injected fault and asserts that none of them produces a clearance.

---

## 2. Design posture

The feed is **authoritative for airspace policy and simultaneously untrusted as input**. Those
are not in tension: the authority decides what the restrictions are, but the bytes claiming to
carry that decision arrive over a network an adversary may reach.

| Property | Mechanism |
| --- | --- |
| Authenticity | Detached signature over canonical bytes; key resolved through a known-key registry only |
| Integrity | Signature covers the whole body **including `algorithm` and `key_id`** |
| Freshness | `nfz_max_staleness_s` (300 s) — past it the cache is not authoritative |
| Replay defence | Strictly monotonic `sequence` per authority, plus `valid_until_utc` |
| Input safety | Strict schema; undeclared fields and unknown enum values rejected outright |
| Availability failure | **Denial**, never a fallback to "probably clear" |

### 2.1 Why the signature covers `algorithm` and `key_id`

A signature that covers only the body lets an attacker rewrite the signature block. Including
`algorithm` and `key_id` in the signed bytes means a downgrade to a weaker primitive, or a
redirect to a different key, invalidates the signature it is trying to satisfy.

Independently, the `algorithm` field only ever **selects** a verifier the receiver already
trusts — it never supplies one. `none` and any unlisted value are rejected *before* a comparison
happens (Zero-Trust §1.1).

### 2.2 Why a stale cache is a denial

This is a deliberate availability-for-safety trade. If the sovereign feed is unreachable during
an incident, the platform will refuse to dispatch. That is the correct outcome: a restriction
published five minutes ago that we cannot see is exactly the restriction most likely to matter
during an active incident.

`nfz_max_staleness_s` is therefore a **safety-relevant tuning parameter, not a performance knob**,
and is subject to the Milestone-0 accountable-owner review with every other envelope constant.

### 2.3 Why `key_id` never touches a path

`key_id` is attacker-controlled text. It is used for exactly one thing: a dictionary lookup in
`SigningKeyRegistry`. It never constructs a filesystem path, URL, or database query — the
`kid`-injection defence from Zero-Trust §1.1.

---

## 3. Bulletin lifecycle

```
fetch bytes
  ├─ size cap (8 MiB)                     ─→ reject: oversized
  ├─ UTF-8 + JSON decode                  ─→ reject: malformed
  ├─ signature block present & well-formed ─→ reject: malformed
  ├─ algorithm on the allow-list           ─→ reject: not allow-listed
  ├─ algorithm implemented in this build   ─→ reject: fails closed, never skipped
  ├─ key_id in the registry                ─→ reject: unknown key
  ├─ registered algorithm matches claim    ─→ reject: algorithm substitution
  ├─ constant-time signature comparison    ─→ reject: verification failed
  ├─ STRICT SCHEMA VALIDATION              ─→ reject: schema violation
  ├─ bulletin authority == key authority   ─→ reject: cross-authority spoofing
  ├─ sequence strictly greater than last   ─→ reject: replay
  ├─ cache authority matches               ─→ reject: authority switch
  └─ not past valid_until_utc              ─→ reject: expired
         ↓
     APPLY (snapshot replaces, or delta upserts + revokes)
```

**Decoding is not trusting.** JSON parsing happens before signature verification because the
signature block has to be located — but nothing decoded is *used* until authenticity is
established, and strict schema validation runs only after that.

**A rejected bulletin leaves the cache entirely unchanged.** This is what defeats the highest-
impact attack on this channel: tampering that *removes* a restriction. The attacker's best case
is that the cache goes stale and every dispatch is denied.

---

## 4. Clearance decision order

`AirspaceClearanceService.check_clearance` — the order is part of the contract:

1. **Safety envelope** (altitude floor/ceiling), independent of feed state. A violating plan is
   denied outright, **never clipped to fit**.
2. **Feed ever synced?** No ⇒ `FEED_NEVER_SYNCED`. An empty cache means *"we do not know"*.
3. **Feed fresh?** No ⇒ `FEED_STALE`.
4. **Conflict?** Geometric **and** altitude-band overlap against every zone in force.
   Blocking ⇒ `ZONE_CONFLICT` naming the zone IDs. Advisory zones are surfaced, not blocking.
5. **Affirmative clearance** — the single path that sets `cleared=True`, expiring after
   `nfz_clearance_validity_s` (120 s) so it cannot be minted early and replayed at dispatch.

The method **does not raise**. Any unexpected exception becomes `INTERNAL_ERROR` and a denial,
because an exception escaping into the dispatch path is precisely the ambiguity Zero-Trust §0.1
requires be resolved as "deny".

---

## 5. Connecting the live endpoint (closes `TM-04`)

What is needed from the issuing authority:

1. **Endpoint URL and protocol** — poll or push. The `NfzSyncChannel` protocol supports either;
   `fetch()` returns raw bytes and must not parse, normalise, or repair them.
2. **Ed25519 public key + `key_id`**, out of band. Registered via `SigningKeyRegistry.register`
   with material loaded from Vault/KMS at runtime.
3. **mTLS client certificate** issued by the enterprise root CA.
4. **Confirmation of the canonical signing form.** `canonical_signing_bytes` defines ours: JSON
   with sorted keys, `(",", ":")` separators, `signature.value` removed. If the authority signs
   differently, this function changes — nothing else does.
5. **Bulletin cadence and `valid_until` policy**, to confirm 300 s staleness is achievable.

Then, in code:

- Implement `ed25519` verification in `AirspaceCache._verify` and add it to
  `_IMPLEMENTED_ALGORITHMS` (closes `TM-05`). Until then an `ed25519` bulletin is **rejected with
  an explicit error, never accepted unverified**.
- Implement a real `NfzSyncChannel` with mTLS, certificate-chain and hostname validation, OCSP
  stapling, and egress-proxy routing with a pinned resolved IP (closes `TM-08`, addresses T-42).
- Persist feed state and zones via `migrations/0001_airspace_zone.sql` so a restarted process
  resumes **stale**, not empty-and-optimistic.
- Move authoritative geometry to PostGIS `ST_Intersects` / `ST_IsValid` (closes `TM-06`, `TM-07`).

**The mock does not close criterion 3.** Its zone data is fictional and its signing secret inert.
The criterion closes when a real sovereign endpoint has been synced and its failure modes
exercised against the real feed.

---

## 6. The mock

`dronez.airspace.mock_client` — development and test only. Deterministic: the same construction
and fault sequence produces byte-identical bulletins, so CI failures reproduce.

```python
from dronez.airspace.mock_client import FaultMode, build_mock_channel

harness = build_mock_channel()
harness.cache.sync(harness.channel)
decision = harness.clearance.check_clearance(polygon, 30.0, 100.0)

harness.channel.fault = FaultMode.TAMPERED_BODY   # inject a fault
```

| Fault | Exercises |
| --- | --- |
| `UNREACHABLE` | Transport failure ⇒ denial (T-39) |
| `MALFORMED_JSON` | Undecodable payload |
| `OVERSIZED` | Resource-exhaustion cap (T-40) |
| `BAD_SIGNATURE` | Signature verification (T-32) |
| `TAMPERED_BODY` | **Silent removal of a blocking restriction** (T-34) |
| `UNKNOWN_KEY` | Key registry (T-32) |
| `ALGORITHM_DOWNGRADE` | Allow-list, `none` rejection (T-35) |
| `CROSS_AUTHORITY` | Authority impersonation (T-33) |
| `UNDECLARED_FIELD` | Mass assignment / envelope-widening attempt (T-37) |
| `REPLAY` | Monotonic sequence (T-36) |
| `EXPIRED` | `valid_until_utc` enforcement |

---

## 7. Open items

`TM-04` (no live endpoint — **blocks the Milestone-0 gate**), `TM-05` (`ed25519` unimplemented,
fails closed), `TM-06` / `TM-07` (planar geometry, conservative), `TM-08` (transport not
implemented). Full register: [`02-security-threat-model.md`](02-security-threat-model.md) §7.
