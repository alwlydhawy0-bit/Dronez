# Command Signing & Role Precedence

| | |
| --- | --- |
| **Milestone** | 1 |
| **Status** | Implemented. Key *lifecycle* is not (`TM-19`). |
| **Code** | `src/dronez/authz/`, `src/dronez/crypto/`, `src/ros2_bridge/mavlink_signer.py`, `src/policy_engine/policies/override.rego` |

---

## 1. Two signatures, two different jobs

A command that reaches an airframe carries two independent cryptographic claims. They are
often conflated, and conflating them loses one of them.

| | Operator command token | MAVLink2 message signing |
| --- | --- | --- |
| Proves | *a named human authorized this* | *these bytes are intact and came from the bridge* |
| Primitive | ECDSA/RSA, asymmetric | SHA-256 over a shared per-link secret |
| Bound to | a FIDO2/WebAuthn authenticator | a link, a system, a component |
| Survives | compromise of the bridge | an RF-adjacent attacker |
| Non-repudiation | **yes** | **no** — both ends hold the key |

> A shared secret cannot establish *who* acted. A system with only MAVLink signing can prove a
> command was not tampered with in flight and cannot answer "who authorized this?" after an
> incident — which is the question that matters in a post-incident review and in court.

Master Plan §5 requires the first; Zero-Trust §4.3 requires the second. Both are implemented.

---

## 2. The binding

`MavlinkSigner.sign` takes an `AuthorizedFieldCommand`. That type is constructible **only** as
the return value of `CommandTokenVerifier.verify`, and carries a private marker the signer
checks — so a caller that simply instantiates the dataclass is refused.

```
operator (FIDO2 key)
    │  signs canonical_field_command_bytes(command, operator, role, nonce, window)
    ▼
OperatorToken ──► CommandTokenVerifier.verify(command, token)
                        │  tier · key · operator binding · credential binding
                        │  window · lifetime cap · algorithm · signature · nonce
                        ▼
                  AuthorizedFieldCommand ──► MavlinkSigner.sign(frame, authorization=…)
                                                   │  message id matches the authorization
                                                   │  authorization unexpired
                                                   │  MAVLINK_IFLAG_SIGNED set
                                                   ▼
                                             MavlinkSignatureBlock (13 bytes)
```

"Verify before signing" is therefore a property of the type system rather than a rule someone
has to remember. There is no argument combination that signs an unauthorized frame.

### 2.1 What the operator token commits to

`canonical_field_command_bytes` covers the command id and type, the mission, **the drone**,
**the exact parameters** (as a digest, so the signer need not parse them), the MAVLink message
id, the operator, the role, the nonce, and the validity window.

A token that named only the operator and the time could be moved onto any command that
operator was entitled to issue. Each field above closes one such move, and the tests name them
individually: `test_token_for_a_different_command_is_refused`,
`test_token_for_a_different_drone_is_refused`,
`test_token_for_different_parameters_is_refused`.

### 2.2 Two orderings that are load-bearing

**The nonce is consumed only after the signature verifies.** Consuming first would let an
attacker burn a legitimate operator's nonce with a garbage signature — turning verification
into a denial-of-service primitive that locks the operator out of issuing the command at all.
(`test_a_bad_signature_does_not_burn_the_nonce`)

**The MAVLink replay check runs after the signature check.** If it ran first, an attacker could
send a far-future timestamp with a garbage signature and advance the stream counter past the
genuine sender. (`test_forged_frame_cannot_advance_the_replay_counter`)

### 2.3 MAVLink2 specifics

Implemented to the MAVLink message-signing specification so it interoperates with
PX4/ArduPilot: a 13-byte block of `link_id (1) | timestamp (6, LE) | signature (6)`, where the
signature is `SHA-256(secret ‖ header ‖ payload ‖ CRC ‖ link_id ‖ timestamp)` truncated to six
bytes, and the timestamp counts 10-microsecond units from 2015-01-01.

That construction is a prefix-keyed hash rather than an HMAC. An HMAC would be better in the
abstract; matching the protocol is what makes the frames verifiable by a real flight
controller, and substituting a stronger construction would simply mean nothing could read them.

Timestamps are monotonic **per `(link_id, system, component)`**. A shared counter would let a
chatty component starve a quiet one by advancing past it. Within a single clock tick — easy at
rate, since a unit is 10 µs — the counter steps rather than reusing a value, because a reused
timestamp is indistinguishable from a replay to the receiver.

### 2.4 No transport

`src/ros2_bridge/` opens no socket, no serial port, and no flight-controller connection. The
Milestone-0 gate forbids code that commands or arms hardware; a signing primitive is a security
control, and keeping the package transport-free is what makes that distinction checkable.
`test_module_has_no_transport` enforces it.

---

## 3. The Role Precedence Matrix

Defined once in `dronez/authz/precedence.py`, mirrored in `override.rego`, and the two tier
tables are compared directly by `test_rego_tier_table_matches_python`. Drift between them would
not surface as a test failure in the ordinary course — it would surface as an authorization bug
in whichever component nobody was looking at.

| Tier | Role | May override / cancel |
| --- | --- | --- |
| 1 | Command Room | Any Tier 2 or Tier 3 command |
| 2 | Tactical Field Leader | Tier 3 only |
| 3 | AI Agent proposal | **Nothing** |

Two properties beyond the obvious:

- **No peer override.** Authority is by tier, never by recency. A Command Room operator cannot
  override another Command Room operator through this path; peer disputes are resolved by a
  human, not by whoever's request arrived last.
- **Tier 3 cannot override another Tier 3.** An agent able to cancel its own earlier proposal
  could launder a rejected plan into an accepted one by superseding the rejection.

---

## 4. The asymmetry: refusal versus violation

Two refusals come out of this matrix and they are **not the same event**.

| | Tier 2 → Tier 1 | Tier 3 → anything |
| --- | --- | --- |
| Outcome | refused | refused |
| Classification | ordinary authorization failure | **security violation** |
| Severity | — | P1 |
| Reaches | the caller | the caller **and** the alert sink |

A field leader legitimately holds override authority over *something*; reaching one tier too
high is a mistake a person makes. An agent holds no override authority at all, so an attempt is
either compromise or malfunction — and Master Plan §5 is explicit that it is *"treated as a
security event, not a benign conflict."*

Classifying both identically would bury the signal that matters in routine noise. So:

- `Outcome.SECURITY_VIOLATION` is a distinct terminal outcome, always a security signal.
- `SecurityViolation` carries a `ViolationKind`, a severity, the actor, and the target.
- `AuditTrail.record_violation` writes the `Command` record **and** fans out to the alert sink
  in one call. A violation recorded but never alerted, or alerted but never recorded, is the
  failure mode that single call exists to prevent.

One attempt therefore produces **two** records, and both are wanted: the violation record
carries the P1 alert payload a SIEM rule fires on, and the `Command` record is the audit
backbone entry Master Plan §5 requires for every attempt including rejected ones. An alert with
no `Command` record has no provenance; a `Command` record with no alert reaches nobody.

### 4.1 Why the attempt is expressible

`supersedes_command_id` is a **declared** field on `DeployReconWaypointRequest`. Leaving it
undeclared would have the closed-world schema reject it as a generic mass-assignment error —
still a rejection, but logged as a schema mistake rather than as an attack. You cannot detect an
attack you have made inexpressible.

### 4.2 Why the flag is derived independently

`PrecedenceArbiter` computes the violation flag from the matrix rather than reading it off the
policy response. The Rego computes the same flag, and they are cross-checked by test — but a
security signal that disappears when the policy engine is down is not a signal.
(`test_agent_attempt_is_flagged_even_when_the_engine_is_down`)

Conversely, a policy-engine **outage** is refused but *not* flagged as an attack. Routing Rego
bugs and network failures to the security on-call rota is how real violations come to be
ignored. (`test_policy_engine_outage_refuses_the_override`)

---

## 5. Open items

| ID | Item | Disposition |
| --- | --- | --- |
| `TM-19` | MAVLink per-link signing secrets have no provisioning, rotation or revocation path | **Open.** The primitive is correct; the key lifecycle is not built. Blocks any real link. |
| `TM-20` | The arbiter and the Rego compute the violation flag independently, cross-checked only by test | **Accepted** — deliberate; see §4.2. |
| `TM-13` | The Rego, including `override.rego`, has never been executed | **Open.** `opa` is blocked by egress policy here. Run `scripts/verify_policies.sh --require-opa`. |
