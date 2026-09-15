# `DEGRADED_VISUAL_INERTIAL_LANDING` — Firmware Specification

| | |
| --- | --- |
| **Milestone** | 4 (specification); firmware implementation is **out of scope for this repository** |
| **Status** | **Specification only.** No flight-controller code exists here — CLAUDE.md §2.1 forbids it until the Milestone-0 gate closes. |
| **Residency** | PX4/ArduPilot flight controller. **Not** the companion computer, **not** the MCP server. |
| **Server-side artifact** | `src/dronez/safety/states.py` — encodes the invariant that the ground can neither command entry into this state nor command exit from it. |
| **Envelope constants** | `degraded_descent_rate_mps`, `degraded_min_obstacle_clearance_m`, `gnss_*` (see `src/dronez/safety/envelope.py`) |

---

## 0. What this document is, and what it is not

This is the **specification a firmware vendor or embedded team implements against**, plus
the hardware-in-the-loop acceptance criteria that decide whether their implementation is
accepted. It is written now, at Milestone 0/4 boundary, for one reason: the behaviour it
describes is the behaviour that has to work when *everything this repository builds has
already failed*. Specifying it after the server is built would invert the dependency.

It is **not** an implementation, and no part of this repository may become one. CLAUDE.md
§2.1: no MAVLink/ROS2 publisher, no flight-controller bridge, no `HardwareDispatcher`.
What this repository contributes to DVIL is a *negative* capability — the demonstrable
absence of any code path by which the ground could reach into this state.

---

## 1. The claim this state exists to make good on

The Master Plan's central safety claim is that **a server outage degrades capability,
never safety**. Most fail-safe states support that claim easily: RTL needs a position
fix and a route home, and the aircraft has both.

DVIL is the case where it does not.

> **Trigger:** GNSS denial **and** loss of the optical/thermal feed, **concurrently**.

Each failure alone has a well-understood answer:

| Failure | Answer | Why it works |
| --- | --- | --- |
| GNSS denied, vision intact | Visual-inertial odometry holds position; RTL over a visually tracked path | The aircraft still knows where it is, relative to what it can see |
| Vision lost, GNSS intact | Standard RTL on GNSS waypoints | The aircraft still knows where it is, absolutely |
| **Both, concurrently** | **DVIL** | **The aircraft does not know where it is in any frame that survives more than a few seconds of inertial drift** |

The third row is why DVIL is not a `trigger_reason` of `execute_safe_return`. A standard
RTL is a *navigation* behaviour: it presumes the aircraft can answer "where am I, and
where is home". After a concurrent GNSS/vision failure the honest answer to both is *we
no longer know, and our estimate is degrading at the rate of the IMU's bias drift*.

Commanding an RTL in that condition is commanding the aircraft to fly a route it is
computing from an estimate it cannot check, in airspace it cannot see, near an incident
it was dispatched to because people are there. **The correct action is to stop translating
and get on the ground where you are, slowly, using the only sensors still telling the
truth.**

### 1.1 DVIL preempts RTL; they are never concurrent

At any instant exactly one of these is active, and the **firmware** selects between them
on which sensors are actually available — not the server, not the operator, not the agent.

```
                    GNSS valid?
                   /           \
                yes             no
                 |               \
          vision needed?          vision (VIO) valid?
                 |                /            \
              RTL             yes              no
                             /                   \
                    VIO-assisted RTL            DVIL
```

If GNSS recovers mid-descent, see §4.3: the aircraft **does not** resume RTL.

---

## 2. Entry conditions

DVIL is a **sub-state of `FAILSAFE`**. The transition is `FAILSAFE →
DEGRADED_VISUAL_INERTIAL_LANDING`, and it is in `FIRMWARE_TRANSITIONS`, never in
`GROUND_COMMANDABLE` (`src/dronez/safety/states.py`).

Both predicates must hold **simultaneously and continuously** for the debounce window.

### 2.1 Predicate A — position solution is not trustworthy

Any one of:

| Condition | Threshold | Envelope constant |
| --- | --- | --- |
| GNSS/INS divergence sustained | > 12 m for ≥ 2 s | `gnss_ins_divergence_max_m`, `gnss_divergence_sustain_s` |
| Satellite count | < 8 | `gnss_min_satellites` |
| HDOP | > 1.8 | `gnss_max_hdop` |
| Total loss of GNSS fix | no fix | — |

The divergence test is the anti-spoofing one, and it is the reason the sustain window
exists as a separate constant. A spoofer who captures the receiver and walks the reported
position away from truth produces exactly this signature: a GNSS solution that is
internally healthy — good satellite count, good HDOP, high confidence — and diverging
from inertial dead-reckoning. **A high-confidence fix is not a trustworthy fix.** The
2-second sustain window prevents a multipath glitch under a bridge or beside a building
from being read as an attack.

### 2.2 Predicate B — the visual/thermal channel is not usable

Any one of:

- No frame from the optical **and** no frame from the thermal sensor within the sensor
  timeout (vendor-set; ≤ 1 s recommended at ≥ 10 fps nominal).
- The VIO estimator has diverged or self-reported loss of tracking.
- Feature count below the estimator's minimum for longer than the estimator's own
  recovery window (smoke, dust, total darkness with thermal also lost, sensor blinding).

> Optical and thermal are separate sensors. Predicate B requires **both** to be
> unusable — a smoke-obscured optical camera with a working thermal array is not a
> concurrent failure, and must not trigger DVIL.

### 2.3 Debounce and hysteresis

Entry requires both predicates true continuously for **`gnss_divergence_sustain_s`
(2 s)**, evaluated on the flight controller's own clock.

There is no exit hysteresis, because there is no exit — see §4.3.

### 2.4 What is explicitly *not* an entry condition

| Not a trigger | Why |
| --- | --- |
| Loss of C2 link | That is `LOST_LINK` → `FAILSAFE` after `link_loss_grace_s`. A link-lost aircraft that can still navigate should RTL. |
| MCP server unreachable | The server has no role in this state at all. |
| An operator command | There is no such command. See §5. |
| An agent proposal | The agent has no actuation path, in any state (CLAUDE.md §3.2). |
| Low battery | That is the `battery_rtl_trigger_pct` / `battery_land_now_pct` / `battery_critical_pct` ladder. |

A low-battery **land-now** while already in DVIL does not change the behaviour: DVIL is
already an immediate local descent, which is what land-now commands.

---

## 3. Behaviour in state

### 3.1 The descent

| Parameter | Value | Constant |
| --- | --- | --- |
| Descent rate | **0.5 m/s** | `degraded_descent_rate_mps` |
| Minimum obstacle clearance | **1.5 m** lateral and vertical | `degraded_min_obstacle_clearance_m` |
| Lateral translation | **None commanded.** Only avoidance-driven displacement (§3.3) | — |
| Yaw | Held. No yaw authority is spent on anything | — |
| Guidance sensors | Ultrasonic + LiDAR arrays **only** | — |

Waypoint navigation is **bypassed entirely**. The mission is over; there is no route, no
next waypoint, and no home position the aircraft trusts. The autopilot's position
controller is not driving this descent — the altitude/obstacle controller is.

`degraded_descent_rate_mps` is deliberately far below `descent_rate_max_mps` (3 m/s), and
`validate_envelope()` asserts that relationship holds. The reason is a control-authority
one: the ultrasonic and LiDAR arrays have a finite sample rate and a finite range, and
the descent must be slow enough that **the arrays, not the descent rate, are the binding
constraint**. At 0.5 m/s the aircraft covers 0.5 m in the second it takes a slow array to
confirm an obstacle at 1.5 m — it can still stop. At 3 m/s it cannot.

### 3.2 Payload and radio behaviour

- **Recording continues.** The evidence pipeline (`docs/06-evidentiary-pipeline.md`) is
  archive-first and does not depend on the link. A DVIL descent is exactly the footage
  an incident review will want.
- **Telemetry continues to be transmitted** if the link is up, best-effort, at reduced
  rate. It is *reporting*, and it changes nothing about the descent.
- **No inbound message alters behaviour.** See §5.

### 3.3 Obstacle handling during descent

The arrays maintain `degraded_min_obstacle_clearance_m` = 1.5 m. On a violation:

1. **Arrest the descent.** Hold altitude.
2. **Displace laterally** — minimum magnitude, away from the intrusion, bounded by what
   the arrays can see. This is the *only* lateral motion in this state, and it is
   reactive, never planned.
3. **Resume descent** once clearance is restored.
4. If clearance cannot be restored before the aircraft reaches the battery-critical
   threshold (`battery_critical_pct`, 10 %), the firmware's critical-battery behaviour
   takes precedence and commands a controlled descent regardless. **The airframe is going
   to the ground; the only remaining question is whether it does so under control.**

Step 4 is the hardest trade in this document and it is deliberate. A drone hovering at
1.5 m clearance with a dead battery falls. A drone descending under control into a
cluttered space at 0.5 m/s does not fall. The envelope constant
`battery_critical_pct` already encodes that choice.

### 3.4 Ground contact and disarm

On land-detection (vendor-specific: descent-rate collapse, thrust drop, contact sensing),
the aircraft **disarms immediately** and transitions
`DEGRADED_VISUAL_INERTIAL_LANDING → POST_FLIGHT`. That transition is in
`FIRMWARE_TRANSITIONS`. There is no ground path into `POST_FLIGHT` from DVIL, and no
re-arm without a full `POST_FLIGHT → IDLE → PRE_FLIGHT_CHECK` cycle with a human in it.

---

## 4. Exit conditions

### 4.1 The only nominal exit

Ground contact and disarm (§3.4).

### 4.2 `FAILSAFE` is not re-enterable from DVIL

DVIL is already inside `FAILSAFE`. There is no escalation left.

### 4.3 Sensor recovery does **not** exit the state

> **If GNSS recovers mid-descent, the aircraft continues the descent.**

This is the single most counter-intuitive rule here, and it is not an oversight.

The trigger for DVIL includes *sustained GNSS/INS divergence* — the signature of a
spoofing attack. An adversary who can produce that signature can also make it stop. If
recovery re-enabled navigation, the attack becomes: deny GNSS to force DVIL, then "restore"
a spoofed fix, and the aircraft resumes navigation on coordinates the attacker chose,
with a degraded inertial reference it can no longer use to cross-check them. The aircraft
would fly *wherever the attacker wanted*, having just been deprived of its only means of
detecting that.

A landing that completes on the wrong patch of ground is recoverable — the aircraft is
on the ground, intact, and a human retrieves it. An aircraft flown under adversarial
guidance is not.

Recovered sensors are still **used**: restored LiDAR, restored optical, restored thermal
all improve the obstacle picture for the descent in progress. They are used for *seeing*,
never for *going somewhere else*.

### 4.4 No timeout

DVIL has no expiry. A descent that takes longer than expected, because of §3.3 obstacle
holds, is a descent that is still working. The battery ladder bounds it physically.

---

## 5. Independence from everything this repository builds

This is the section a security reviewer should read first.

| Dependency | Present? | Consequence |
| --- | --- | --- |
| MCP server reachable | **No** | A total server outage does not affect DVIL |
| Policy engine (OPA) | **No** | A policy-engine failure does not affect DVIL |
| C2 / RF link | **No** | DVIL is frequently entered *with* the link up; it does not need it |
| Companion computer | **No** | DVIL is flight-controller-resident. A compromised or crashed Jetson does not affect it |
| AI agent | **No** | The agent has no actuation path in any state |
| GNSS | **No** | Its absence is half the trigger |
| Optical/thermal | **No** | Its absence is the other half |
| Ultrasonic/LiDAR arrays | **Yes** | The only external dependency. §7.3 covers their loss |
| IMU / barometer | **Yes** | Attitude and altitude-rate control |

### 5.1 The server's contribution is a hole where a feature would be

`src/dronez/safety/states.py` encodes what the ground **cannot** say:

```python
GROUND_COMMANDABLE  # 14 transitions. None enters FAILSAFE or DVIL. None leaves either.
```

`check_transition(..., by_ground=True)` refuses on two separate grounds — target in
`FAILSAFE_STATES`, and source in `FAILSAFE_STATES` — and the unit tests assert both
across the full state cross-product, so the property is checked exhaustively rather than
by example.

There is no "DVIL request" tool, no `trigger_reason` value for it on `execute_safe_return`,
and no field on any schema that names it as an input. It appears in the schemas in exactly
one capacity: as a **`DroneState` value the server can observe and display**. Observability
is mandatory — see §6.

### 5.2 Why observable but not commandable

The command room must be able to see that an airframe has entered degraded landing:
they need to know a drone is coming down uncontrolled-in-position, roughly where it was
last known to be, so they can keep a security team clear of it and recover it afterwards.
Blinding the operators during the exact event they most need to understand would be its
own safety failure.

Observable is not requestable. Conflating the two is how a safety state becomes an attack
surface — a state you can *ask* for is a state an adversary can *induce*.

---

## 6. Reporting obligations (ground side — these **are** in scope here)

When telemetry reports DVIL, the MCP server must:

1. **Accept the state.** `FAILSAFE → DEGRADED_VISUAL_INERTIAL_LANDING` is in
   `FIRMWARE_TRANSITIONS`, so `check_transition(..., by_ground=False)` returns plausible
   and `FleetRegistry` records it rather than rejecting the telemetry as corrupt.
2. **Mark the drone unavailable** for scheduling, immediately and without a grace period
   (`FleetRegistry` / `unavailable_reason`).
3. **Raise a `AlertEvent` at the highest severity**, to the command room, out of band from
   the mission thread.
4. **Write a `Command` audit record** — this is a mission ending, and CLAUDE.md §1.3
   requires every mission to end in one of exactly three states with a record.
5. **Not attempt any recovery command.** Not RTL, not land, not disarm, not re-arm. There
   is nothing useful to send and the attempt itself is the Zero-Trust §4.1 violation.
6. **Continue archiving the evidence stream** for as long as frames arrive.

---

## 7. Known limitations, stated rather than hidden

### 7.1 Where the aircraft lands is not chosen

DVIL descends **where the aircraft is**. It does not select a landing site, because
site selection needs the vision system that is by definition unavailable. Inside an urban
incident zone that may be a road, a roof, or water.

This is accepted as the least-bad option: the alternative is translating toward a remembered
site using a position estimate that is drifting, through obstacles that are only visible to
short-range arrays, which is the failure mode this state exists to avoid. The operational
mitigation is `mission_radius_max_m` (2000 m) and `altitude_min_agl_m` (15 m) — the
aircraft is never far from where it was dispatched and never higher than it needs to be.

### 7.2 Inertial drift is unbounded during the descent

The aircraft's position estimate degrades throughout DVIL. Nothing corrects it, and
nothing in DVIL depends on it — that is the point. The consequence is that **the reported
touchdown position is an estimate with a growing error bound**, and recovery teams must
be given that bound rather than a point. Ground software must surface the uncertainty, not
a coordinate that looks authoritative.

### 7.3 Loss of the ultrasonic/LiDAR arrays during DVIL

The one remaining external dependency. If the arrays fail mid-descent, obstacle clearance
cannot be maintained, and the firmware falls back to a blind controlled descent at
`degraded_descent_rate_mps` with the descent rate unchanged.

There is no better option — the aircraft cannot hold altitude indefinitely, cannot
navigate, and cannot see. A slow blind descent is the lowest-energy way to reach the
ground. **This must be reported distinctly in telemetry** so that the command room knows
the descent is unguided, because the ground-safety implication for the security team
differs sharply from a guided one.

### 7.4 This specification is unvalidated against real hardware

No airframe has been selected (CLAUDE.md §4.1 — several envelope constants carry
*"pending fleet-specific review"*). `degraded_descent_rate_mps` and
`degraded_min_obstacle_clearance_m` are engineering defaults derived from the plan and the
standard, **not** values validated against a specific array's range, sample rate and
minimum sensing distance. §8 is how that gets fixed; until §8 passes on the actual
airframe, these numbers are a proposal.

---

## 8. HIL acceptance criteria

Milestone 4's security gate requires hardware-in-the-loop simulation of concurrent
fail-safe triggers across multiple airframes, explicitly including the dual-failure
scenario landing safely under ultrasonic/LiDAR guidance alone. These are the tests that
gate acceptance of a vendor's firmware. **All are run with the MCP server powered off**
unless a case says otherwise — that is the claim under test.

| ID | Scenario | Pass criterion |
| --- | --- | --- |
| **HIL-D-01** | GNSS denied, vision intact | RTL on VIO. **DVIL must NOT trigger.** |
| **HIL-D-02** | Vision lost, GNSS intact | Standard RTL. **DVIL must NOT trigger.** |
| **HIL-D-03** | Optical lost, thermal intact, GNSS denied | RTL on thermal VIO. **DVIL must NOT trigger** (§2.2). |
| **HIL-D-04** | Both denied concurrently, clear airspace below | DVIL entry within `gnss_divergence_sustain_s` + one control cycle; descent rate 0.5 m/s ±10 %; no commanded lateral translation; disarm on contact; `POST_FLIGHT`. |
| **HIL-D-05** | Both denied, **MCP server powered off** | Identical to HIL-D-04. No behavioural difference measurable. |
| **HIL-D-06** | Both denied, **C2 link severed** | Identical to HIL-D-04. |
| **HIL-D-07** | Both denied, **companion computer halted** | Identical to HIL-D-04. |
| **HIL-D-08** | Both denied, obstacle intrudes to 1.0 m mid-descent | Descent arrested; lateral displacement away, minimum magnitude; descent resumed; clearance never below 1.5 m after the first control cycle. |
| **HIL-D-09** | **GNSS "recovers" mid-descent (spoofed)** | Descent **continues**. No navigation resumed. No RTL. (§4.3) |
| **HIL-D-10** | Vision recovers mid-descent | Descent **continues**. Recovered sensors improve the obstacle picture only. |
| **HIL-D-11** | Ultrasonic/LiDAR arrays fail mid-DVIL | Blind controlled descent at 0.5 m/s; **distinct telemetry indication** that guidance is lost (§7.3). |
| **HIL-D-12** | Battery reaches `battery_critical_pct` while holding on an obstacle | Critical-battery controlled descent takes precedence (§3.3 step 4). |
| **HIL-D-13** | **Ground commands RTL / land / disarm / re-arm during DVIL** | Every command **ignored**. Descent unaffected. Each attempt logged by the firmware. |
| **HIL-D-14** | **Forged, correctly MAVLink2-signed "exit DVIL" command injected** | Ignored. There is no such command in the protocol surface. |
| **HIL-D-15** | Transient 1 s dual dropout (below debounce) | **DVIL must NOT trigger.** Mission continues. |
| **HIL-D-16** | GNSS spoof walking position away at 2 m/s, vision denied | DVIL entry on the divergence test (§2.1) — **the aircraft must not follow the spoofed fix.** |
| **HIL-D-17** | Dual failure during multi-drone operation | Each affected airframe enters DVIL independently; `swarm_min_separation_m` maintained by the unaffected airframes' own onboard deconfliction (companion-resident), not by the server. |
| **HIL-D-18** | Dual failure at `altitude_max_agl_m` (120 m) | Descent completes; total time consistent with 0.5 m/s plus obstacle holds; battery ladder not breached before contact. **This case sizes the battery reserve.** |

### 8.1 Release-blocking

Per Zero-Trust §11.1 and CLAUDE.md §10.3, for native/embedded code: any open ASan/UBSan/
MSan finding or a missing current fuzzing report is release-blocking. The ultrasonic/LiDAR
ingest path and the MAVLink parser are both native-code attack surface reachable in this
state — **HIL-D-14 is not a formality**, and the fuzzing corpus must cover the array ingest
path, not only MAVLink.

### 8.2 Traceability

`TM-12` in CLAUDE.md §7 records that no HIL rig exists yet, which makes every row in §8
**unexecuted**. The threat model calls the "server disconnected, fail-safe still works"
test the single most important test in the programme; HIL-D-05 is that test, and it is
open.

---

## 9. Cross-references

| | |
| --- | --- |
| State machine and ground-command allow-list | `src/dronez/safety/states.py`, CLAUDE.md §5.4 |
| Envelope constants and enforcement locus | `src/dronez/safety/envelope.py`, CLAUDE.md §4 |
| GNSS spoofing threat analysis | `docs/02-security-threat-model.md` |
| Evidence continuity during the descent | `docs/06-evidentiary-pipeline.md` |
| Fleet-side reporting obligations | `src/fleet_manager/registry.py` |
| Why the server never overrides firmware | Zero-Trust v3.0-ULTRA §4.1; CLAUDE.md §3.3, §6 |
