# The Evidentiary Pipeline

| | |
| --- | --- |
| **Milestone** | 2 |
| **Status** | Capture, hashing, WORM and degradation implemented. **Privacy redaction not built** — see §6. |
| **Code** | `src/dronez/evidence/`, `src/edge_node/`, `src/mcp_server/media/`, `src/mcp_server/tools/stream.py` |

---

## 1. The order is the design

```
capture ──► hash + chain (on the Jetson) ──► WORM archive ─────────────► ALWAYS
                                        └─► transmit ──► tier gate ──► MAYBE
```

Master Plan §5: *"Every detection event is hashed and archived to the WORM store at
capture time, **independent of whether the live viewer was connected**."*

So the pipeline never asks whether anyone is watching before it preserves evidence.
Archival is unconditional; transmission is what degrades. A pipeline built the other way
round — archive what we manage to send — loses exactly the footage from the moments when
the link was worst, which are the moments most likely to matter afterwards.

---

## 2. Hashing happens at the sensor, not at the console

Master Plan §4 is specific about *where*: frames are hashed *"on the edge hardware (e.g.
NVIDIA Jetson) prior to transmission, not after arrival at the command room — this is
what makes the chain-of-custody claim defensible against an attacker who compromises the
network path."*

> A hash computed when a frame reaches the command room attests that nobody altered it
> **after it arrived**. An attacker on the RF link is in a position to make that claim
> true about frames they substituted. Hashing at the sensor boundary moves the trust
> anchor inside the airframe, where the secure element is.

### 2.1 Why the records are chained

Hashing each frame independently proves that **the frames you have** were not modified.
It proves nothing about the frames you *don't* have.

Each record therefore commits to its predecessor:

```
chain_hash = SHA256(previous_chain_hash ‖ stream ‖ sequence ‖ kind ‖
                    artifact_sha256 ‖ bytes ‖ captured_at ‖ collecting_system)
```

| Manipulation | Detected by |
| --- | --- |
| A frame altered | its own chain hash no longer matches its contents |
| A span of frames deleted | sequence gap **and** broken link at the splice |
| Frames reordered | out-of-order detection |
| A forged frame inserted | broken link at the insertion |
| Records relabelled to another device | `collecting_system` is inside the hash |
| **The tail truncated** | **nothing in the chain — see below** |

Truncation is the one case the chain cannot catch by itself: a truncated chain is
internally consistent, because nothing in it points forward. That is what the segment
seals are for, and `test_truncated_tail_is_detected_against_a_known_head` documents the
limitation rather than papering over it.

### 2.2 Segment seals, and why not per-frame signatures

Signing every frame would be the obvious way to bind the chain to the hardware, and it
does not work: an ECDSA signature is roughly three orders of magnitude slower than a
SHA-256 over a thermal frame, and the Jetson is already running detection inference at
video rate.

So every frame is hashed and chained, and the chain **head** is signed periodically by
the secure element — one asymmetric operation per segment instead of per frame. The
chain is what makes a single seal cover every frame beneath it.

`DEFAULT_SEGMENT_FRAMES = 300` is a seal every ten seconds at 30 fps. The trade-off is
stated at the constant: shorter bounds how much an attacker who rewrites the chain can
reach, and costs more asymmetric operations and more manifest records.

If no signer is configured, `seal_segment` **raises** rather than skipping quietly. An
unsigned chain is internally consistent and reproducible by anyone, so silently
continuing would leave the pipeline looking protected when it is not.

---

## 3. The WORM store

Zero-Trust §8.1 and Master Plan §4: *"no service identity in the system — including
administrators — holds delete/modify permission on committed records."*

**`WormSink` has no delete method and no update method.** Not a method that raises, not
one behind a permission check — none. An API that offers deletion and refuses it still
teaches every caller that deletion is something one asks for, and the refusal is one
config change from being granted. The absence is the control, and
`test_worm_sink_offers_no_deletion_path` asserts the exact method surface.

Two further properties:

- **Write-once includes identical content.** A second commit of the same record id is
  refused even when the bytes match — "identical" is a judgement the store should not be
  making about evidence.
- **Integrity is established at the door.** A record whose chain hash does not match its
  contents is refused at commit rather than discovered at audit time.

> **Where the real control lives.** This module enforces immutability in the application
> layer, which stops the application. It does not stop someone with credentials to the
> bucket. Production is S3 Object Lock in **compliance** mode, where the retention period
> cannot be shortened by any principal including the account root. Governance mode is
> explicitly unsuitable: it can be overridden by a privileged identity, which is no use
> for evidence that might implicate that identity. `InMemoryWormStore` provides the
> interface contract and none of the durability — the difference is the whole of §8.1.

---

## 4. Transport: what SDP can and cannot enforce

It is tempting to write "check the SDP says DTLS 1.3". **SDP cannot say that.** The DTLS
version is chosen during the handshake, on the media path, after signaling has finished.
A guard claiming to check it would be theatre.

The responsibility is split honestly:

| Enforced at signaling (`SdpGuard`) | Enforced in the media engine (`DtlsSrtpPolicy`) |
| --- | --- |
| Transport profile is `UDP/TLS/RTP/SAVPF` | DTLS **1.3** minimum version |
| No `a=crypto` (SDES) | AEAD SRTP profiles only (AES-GCM) |
| Fingerprint hash is SHA-256 or better | Peer certificate matches the offered fingerprint |
| ICE credentials present | |
| DTLS setup role present | |

Each signaling check closes a specific hole:

- **SDES** puts the SRTP master key *in the signaling plane*. Anyone who can read the
  offer — including anything that logged it — can decrypt the media.
- **A SHA-1 fingerprint** binds the DTLS certificate with a broken hash, so certificate
  substitution is feasible.
- **No fingerprint at all** means DTLS authenticates *a* peer, not *the* peer the
  signaling channel agreed with — a man-in-the-middle who never touched signaling.
- **No ICE** means no consent checks, and the media port becomes a reflector.
- **Non-AEAD SRTP** lets an attacker flip ciphertext bits and corrupt a thermal frame
  without the receiver noticing.

The offer is screened **after** authorization, deliberately: screening first would make
this tool an oracle for probing media policy without holding any authorization.

---

## 5. Degradation: detection is never shed

Master Plan §5: *"On link degradation, the stream drops quality tier before dropping
detection-event delivery — actionable detection alerts are prioritized over raw video
bandwidth."*

| Tier | Detection | Telemetry | Keyframe | Video delta |
| --- | --- | --- | --- | --- |
| `HIGH` | ✅ | ✅ | ✅ | ✅ |
| `MEDIUM` | ✅ | ✅ | ✅ | ✅ |
| `LOW` | ✅ | ✅ | ✅ | ✗ |
| `DETECTION_ONLY` | ✅ | ✅ | ✗ | ✗ |

`DETECTION_ONLY` is the floor and it is **not "nothing"**: it is the mode in which a
jammed link still tells the command room there are four people in the north stairwell.
`SHEDDABLE` contains only `VIDEO_DELTA` and `KEYFRAME`, and a test asserts detection is
absent from it.

This is not a tuning parameter. A recon platform whose value is telling a security team
what is inside a building *before* they enter fails completely if the detection reaches
nobody, and succeeds adequately if the video is grainy.

### 5.1 Asymmetric hysteresis

Degradation is **immediate**; recovery requires the link to hold good for a dwell period.
A link that cannot carry the current tier is already dropping packets, so waiting out a
timer just means dropping them for longer. Conversely every tier change costs a
renegotiation and a visible glitch, so a marginal link must not produce a flapping
stream.

Bandwidth alone does not set the tier: loss and round-trip time cap it independently. A
fat pipe dropping one packet in twenty cannot carry inter-frame video usefully, however
many bits per second it advertises.

### 5.2 The spool applies the same priority

The WORM store is reached over the same degraded link as the video, so archival is staged
through a bounded local spool. When it is full, **video records are dropped before
detection records** — the same priority as live delivery, for the same reason. The loss
is counted in `PipelineStats.spool_dropped` rather than being silent, because losing a
queued artifact is a real loss of evidence. The alternative — an unbounded spool that
eventually exhausts the module's storage and takes detection down with it — is worse.

---

## 6. What is not built

| Item | Status |
| --- | --- |
| **Privacy redaction pipeline** | **Not built.** Master Plan §2 requires blur/redaction before footage leaves the tactical boundary, and §6 requires compliance sign-off on it before any footage does. This is a Milestone-2 deliverable and it is outstanding — see `TM-21`. |
| Real WORM backend | `InMemoryWormStore` only. S3 Object Lock in compliance mode is `TM-22`. |
| Media engine | `DtlsSrtpPolicy` is configuration; no engine consumes it yet (`TM-23`). |
| Secure-element signer | The `SecureElementSigner` protocol has no TPM-backed implementation (`TM-24`). |
| Penetration test | Milestone 2's security gate requires a pen test of store immutability and of the video pipeline's encryption, including attempted RF eavesdropping. Not scheduled. |
