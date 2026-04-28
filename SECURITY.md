# YEET Security Model

This document describes the threat model YEET is designed against, the
guarantees the SAS handshake provides (and does not provide), and the
out-of-scope cases pairing partners need to be aware of. It complements
`ANALYSIS.md` (which describes architectural constraints) and the in-tree
spec for the SAS handshake.

## Sole authentication mechanism

**The SAS — the six-digit code shown on both screens after pairing — is the
sole authentication mechanism.** No fingerprint, fingerprint prefix, or
session secret is transmitted in the passcode. The passcode carries only the
information needed for two browsers to establish a WebRTC session; verifying
that the session is end-to-end with the intended human is the job of the SAS
comparison alone.

If users skip the comparison, click "they match" without checking, or pair
across a channel where the SAS cannot be compared (deafblind remote pairing,
asynchronous handoff with no follow-up call), the connection is unverified
and a network attacker who can see the passcode could be in the middle.

## Threat model

The attacker, Eve, sits on the network between the sender (Alice) and the
receiver (Bob).

- Eve **cannot** break DTLS, SHA-256, or HKDF-SHA256.
- Eve **can** see, modify, drop, and inject any packet between Alice and
  Bob, including ICE/DTLS traffic.
- Eve **can** present her own self-signed DTLS certificate to either side.
- Eve **may** see the passcode (e.g. it was screen-shared in a meeting Eve
  is on, or the channel Alice and Bob used to share it is monitored).

Eve's only path to a successful attack against the SAS is a parallel-MITM:
she completes one DTLS handshake with Bob (presenting her cert C_eve_to_bob)
and another with Alice (presenting C_eve_to_alice), then forwards application
traffic between them.

For Eve to win, she needs the SAS Bob computes — HKDF over (FP_eve_to_bob,
FP_bob, nonce) — to equal the SAS Alice computes — HKDF over
(FP_eve_to_alice, FP_alice, nonce). She controls two of the four
fingerprints, but she has to commit to her certs **before** seeing the
peer's. Her odds per attempt are 2^-20 (≈ 1 in a million).

If Alice or Bob notices the SAS does not match and aborts, the session is
torn down and a new passcode is required. Eve cannot grind certs against an
already-displayed passcode without the human-comparison step catching her.

## What the SAS does not protect against

- **A user who taps "they match" without comparing.** No code can fix this.
  The instruction copy ("Read these numbers out loud. The other person should
  see the same ones.") is deliberately blunt.
- **A compromised endpoint.** If Alice's browser or device is compromised,
  no over-the-wire protocol can help. SAS protects the channel, not the
  endpoints.
- **Side channels on the SAS itself.** The SAS is six decimal digits read
  aloud. If an attacker can hear Alice and Bob, the SAS does not stay secret
  — but it does not need to. Its security property is "Eve cannot pre-image a
  cert pair to a chosen 20-bit value with non-negligible probability," not
  "the SAS is secret."
- **Long-term tracking.** YEET does not pin fingerprints across sessions
  (Decision #10). Each pairing starts fresh. If Eve was in the middle last
  Tuesday and Alice ignored the SAS mismatch, Wednesday's session is not
  protected by Tuesday's mistake — but neither is it tainted by it.

## Why the data channel is application-gated

WebRTC opens the data channel as soon as DTLS completes. Both peers can send
bytes immediately, before the SAS has been compared. YEET's data channel is
**application-gated**: until both peers have exchanged a valid `sas-confirm`
message AND the local user has tapped "they match," the application layer
neither delivers received payloads to the UI nor accepts outbound payloads
from the UI. The only message accepted before unlock is the SAS confirm
itself; anything else aborts the session.

This means asymmetric confirmation — only one peer clicking — does not unlock
the channel. Both must confirm, and each must observe a `sas_value` from the
peer that matches its own local SAS. A divergent `sas_value` is a hard abort,
not silent — this catches implementation bugs (byte-ordering inverted,
extraction reversed) loudly rather than letting them tap-through to a false
sense of safety.

## Listener model in browser-only WebRTC

The original spec called for a "single-completed-handshake listener" — Bob
listens, accepts unlimited *failed* handshakes, closes on the first success
— so Eve's probing attempts visibly burn the session. Browser WebRTC does
not expose a listener primitive: ICE/DTLS only run after both sides have
exchanged SDP via `setRemoteDescription`.

We therefore rely on the application-layer abort path to provide the
"one-shot per session" property:

- A successful MITM still has only 2^-20 odds per attempt.
- If the SAS does not match and either user aborts, the `RTCPeerConnection`
  is closed, the cert is discarded, and a fresh passcode is required.
- There is no fingerprint pinning across sessions, so a partial compromise
  does not propagate (Decision #10).

The threat-model implication is not weaker: Eve still has to win 1-in-a-
million per attempt against an attentive user. It is weaker only against
inattentive users — but the spec is explicit that no protocol can rescue a
user who clicks "they match" without checking.

## Out of scope

- **Deafblind remote pairing.** SAS comparison requires that both users can
  observe the same value on their respective screens and confirm it to each
  other. If neither user can see the screen and they are not in the same
  room, the SAS step cannot be performed safely. YEET v1 does not ship with
  a non-visual SAS variant (QR-of-SAS, audio playback, haptic) — these are
  deferred. Users who need accessible pairing should pair in person where
  the passcode and SAS can be communicated through whatever channel works
  for them.
- **Asynchronous pairing.** "Leave a passcode, peer connects later" requires
  both users to be reachable for the SAS step. If only one user is present,
  the connection cannot be authenticated.
- **Denial of service.** YEET makes no attempt to defend against a network
  attacker who simply blocks UDP between Alice and Bob.

## Version byte and forward compatibility

Every passcode begins with a 1-byte version field. v1 is `0x01`. Any change
to the wire format, HKDF inputs, SAS extraction rule, or word list MUST bump
this byte. The parser rejects unknown versions with the copy "This passcode
was made by a different version of YEET. Both people need to be on the same
version." This prevents two clients with diverging SAS computations from
silently producing mismatched values that users tap through.

Test vectors at `tests/sas-vectors.json` are the canonical contract for the
SAS computation. Any version bump must update those vectors and justify the
change in the PR description; the prior version's vectors should be retained
as `tests/sas-vectors-v1.json` if backward parsing is ever supported.
