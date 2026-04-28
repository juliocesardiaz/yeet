# Phase 1 — Codebase Analysis

This document is the Phase 1 deliverable for the SAS handshake redesign. It maps
the existing codebase, names the files that change in Phase 2, and surfaces one
load-bearing architectural conflict between the spec and what browser WebRTC
will actually let us do.

## Repo layout (as shipped today)

```
yeet/
├── index.html              single-page app shell, three views (pairing, connected, disconnected)
├── css/style.css           Mechanical Vellum design system, hand-written
├── js/
│   ├── app.js              entry point, pairing state machine, button wiring
│   ├── rtc.js              RTCPeerConnection wrapper (createOffer / acceptOffer / acceptAnswer)
│   ├── signaling.js        SDP <-> word-code codec, ICE-credential derivation
│   ├── wordlist.js         4096-word BIP39-style list (12 bits per word)
│   ├── protocol.js         data-channel message constants + JSON codec
│   └── ui.js               DOM helpers, name generator
└── tests/
    ├── test-signaling.mjs  node:test runner against signaling.js
    └── test-connection.html in-browser RTC smoke harness
```

No build step. ES modules loaded directly. Single external network dependency
is Google Fonts.

## Pairing flow today

Two-way exchange, not one. Initiator generates a code containing their offer
SDP; joiner pastes it, generates their own code containing the answer SDP;
initiator pastes that. After both `setRemoteDescription` calls, ICE/DTLS runs
and the data channel opens.

```
Initiator                          Joiner
---------                          ------
createOffer()
  -> SDP -> compress() -> "code A"
                                   acceptOffer("code A")
                                     -> SDP' -> compress() -> "code B"
acceptAnswer("code B")
                                   <-- ICE/DTLS handshake -->
                                     data channel opens
```

The "code" in each direction is a compressed SDP, currently 20-30 words. The
README's "22 words" figure for the redesign refers to the dominant cost: the
32-byte SHA-256 fingerprint at 12 bits/word is ~22 words by itself.

## Key files for Phase 2

| File              | Role                                  | Phase 2 change                                 |
|-------------------|---------------------------------------|------------------------------------------------|
| `js/sas.js` (new) | pure SAS computation                  | new module, no deps on rtc/signaling           |
| `js/signaling.js` | wire-format codec                     | add version byte, embed session nonce          |
| `js/rtc.js`       | RTCPeerConnection wrapper             | extract local+remote fingerprints post-DTLS    |
| `js/protocol.js`  | data-channel message types            | add `SAS_CONFIRM` type                         |
| `js/app.js`       | pairing state machine                 | add awaiting-sas-confirm state, gate data flow |
| `index.html`      | view markup                           | new SAS-verify step under `#view-pairing`      |
| `css/style.css`   | styling                               | add `.sas-digits` block; reuse existing tokens |
| `tests/sas-vectors.json` (new) | hand-computed SAS test vectors      | new                                            |
| `tests/test-sas.mjs` (new)     | vector test runner                  | new                                            |
| `SECURITY.md` (new) | threat model + scope acknowledgment | new                                            |

## Word list

Confirmed 4096 words, 12 bits per word — see `tests/test-signaling.mjs:37`.
The spec's 72-bit / 6-word arithmetic stands.

## Architectural conflict with the single-passcode model (load-bearing)

The spec's Decision #2 — passcode = `version || IPv4 || port || nonce`, no
fingerprint — and Decision #1 — receiver exposes a listener and accepts a
single completed DTLS handshake — together describe a transport where Alice
uses just an IP+port+nonce to open a DTLS session to Bob.

Browser WebRTC does not expose this primitive. `RTCPeerConnection` requires a
remote SDP via `setRemoteDescription` before ICE/DTLS will run, and that SDP
must contain the peer's DTLS fingerprint — the browser's DTLS stack verifies
the certificate against the SDP fingerprint on every handshake. There is no
public API for "skip cert verification, we'll catch substitution at the app
layer with SAS." Without the fingerprint in SDP up-front, Alice's browser
will reject the certificate Bob presents during DTLS, and the handshake will
not complete.

Two implications:

1. **The 6-word figure is not achievable in a browser-only build** without
   either a signaling server (forbidden by the constraints) or a bridge
   process that pre-fetches Bob's SDP via some side channel. The two codes
   in the current flow already cost ~20-30 words *each*; the redesign cannot
   collapse them to a single 6-word string while staying inside the browser.

2. **The "single-completed-handshake listener" property does not directly
   apply** because there is no listener — Bob does not accept incoming DTLS;
   his browser drives ICE outward using ufrag/pwd from the answer SDP that
   Alice's browser produced. The probe-detection property the spec relies on
   for its threat model (Eve burns Bob's session by completing one handshake
   to learn FP_bob) does not have a clean analog. Eve's attack surface is
   instead bounded by her chance of substituting both her certs without
   either side noticing the SAS mismatch — still 2^-20 per attempt, but the
   "one shot per session" property has to come from the app layer aborting
   on SAS mismatch and forcing a fresh code, not from a listener closing.

## Recommended Phase 2 adaptation

Implement the SAS layer in full (the security-critical bit). Keep the two-way
SDP exchange (the only browser-supported transport). Embed the session nonce
in the offer code so both peers feed the same nonce to HKDF.

Concretely:

- **Wire format** gains a 1-byte version prefix (`0x01`) and a 16-bit nonce
  field. Initiator generates the nonce when creating the offer code; joiner
  parses it from the offer and reuses it. Answer code carries the same
  version prefix; nonce does not need to be echoed because the joiner already
  has it from the offer. Unknown version bytes hard-reject with the spec's
  "update YEET" copy.
- **SAS** is computed on both sides immediately after `connectionState ===
  "connected"`, using the actual fingerprints visible in `pc.localDescription`
  and `pc.remoteDescription`. Algorithm follows Decision #4 verbatim, including
  the `"YEET-SAS-v1"` info string with the nonce appended.
- **Data channel** opens at DTLS-complete (we cannot prevent that), but the
  application layer will not deliver any payload to the UI nor accept any
  outbound payload from the UI until both peers have exchanged a valid
  `sas-confirm` message. Anything received before that point is either a
  `sas-confirm` (process it) or a protocol error (abort).
- **Confirm message** is `{ type, version, sas_value }` per Decision #9. The
  receiver checks `sas_value` against its local SAS — mismatch is a hard
  abort, not silent.
- **UI** gains an awaiting-sas-confirm step shown to both peers with the bare
  instruction copy from Decision #11 and the two action buttons.

## Manual cross-browser smoke matrix

Phase 3 unchanged from the spec. We ship after the matrix passes by hand;
automated cross-browser harness deferred.

## Open items resolved by this analysis

- **Word list:** 4096 words, 12 bits/word — confirmed.
- **SAS module location:** `js/sas.js`, alongside `signaling.js`, no build step.
- **Mismatch UI weighting:** the "they don't match" affordance will use the
  same primary-button styling as "they match" — mismatch is the routine,
  expected outcome of an attack and must not look more dangerous than the
  match path.
