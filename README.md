# YEET

**Local P2P shared clipboard over WebRTC — no server, no accounts.**

A static web app that connects two devices peer-to-peer for a shared clipboard. Pair the devices by copying a short word-code from one to the other; after that, traffic flows directly between browsers over WebRTC DataChannels with DTLS encryption.

---

## Status

**Phase 1 — Proof of Concept.** Working today:

- WebRTC peer connection with manual copy-paste signaling
- SDP compressed to a BIP39-style word code (typically 20–30 words)
- Text snippets sent back and forth, rendered as a message feed
- Ephemeral auto-generated device names ("Onyx", "Slate", …)

Planned (not implemented yet): QR pairing, file transfer, clipboard persistence, reconnection, PWA. See the Roadmap below.

---

## How It Works

```
Device A (Initiator)                Device B (Joiner)
────────────────────                ─────────────────
1. Click "Create Room"
2. Generate WebRTC offer
3. Copy the word code
                                    4. Paste into Join Room
                                    5. Generate answer
                                    6. Copy answer code
7. Paste answer
                  ── DTLS handshake ──
8. Both screens show the same six-digit code
9. Read the code aloud, both tap "they match"
10. Direct encrypted DataChannel unlocks
```

Pairing is manual: no signaling server, no third-party relay. After the two
codes are exchanged, devices communicate directly.

### Verification step (SAS)

After the connection comes up, both devices show a six-digit code (e.g.
`482 917`). Read it aloud. The other person should see the same one. Tap
"they match" on both ends; the data channel does not unlock until both
people have confirmed and both confirmations carry matching values.

If the codes do not match, an attacker is between you. Tap "they don't
match — start over" and pair again. There is no skip button.

See `SECURITY.md` for the full threat model, including what the SAS does
and does not protect against, and `ANALYSIS.md` for the architectural
constraints behind the two-code exchange.

### Word-code format

The offer/answer SDP is stripped to the essentials — DTLS fingerprint, ICE
host candidate, setup role — and packed into a compact byte string with a
1-byte version prefix and a 16-bit session nonce (used as HKDF input for
the SAS). ICE credentials are derived deterministically from the
fingerprint via SHA-256 and are not transmitted. The result is optionally
deflate-compressed and encoded 12 bits per word against a 4096-word list.

### Async pairing caveat

"Leave a passcode, peer connects later" works for the connect step, but
the SAS step requires both people to be reachable to compare the code.
Without that, the connection is not authenticated.

---

## Tech Stack

| Layer | Choice |
|---|---|
| Frontend | Vanilla JS (ES modules) — no build step |
| Styling | Hand-written CSS, Space Grotesk via Google Fonts |
| WebRTC | Native `RTCPeerConnection` / `RTCDataChannel` |
| Compression | Native `CompressionStream('deflate-raw')` |
| Word encoding | 4096-word list, 12 bits per word |
| Hosting | Any static host (GitHub Pages works) |
| Build | None |

**External dependencies: 0.**

---

## Project Structure

```
yeet/
├── index.html              # Single page app
├── ANALYSIS.md             # Phase 1 codebase map + architectural notes
├── SECURITY.md             # Threat model and SAS guarantees
├── css/
│   └── style.css
├── js/
│   ├── app.js              # Entry point, pairing + SAS state machine
│   ├── rtc.js              # RTCPeerConnection wrapper, fingerprint extraction
│   ├── signaling.js        # SDP ↔ word-code codec, version byte, nonce
│   ├── sas.js              # Pure HKDF SAS computation
│   ├── wordlist.js         # 4096-word BIP39-style list
│   ├── protocol.js         # Message types, sas-confirm envelope
│   └── ui.js               # DOM helpers
└── tests/
    ├── test-signaling.mjs  # Codec, nonce, version-byte tests
    ├── test-sas.mjs        # SAS vector test
    ├── sas-vectors.json    # Hand-computed SAS triples (the contract)
    └── test-connection.html # In-browser RTC smoke test
```

---

## Data Protocol

Messages over the WebRTC data channel use a minimal JSON format. `ts` is attached automatically on encode.

```json
{ "t": "hello",     "name": "Onyx" }
{ "t": "clipboard", "content": "..." }
```

Peer disconnect is detected via `RTCPeerConnection.connectionState` — no wire-level message.

---

## Security

- **WebRTC DTLS encryption** on all data channel traffic.
- **Short Authentication String (SAS)** verifies end-to-end identity after
  DTLS comes up. The data channel is application-gated until both peers
  exchange a valid `sas-confirm` AND the local user taps "they match." See
  `SECURITY.md`.
- **No server, no accounts, no cloud** — nothing stored or relayed.
- **No third-party JS dependencies** — only Google Fonts is loaded from a CDN.
- The word code can be shared over an untrusted channel; the SAS catches
  network-level tampering at the verification step.

---

## Running Tests

```bash
node --test tests/test-signaling.mjs tests/test-sas.mjs
```

The SAS vector test (`tests/test-sas.mjs`) is the contract that prevents
silent cross-browser SAS divergence. Vectors at `tests/sas-vectors.json`
are hand-computed from the spec and cross-verified against an independent
HKDF implementation; do not regenerate them mechanically without bumping
`PROTOCOL_VERSION`.

The in-browser smoke test (`tests/test-connection.html`) can be opened
directly in a browser to exercise the RTC stack. For pre-release sign-off,
also run the manual cross-browser pairing matrix in `ANALYSIS.md` /
SECURITY-spec Phase 3.

---

## Roadmap

- [x] **Phase 1** — Proof of Concept: WebRTC connection via word-code signaling, text messaging
- [ ] **Phase 2** — QR pairing, reconnection, RTT display, clipboard persistence
- [ ] **Phase 3** — File transfer: chunked, drag-and-drop, progress
- [ ] **Phase 4** — Polish: mobile layout, keyboard shortcuts, PWA

---

## License

MIT
