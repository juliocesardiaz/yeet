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
8. Direct encrypted DataChannel
```

Pairing is manual: no signaling server, no third-party relay. After the two codes are exchanged, devices communicate directly.

### Word-code format

The offer/answer SDP is stripped to the essentials — DTLS fingerprint, ICE host candidate, setup role — and packed into a compact byte string (ICE credentials are derived deterministically from the fingerprint via SHA-256, so they don't need to be transmitted). The result is optionally deflate-compressed and encoded 12 bits per word against a 4096-word list.

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
├── css/
│   └── style.css
├── js/
│   ├── app.js              # Entry point, pairing state machine
│   ├── rtc.js              # RTCPeerConnection wrapper
│   ├── signaling.js        # SDP ↔ word-code codec
│   ├── wordlist.js         # 4096-word BIP39-style list
│   ├── protocol.js         # Message type constants, JSON codec
│   └── ui.js               # DOM helpers
└── tests/
    ├── test-signaling.mjs  # Node test runner
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
- **No server, no accounts, no cloud** — nothing stored or relayed.
- **No third-party JS dependencies** — only Google Fonts is loaded from a CDN.
- Word codes must be shared over a channel you trust (screen, messaging, voice); an attacker who can inject their own code into that channel can redirect the connection, which is the standard manual-signaling trade-off.

---

## Running Tests

```bash
node --test tests/test-signaling.mjs
```

The in-browser smoke test (`tests/test-connection.html`) can be opened directly in a browser to exercise the RTC stack.

---

## Roadmap

- [x] **Phase 1** — Proof of Concept: WebRTC connection via word-code signaling, text messaging
- [ ] **Phase 2** — QR pairing, reconnection, RTT display, clipboard persistence
- [ ] **Phase 3** — File transfer: chunked, drag-and-drop, progress
- [ ] **Phase 4** — Polish: mobile layout, keyboard shortcuts, PWA

---

## License

MIT
