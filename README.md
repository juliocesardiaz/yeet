# YEET

**Local P2P File Transfer & Shared Clipboard**

A static web app that connects two devices on the same network for peer-to-peer file transfer and a shared clipboard — no accounts, no central server, no cloud. Open the site on both devices, pair via QR code, and start moving things between them.

---

## Why YEET?

- **Zero install** — runs in any modern browser
- **Zero server** — static HTML/JS hosted on GitHub Pages
- **Zero accounts** — ephemeral sessions, no sign-up
- **Zero cloud** — data never leaves your local network
- **Encrypted** — WebRTC DTLS encryption on all traffic

The tool you leave open in a browser tab all day. The shared clipboard is the main draw — quick text/snippet sharing between devices while working with LLMs, coding, or reading. File transfer is the secondary power feature.

---

## How It Works

```
Device A (Initiator)                Device B (Joiner)
────────────────────                ─────────────────
1. Click "Create Room"
2. Generate WebRTC offer
3. Display offer as QR code
                                    4. Scan QR with camera
                                    5. Generate WebRTC answer
                                    6. Display answer as QR
7. Scan answer QR
8. P2P data channel established
   ─── Direct encrypted connection ───
```

Pairing uses **QR-based manual signaling** — no WebSocket server, no third-party relay. After the two-scan handshake, devices communicate directly over **WebRTC DataChannels** with built-in DTLS encryption.

---

## Features

### Shared Clipboard (Primary)

A synchronized scratchpad between two devices.

- **Send text** — type or paste, hit Send (or `Ctrl+Enter`)
- **Live feed** — snippets appear as cards on both devices in reverse-chronological order
- **Card details** — content preview, timestamp, source device indicator
- **Copy button** — one-click copy to OS clipboard
- **Expand** — click a card to see full content
- **Local persistence** — clipboard history saved to IndexedDB across browser sessions

### File Transfer

- **Drag-and-drop** or file picker
- **Chunked transfer** over WebRTC data channel with progress bar and speed indicator
- **Accept/reject** incoming files (or auto-accept toggle)
- **Transfer queue** — multiple files with individual progress tracking
- **Download** received files via browser download dialog

### Connection & Identity

- **Ephemeral device names** — auto-generated on page load (e.g., "Onyx", "Slate", "Neon")
- **Connection quality** — latency ping with RTT display
- **Clean disconnect** — button to close the session
- **Reconnect** — repeat the QR flow if the connection drops

---

## Tech Stack

| Layer | Choice |
|---|---|
| Frontend | Vanilla JS (ES modules) — no build step |
| Styling | Hand-written CSS with custom properties |
| WebRTC | Native browser API (`RTCPeerConnection`, `RTCDataChannel`) |
| QR generation | `qrcode` (~30KB) |
| QR scanning | `jsQR` + `getUserMedia` (~30KB) |
| Compression | `lz-string` (~5KB) — compress SDP for QR encoding |
| Storage | IndexedDB — clipboard history persistence |
| Hosting | GitHub Pages — free, static, HTTPS |
| Build | None — just files |

**Total external dependencies: ~3 libraries, <100KB.**

---

## Project Structure

```
yeet/
├── index.html              # Single page app
├── css/
│   └── style.css           # All styles, CSS custom properties
├── js/
│   ├── app.js              # Entry point, view routing
│   ├── rtc.js              # WebRTC connection management
│   ├── signaling.js        # QR-based signaling logic
│   ├── clipboard.js        # Clipboard tab logic
│   ├── transfer.js         # File transfer tab logic
│   ├── protocol.js         # Message encoding/decoding
│   ├── storage.js          # IndexedDB wrapper
│   └── ui.js               # DOM manipulation helpers
├── lib/
│   ├── qrcode.min.js       # QR generation
│   ├── jsqr.min.js         # QR scanning
│   └── lz-string.min.js    # Compression
├── assets/
│   └── fonts/              # IBM Plex Mono (self-hosted)
└── README.md
```

---

## Data Protocol

Messages over the WebRTC data channel use a simple JSON protocol:

```json
{ "type": "clipboard",      "id": "...", "content": "...", "timestamp": 0 }
{ "type": "file-meta",      "id": "...", "name": "...", "size": 0, "mimeType": "...", "chunks": 0 }
{ "type": "file-chunk",     "id": "...", "index": 0, "data": "..." }
{ "type": "file-complete",  "id": "..." }
{ "type": "ping" }
{ "type": "pong" }
{ "type": "disconnect" }
```

Files are chunked (64KB default) and sent sequentially with progress tracking and backpressure handling.

---

## Security

- **No server, no cloud, no accounts** — nothing to breach
- **WebRTC DTLS encryption** on all data channel traffic
- **No signaling server metadata** — QR-based pairing, no third party sees connections
- **Ephemeral sessions** — nothing persists on any server
- **CSP headers** to prevent XSS
- **Subresource Integrity** on external scripts
- **Camera released** immediately after pairing
- **No analytics, no tracking, no cookies**

---

## Differentiation

| Tool | Limitation |
|---|---|
| AirDrop | Apple only |
| Snapdrop / Pairdrop | Requires central signaling server |
| LocalSend | Requires native app install |
| KDE Connect | Native app, Linux/Android focused |
| Pushbullet / Join | Cloud-synced, account required |

**YEET** is the only browser-based, zero-server, zero-install, local P2P transfer tool with a first-class shared clipboard for LLM/coding workflows.

---

## Roadmap

- [x] **Phase 1** — Proof of Concept: WebRTC connection via QR signaling
- [ ] **Phase 2** — Clipboard MVP: send/receive text snippets, feed UI, dark theme
- [ ] **Phase 3** — File Transfer MVP: chunked transfer, progress bars, drag-and-drop
- [ ] **Phase 4** — Polish: persistence, pinning, tags, search, mobile layout, reconnection
- [ ] **Phase 5** — Advanced: keyboard shortcuts, code extraction, folder transfer, PWA, E2E encryption

---

## Design

Utilitarian brutalism with a warm edge.

- **Font**: IBM Plex Mono
- **Background**: Near-black (`#0a0a0a`)
- **Accent**: Single strong color (electric amber / terminal green)
- **Layout**: Two-column desktop (clipboard + files), tabbed mobile
- **Motion**: Minimal — subtle fades, progress bars only
- **Edges**: Sharp, 1px borders, no rounded corners

---

## License

MIT
