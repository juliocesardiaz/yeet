import { WORDLIST } from './wordlist.js';

// Build reverse lookup once
const WORD_INDEX = new Map(WORDLIST.map((w, i) => [w, i]));

// --- Public API (same interface as before) ---

export async function compress(sdpString) {
  const fields = extractSDP(sdpString);
  const bytes = packSDP(fields);
  return bytesToWords(bytes);
}

export async function decompress(wordString) {
  const bytes = wordsToBytes(wordString);
  const fields = unpackSDP(bytes);
  return reconstructSDP(fields);
}

// --- SDP Extraction ---

function extractSDP(sdp) {
  const lines = sdp.split(/\r?\n/);
  const fields = {
    type: '',       // 'offer' or 'answer'
    ufrag: '',
    pwd: '',
    fingerprint: '', // hex string like "AA:BB:CC:..."
    setup: '',       // 'actpass', 'active', 'passive'
    candidates: [],  // [{ ip, port, priority, foundation, component, transport }]
  };

  // Detect type from SDP content
  fields.type = sdp.includes('a=setup:actpass') ? 'offer' : 'answer';

  for (const line of lines) {
    if (line.startsWith('a=ice-ufrag:')) {
      fields.ufrag = line.slice('a=ice-ufrag:'.length);
    } else if (line.startsWith('a=ice-pwd:')) {
      fields.pwd = line.slice('a=ice-pwd:'.length);
    } else if (line.startsWith('a=fingerprint:')) {
      // "a=fingerprint:sha-256 AA:BB:CC:..."
      fields.fingerprint = line.slice('a=fingerprint:'.length);
    } else if (line.startsWith('a=setup:')) {
      fields.setup = line.slice('a=setup:'.length);
    } else if (line.startsWith('a=candidate:')) {
      const candidate = parseCandidate(line);
      if (candidate) fields.candidates.push(candidate);
    }
  }

  return fields;
}

function parseCandidate(line) {
  // a=candidate:foundation component transport priority ip port typ type ...
  const parts = line.slice('a=candidate:'.length).split(/\s+/);
  if (parts.length < 7) return null;

  return {
    foundation: parts[0],
    component: parts[1],
    transport: parts[2].toUpperCase(),
    priority: parts[3],
    ip: parts[4],
    port: parseInt(parts[5], 10),
    type: parts[7] || 'host', // after 'typ'
  };
}

// --- SDP Reconstruction ---

function reconstructSDP(fields) {
  const lines = [
    'v=0',
    'o=- 0 0 IN IP4 127.0.0.1',
    's=-',
    't=0 0',
    'a=group:BUNDLE 0',
    'a=msid-semantic:WMS',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
    'c=IN IP4 0.0.0.0',
  ];

  // Add candidates
  for (const c of fields.candidates) {
    lines.push(`a=candidate:${c.foundation} ${c.component} ${c.transport} ${c.priority} ${c.ip} ${c.port} typ ${c.type}`);
  }

  lines.push('a=ice-ufrag:' + fields.ufrag);
  lines.push('a=ice-pwd:' + fields.pwd);
  lines.push('a=fingerprint:' + fields.fingerprint);
  lines.push('a=setup:' + fields.setup);
  lines.push('a=mid:0');
  lines.push('a=sctp-port:5000');
  lines.push('');

  return lines.join('\r\n');
}

// --- Binary Packing ---
// Format:
//   [version:1] [flags:1] [ufrag_len:1] [ufrag...] [pwd_len:1] [pwd...]
//   [fingerprint_raw:32] [setup:1] [candidate_count:1]
//   per candidate: [foundation_len:1] [foundation...] [component:1] [transport:1]
//                  [priority:4 BE] [ip:4] [port:2 BE] [type:1]

const TRANSPORT_MAP = { 'UDP': 0, 'TCP': 1 };
const TRANSPORT_UNMAP = ['UDP', 'TCP'];
const TYPE_MAP = { 'host': 0, 'srflx': 1, 'prflx': 2, 'relay': 3 };
const TYPE_UNMAP = ['host', 'srflx', 'prflx', 'relay'];
const SETUP_MAP = { 'actpass': 0, 'active': 1, 'passive': 2 };
const SETUP_UNMAP = ['actpass', 'active', 'passive'];

function packSDP(fields) {
  const parts = [];

  // Version
  parts.push(0x01);

  // Ufrag (length-prefixed)
  const ufragBytes = new TextEncoder().encode(fields.ufrag);
  parts.push(ufragBytes.length);
  for (const b of ufragBytes) parts.push(b);

  // Pwd (length-prefixed)
  const pwdBytes = new TextEncoder().encode(fields.pwd);
  parts.push(pwdBytes.length);
  for (const b of pwdBytes) parts.push(b);

  // Fingerprint — stored as the full string "sha-256 AA:BB:..." length-prefixed
  const fpBytes = new TextEncoder().encode(fields.fingerprint);
  // Use 2 bytes for length since fingerprint string can be >127
  parts.push((fpBytes.length >> 8) & 0xFF);
  parts.push(fpBytes.length & 0xFF);
  for (const b of fpBytes) parts.push(b);

  // Setup
  parts.push(SETUP_MAP[fields.setup] ?? 0);

  // Candidates
  parts.push(fields.candidates.length);
  for (const c of fields.candidates) {
    // Foundation (length-prefixed)
    const foundBytes = new TextEncoder().encode(c.foundation);
    parts.push(foundBytes.length);
    for (const b of foundBytes) parts.push(b);

    // Component
    parts.push(parseInt(c.component, 10));

    // Transport
    parts.push(TRANSPORT_MAP[c.transport] ?? 0);

    // Priority (4 bytes big-endian)
    const pri = parseInt(c.priority, 10);
    parts.push((pri >>> 24) & 0xFF);
    parts.push((pri >>> 16) & 0xFF);
    parts.push((pri >>> 8) & 0xFF);
    parts.push(pri & 0xFF);

    // IP (4 bytes for IPv4)
    const ipParts = c.ip.split('.').map(Number);
    for (const b of ipParts) parts.push(b);

    // Port (2 bytes big-endian)
    parts.push((c.port >> 8) & 0xFF);
    parts.push(c.port & 0xFF);

    // Type
    parts.push(TYPE_MAP[c.type] ?? 0);
  }

  return new Uint8Array(parts);
}

function unpackSDP(bytes) {
  let i = 0;
  const read = (n) => { const s = bytes.slice(i, i + n); i += n; return s; };
  const readByte = () => bytes[i++];

  const version = readByte(); // 0x01

  // Ufrag
  const ufragLen = readByte();
  const ufrag = new TextDecoder().decode(read(ufragLen));

  // Pwd
  const pwdLen = readByte();
  const pwd = new TextDecoder().decode(read(pwdLen));

  // Fingerprint (2-byte length)
  const fpLenHi = readByte();
  const fpLenLo = readByte();
  const fpLen = (fpLenHi << 8) | fpLenLo;
  const fingerprint = new TextDecoder().decode(read(fpLen));

  // Setup
  const setup = SETUP_UNMAP[readByte()] || 'actpass';

  // Candidates
  const candidateCount = readByte();
  const candidates = [];
  for (let c = 0; c < candidateCount; c++) {
    const foundLen = readByte();
    const foundation = new TextDecoder().decode(read(foundLen));
    const component = String(readByte());
    const transport = TRANSPORT_UNMAP[readByte()] || 'UDP';

    const pri = (readByte() << 24 | readByte() << 16 | readByte() << 8 | readByte()) >>> 0;
    const priority = String(pri);

    const ip = `${readByte()}.${readByte()}.${readByte()}.${readByte()}`;
    const port = (readByte() << 8) | readByte();
    const type = TYPE_UNMAP[readByte()] || 'host';

    candidates.push({ foundation, component, transport, priority, ip, port, type });
  }

  return { ufrag, pwd, fingerprint, setup, candidates };
}

// --- Word Encoding (11 bits per word, BIP39-style) ---

function bytesToWords(bytes) {
  // Convert bytes to bit string
  let bits = '';
  for (const b of bytes) {
    bits += b.toString(2).padStart(8, '0');
  }

  // Encode total byte count in the first word (so we know how many bits are payload)
  const words = [WORDLIST[bytes.length]]; // length word (max 2047 bytes, fits in 11 bits)

  // Chunk remaining bits into 11-bit groups
  for (let i = 0; i < bits.length; i += 11) {
    const chunk = bits.slice(i, i + 11).padEnd(11, '0');
    const index = parseInt(chunk, 2);
    words.push(WORDLIST[index]);
  }

  return words.join(' ');
}

function wordsToBytes(wordString) {
  const words = wordString.trim().toLowerCase().split(/\s+/);
  if (words.length < 2) throw new Error('Invalid code: too few words');

  // First word encodes the byte length
  const lengthWord = words[0];
  const totalBytes = WORD_INDEX.get(lengthWord);
  if (totalBytes === undefined) throw new Error(`Unknown word: "${lengthWord}"`);

  // Remaining words encode the data
  let bits = '';
  for (let i = 1; i < words.length; i++) {
    const idx = WORD_INDEX.get(words[i]);
    if (idx === undefined) throw new Error(`Unknown word: "${words[i]}"`);
    bits += idx.toString(2).padStart(11, '0');
  }

  // Convert bits back to bytes, using totalBytes to know exact length
  const result = new Uint8Array(totalBytes);
  for (let i = 0; i < totalBytes; i++) {
    result[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }

  return result;
}
