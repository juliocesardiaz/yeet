import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compress, decompress, deriveCredentials, replaceCredentials, generateNonce, PROTOCOL_VERSION, UnknownVersionError } from '../js/signaling.js';
import { WORDLIST } from '../js/wordlist.js';
import { MSG, encode, decode } from '../js/protocol.js';

// A realistic SDP offer (datachannel, single host candidate)
const SAMPLE_SDP = [
  'v=0',
  'o=- 4811567612290755429 2 IN IP4 127.0.0.1',
  's=-',
  't=0 0',
  'a=group:BUNDLE 0',
  'a=msid-semantic:WMS',
  'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
  'c=IN IP4 0.0.0.0',
  'a=candidate:1 1 UDP 2113937151 192.168.1.42 54321 typ host',
  'a=ice-ufrag:abcd1234',
  'a=ice-pwd:aabbccddee112233445566',
  'a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  'a=setup:actpass',
  'a=mid:0',
  'a=sctp-port:5000',
  '',
].join('\r\n');

// Same SDP with 'active' setup (as an answer would have)
const SAMPLE_ANSWER_SDP = SAMPLE_SDP
  .replace('a=setup:actpass', 'a=setup:active')
  .replace('192.168.1.42', '192.168.1.100')
  .replace('54321', '12345')
  .replace(/AA:BB:CC/g, 'FF:EE:DD');

// --- Wordlist tests ---

describe('wordlist', () => {
  it('has exactly 4096 words', () => {
    assert.equal(WORDLIST.length, 4096);
  });

  it('has no duplicates', () => {
    const unique = new Set(WORDLIST);
    assert.equal(unique.size, 4096, `Found ${4096 - unique.size} duplicates`);
  });

  it('all words are lowercase', () => {
    for (const w of WORDLIST) {
      assert.equal(w, w.toLowerCase(), `Word "${w}" is not lowercase`);
    }
  });
});

// --- Credential derivation tests ---

describe('deriveCredentials', () => {
  it('produces deterministic ufrag and pwd', async () => {
    const fp = new Uint8Array(32).fill(0xAA);
    const cred1 = await deriveCredentials(fp);
    const cred2 = await deriveCredentials(fp);

    assert.equal(cred1.ufrag, cred2.ufrag);
    assert.equal(cred1.pwd, cred2.pwd);
  });

  it('ufrag is >= 4 chars (ICE minimum)', async () => {
    const fp = new Uint8Array(32).fill(0x42);
    const { ufrag } = await deriveCredentials(fp);
    assert.ok(ufrag.length >= 4, `ufrag "${ufrag}" too short`);
  });

  it('pwd is >= 22 chars (ICE minimum)', async () => {
    const fp = new Uint8Array(32).fill(0x42);
    const { pwd } = await deriveCredentials(fp);
    assert.ok(pwd.length >= 22, `pwd "${pwd}" too short`);
  });

  it('different fingerprints produce different credentials', async () => {
    const fp1 = new Uint8Array(32).fill(0x00);
    const fp2 = new Uint8Array(32).fill(0xFF);
    const cred1 = await deriveCredentials(fp1);
    const cred2 = await deriveCredentials(fp2);

    assert.notEqual(cred1.ufrag, cred2.ufrag);
    assert.notEqual(cred1.pwd, cred2.pwd);
  });

  it('ufrag and pwd are valid hex', async () => {
    const fp = new Uint8Array(32).fill(0x55);
    const { ufrag, pwd } = await deriveCredentials(fp);
    assert.match(ufrag, /^[0-9a-f]+$/);
    assert.match(pwd, /^[0-9a-f]+$/);
  });
});

// --- replaceCredentials tests ---

describe('replaceCredentials', () => {
  it('replaces ufrag and pwd in SDP', async () => {
    const modified = await replaceCredentials(SAMPLE_SDP);
    assert.ok(!modified.includes('a=ice-ufrag:abcd1234'), 'original ufrag still present');
    assert.ok(!modified.includes('a=ice-pwd:aabbccddee112233445566'), 'original pwd still present');
    assert.ok(modified.includes('a=ice-ufrag:'), 'ufrag line missing');
    assert.ok(modified.includes('a=ice-pwd:'), 'pwd line missing');
  });

  it('preserves fingerprint', async () => {
    const modified = await replaceCredentials(SAMPLE_SDP);
    assert.ok(modified.includes('a=fingerprint:sha-256 AA:BB:CC:DD'));
  });

  it('derived credentials match deriveCredentials output', async () => {
    const fpBytes = new Uint8Array([
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ]);
    const expected = await deriveCredentials(fpBytes);
    const modified = await replaceCredentials(SAMPLE_SDP);
    assert.ok(modified.includes('a=ice-ufrag:' + expected.ufrag));
    assert.ok(modified.includes('a=ice-pwd:' + expected.pwd));
  });

  it('returns SDP unchanged if no fingerprint', async () => {
    const noFp = 'v=0\r\na=ice-ufrag:test\r\na=ice-pwd:test\r\n';
    const result = await replaceCredentials(noFp);
    assert.equal(result, noFp);
  });
});

// --- Compress/decompress roundtrip tests ---

// Fixed nonce for the roundtrip suite — random nonce would make tests
// non-deterministic. Production callers use generateNonce().
const TEST_NONCE = new Uint8Array([0x12, 0x34]);

describe('compress / decompress roundtrip', () => {
  it('roundtrips a sample offer SDP', async () => {
    const words = await compress(SAMPLE_SDP, TEST_NONCE);
    const { sdp: restored, nonce } = await decompress(words);

    // The restored SDP won't be identical (minimal reconstruction),
    // but must preserve the critical fields
    assert.ok(restored.includes('a=fingerprint:sha-256 AA:BB:CC:DD'));
    assert.ok(restored.includes('a=setup:actpass'));
    assert.ok(restored.includes('192.168.1.42'));
    assert.ok(restored.includes('54321'));
    assert.ok(restored.includes('m=application 9 UDP/DTLS/SCTP webrtc-datachannel'));
    assert.deepEqual(Array.from(nonce), Array.from(TEST_NONCE));
  });

  it('roundtrips an answer SDP with active setup', async () => {
    const words = await compress(SAMPLE_ANSWER_SDP, TEST_NONCE);
    const { sdp: restored } = await decompress(words);

    assert.ok(restored.includes('a=setup:active'));
    assert.ok(restored.includes('192.168.1.100'));
    assert.ok(restored.includes('12345'));
  });

  it('produces only valid words from the wordlist', async () => {
    const words = await compress(SAMPLE_SDP, TEST_NONCE);
    const wordSet = new Set(WORDLIST);
    for (const w of words.split(/\s+/)) {
      assert.ok(wordSet.has(w), `"${w}" not in wordlist`);
    }
  });

  it('produces ≤ 30 words per code', async () => {
    const words = await compress(SAMPLE_SDP, TEST_NONCE);
    const count = words.split(/\s+/).length;
    assert.ok(count <= 30, `Expected ≤ 30 words, got ${count}`);
  });

  it('reconstructed SDP has derived ICE credentials', async () => {
    const words = await compress(SAMPLE_SDP, TEST_NONCE);
    const { sdp: restored } = await decompress(words);

    // Credentials should be derived, not the original ones
    assert.ok(!restored.includes('abcd1234'), 'original ufrag leaked through');
    assert.ok(!restored.includes('aabbccddee112233445566'), 'original pwd leaked through');
    assert.ok(restored.includes('a=ice-ufrag:'));
    assert.ok(restored.includes('a=ice-pwd:'));
  });

  it('preserves fingerprint bytes exactly', async () => {
    const words = await compress(SAMPLE_SDP, TEST_NONCE);
    const { sdp: restored } = await decompress(words);

    const fpLine = restored.split('\r\n').find(l => l.startsWith('a=fingerprint:'));
    assert.ok(fpLine);
    assert.ok(fpLine.includes('AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'));
  });

  it('handles SDP with no candidates', async () => {
    const noCandidate = SAMPLE_SDP.replace(/a=candidate:.*\r\n/, '');
    const words = await compress(noCandidate, TEST_NONCE);
    const { sdp: restored } = await decompress(words);

    assert.ok(!restored.includes('a=candidate:'));
    assert.ok(restored.includes('a=fingerprint:sha-256'));
  });

  it('handles passive setup', async () => {
    const passive = SAMPLE_SDP.replace('a=setup:actpass', 'a=setup:passive');
    const words = await compress(passive, TEST_NONCE);
    const { sdp: restored } = await decompress(words);
    assert.ok(restored.includes('a=setup:passive'));
  });

  it('handles srflx candidates', async () => {
    const sdpWithSrflx = SAMPLE_SDP.replace('typ host', 'typ srflx');
    const words = await compress(sdpWithSrflx, TEST_NONCE);
    const { sdp: restored } = await decompress(words);
    // srflx candidates are accepted but reconstructed as host type
    assert.ok(restored.includes('192.168.1.42'));
    assert.ok(restored.includes('54321'));
  });

  it('keeps only the first candidate', async () => {
    const sdpMulti = SAMPLE_SDP.replace(
      'a=candidate:1 1 UDP 2113937151 192.168.1.42 54321 typ host',
      'a=candidate:1 1 UDP 2113937151 192.168.1.42 54321 typ host\r\n' +
      'a=candidate:2 1 UDP 2113937150 10.0.0.1 9999 typ host'
    );
    const words = await compress(sdpMulti, TEST_NONCE);
    const { sdp: restored } = await decompress(words);

    assert.ok(restored.includes('192.168.1.42'));
    assert.ok(!restored.includes('10.0.0.1'), 'second candidate should be dropped');
  });

  it('round-trips the nonce verbatim', async () => {
    for (const n of [[0x00, 0x00], [0xFF, 0xFF], [0xAB, 0xCD]]) {
      const words = await compress(SAMPLE_SDP, new Uint8Array(n));
      const { nonce } = await decompress(words);
      assert.deepEqual(Array.from(nonce), n);
    }
  });

  it('rejects unknown version bytes with UnknownVersionError', async () => {
    const words = await compress(SAMPLE_SDP, TEST_NONCE);
    // Mutate the encoded bytes to flip the version byte to 0x99.
    // Easiest path: re-encode with a tampered first byte using internal-shape
    // knowledge. We just call the API and corrupt the first byte of the
    // packed payload by hand-decoding and re-encoding.
    // (Use the public bytes round-trip via wordsToBytes is internal, so we
    // test by constructing a minimal packed payload directly.)
    const bad = new Uint8Array(36);
    bad[0] = 0x99; // bogus version
    // remaining bytes can be anything
    const { bytesToWords } = await import('../js/signaling-internals-for-tests.mjs').catch(() => ({}));
    if (bytesToWords) {
      const w = bytesToWords(bad, false);
      await assert.rejects(() => decompress(w), UnknownVersionError);
    } else {
      // signaling.js doesn't export internals — synthesize via header word.
      // Header word: deflate=0, length=36 -> raw index 36.
      // Body words: 36 bytes = 288 bits / 12 = 24 words.
      const headerIdx = 36; // raw, length=36
      let bits = '';
      for (const b of bad) bits += b.toString(2).padStart(8, '0');
      const wordIndices = [headerIdx];
      for (let i = 0; i < bits.length; i += 12) {
        const chunk = bits.slice(i, i + 12).padEnd(12, '0');
        wordIndices.push(parseInt(chunk, 2));
      }
      const sentence = wordIndices.map((idx) => WORDLIST[idx]).join(' ');
      await assert.rejects(() => decompress(sentence), UnknownVersionError);
    }
  });

  it('PROTOCOL_VERSION is 0x01 for v1', () => {
    assert.equal(PROTOCOL_VERSION, 0x01);
  });
});

// --- Protocol tests ---

describe('protocol', () => {
  it('encode/decode HELLO roundtrip', () => {
    const msg = encode(MSG.HELLO, { name: 'Onyx' });
    const decoded = decode(msg);

    assert.equal(decoded.t, MSG.HELLO);
    assert.equal(decoded.name, 'Onyx');
    assert.equal(typeof decoded.ts, 'number');
  });

  it('encode/decode CLIPBOARD roundtrip', () => {
    const msg = encode(MSG.CLIPBOARD, { content: 'hello world' });
    const decoded = decode(msg);

    assert.equal(decoded.t, MSG.CLIPBOARD);
    assert.equal(decoded.content, 'hello world');
  });

  it('handles unicode content', () => {
    const msg = encode(MSG.CLIPBOARD, { content: '🚀 hello 世界' });
    const decoded = decode(msg);
    assert.equal(decoded.content, '🚀 hello 世界');
  });
});

// --- Edge case tests ---

describe('edge cases', () => {
  it('decompress rejects empty string', async () => {
    await assert.rejects(() => decompress(''), /too few words/);
  });

  it('decompress rejects single word', async () => {
    await assert.rejects(() => decompress('abandon'), /too few words/);
  });

  it('decompress rejects unknown words', async () => {
    await assert.rejects(() => decompress('xyzzy plugh'), /Unknown word/);
  });

  it('compress/decompress is case insensitive on input', async () => {
    const words = await compress(SAMPLE_SDP, TEST_NONCE);
    const upper = words.toUpperCase();
    const { sdp: restored } = await decompress(upper);
    assert.ok(restored.includes('a=fingerprint:sha-256'));
  });
});

// --- Candidate filtering tests ---

describe('candidate filtering', () => {
  it('drops IPv6 host candidates instead of corrupting them', async () => {
    const v6 = SAMPLE_SDP.replace(
      'a=candidate:1 1 UDP 2113937151 192.168.1.42 54321 typ host',
      'a=candidate:1 1 UDP 2113937151 fe80::1 54321 typ host'
    );
    const words = await compress(v6, TEST_NONCE);
    const { sdp: restored } = await decompress(words);
    assert.ok(!restored.includes('a=candidate:'), 'IPv6 candidate should be dropped, not packed');
    assert.ok(!restored.includes('fe80'), 'IPv6 address must not survive the codec');
  });

  it('drops hostname (mDNS) candidates', async () => {
    const mdns = SAMPLE_SDP.replace(
      '192.168.1.42',
      'abcd-ef01-2345.local'
    );
    const words = await compress(mdns, TEST_NONCE);
    const { sdp: restored } = await decompress(words);
    assert.ok(!restored.includes('a=candidate:'));
  });

  it('drops candidates with out-of-range octets', async () => {
    const bad = SAMPLE_SDP.replace('192.168.1.42', '300.168.1.42');
    const words = await compress(bad, TEST_NONCE);
    const { sdp: restored } = await decompress(words);
    assert.ok(!restored.includes('a=candidate:'));
  });

  it('keeps IPv4 alongside a dropped IPv6 candidate', async () => {
    const mixed = SAMPLE_SDP.replace(
      'a=candidate:1 1 UDP 2113937151 192.168.1.42 54321 typ host',
      'a=candidate:1 1 UDP 2113937151 fe80::1 54321 typ host\r\n' +
      'a=candidate:2 1 UDP 2113937150 10.0.0.5 5555 typ host'
    );
    const words = await compress(mixed, TEST_NONCE);
    const { sdp: restored } = await decompress(words);
    assert.ok(restored.includes('10.0.0.5'));
    assert.ok(restored.includes('5555'));
  });
});

// --- Fingerprint algorithm guard ---

describe('fingerprint algorithm', () => {
  it('rejects non-sha-256 fingerprints rather than truncating', async () => {
    const sha384 = SAMPLE_SDP.replace('a=fingerprint:sha-256', 'a=fingerprint:sha-384');
    await assert.rejects(() => compress(sha384, TEST_NONCE), /unsupported fingerprint algorithm/);
  });

  it('replaceCredentials handles any algorithm string', async () => {
    // replaceCredentials shouldn't care about the algo — it only needs the bytes.
    const sha384 = SAMPLE_SDP.replace('a=fingerprint:sha-256', 'a=fingerprint:sha-384');
    const result = await replaceCredentials(sha384);
    assert.ok(!result.includes('a=ice-ufrag:abcd1234'));
    assert.ok(result.includes('a=ice-ufrag:'));
  });
});

// --- Deflate-path coverage ---

describe('deflate path', () => {
  // Build an SDP whose packed form (after header + 32-byte fp + 6-byte candidate)
  // has enough redundancy that deflate actually wins. A repeated-byte fingerprint
  // is the easiest way to force that.
  function sdpWithRepeatingFp() {
    const byte = 'AA';
    const fp = Array(32).fill(byte).join(':');
    return SAMPLE_SDP.replace(
      /a=fingerprint:sha-256 [0-9A-F:]+/,
      'a=fingerprint:sha-256 ' + fp
    );
  }

  it('selects the deflate encoding when it is shorter', async () => {
    const words = await compress(sdpWithRepeatingFp(), TEST_NONCE);
    // Header word (index 0) has bit 11 set when deflate path is used.
    const firstWord = words.split(/\s+/)[0];
    const headerIdx = WORDLIST.indexOf(firstWord);
    assert.ok(headerIdx >= 0, 'header word must be in wordlist');
    assert.ok(headerIdx & 0x800, 'deflate flag bit must be set on a redundant payload');
  });

  it('deflate-encoded payload still roundtrips', async () => {
    const sdp = sdpWithRepeatingFp();
    const words = await compress(sdp, TEST_NONCE);
    const { sdp: restored } = await decompress(words);
    assert.ok(restored.includes('a=fingerprint:sha-256 AA:AA:AA'));
    assert.ok(restored.includes('192.168.1.42'));
  });

  it('raw path used when deflate would be larger', async () => {
    // 32 distinct bytes — deflate-raw overhead exceeds any savings, so the
    // codec must pick the raw path.
    const fp = Array.from({ length: 32 }, (_, i) => (i * 17 + 3).toString(16).padStart(2, '0').toUpperCase().slice(-2));
    // Disambiguate by salting every byte through a rough pseudo-random function.
    for (let i = 0; i < 32; i++) {
      const v = ((i * 2654435761) >>> 0) & 0xFF;
      fp[i] = v.toString(16).padStart(2, '0').toUpperCase();
    }
    const sdp = SAMPLE_SDP.replace(
      /a=fingerprint:sha-256 [0-9A-F:]+/,
      'a=fingerprint:sha-256 ' + fp.join(':')
    );
    const words = await compress(sdp, TEST_NONCE);
    const firstWord = words.split(/\s+/)[0];
    const headerIdx = WORDLIST.indexOf(firstWord);
    assert.equal(headerIdx & 0x800, 0, 'deflate flag should not be set on incompressible input');
  });
});

// --- Nonce generator ---

describe('generateNonce', () => {
  it('returns a 2-byte Uint8Array', () => {
    const n = generateNonce();
    assert.ok(n instanceof Uint8Array);
    assert.equal(n.length, 2);
  });

  it('produces different values across calls (probabilistically)', () => {
    const seen = new Set();
    for (let i = 0; i < 50; i++) {
      const n = generateNonce();
      seen.add((n[0] << 8) | n[1]);
    }
    assert.ok(seen.size > 1, 'generateNonce should not be constant');
  });
});
