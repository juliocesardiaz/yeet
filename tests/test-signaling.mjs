import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compress, decompress, deriveCredentials, replaceCredentials } from '../js/signaling.js';
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

describe('compress / decompress roundtrip', () => {
  it('roundtrips a sample offer SDP', async () => {
    const words = await compress(SAMPLE_SDP);
    const restored = await decompress(words);

    // The restored SDP won't be identical (minimal reconstruction),
    // but must preserve the critical fields
    assert.ok(restored.includes('a=fingerprint:sha-256 AA:BB:CC:DD'));
    assert.ok(restored.includes('a=setup:actpass'));
    assert.ok(restored.includes('192.168.1.42'));
    assert.ok(restored.includes('54321'));
    assert.ok(restored.includes('m=application 9 UDP/DTLS/SCTP webrtc-datachannel'));
  });

  it('roundtrips an answer SDP with active setup', async () => {
    const words = await compress(SAMPLE_ANSWER_SDP);
    const restored = await decompress(words);

    assert.ok(restored.includes('a=setup:active'));
    assert.ok(restored.includes('192.168.1.100'));
    assert.ok(restored.includes('12345'));
  });

  it('produces only valid words from the wordlist', async () => {
    const words = await compress(SAMPLE_SDP);
    const wordSet = new Set(WORDLIST);
    for (const w of words.split(/\s+/)) {
      assert.ok(wordSet.has(w), `"${w}" not in wordlist`);
    }
  });

  it('produces ≤ 30 words per code', async () => {
    const words = await compress(SAMPLE_SDP);
    const count = words.split(/\s+/).length;
    assert.ok(count <= 30, `Expected ≤ 30 words, got ${count}`);
  });

  it('reconstructed SDP has derived ICE credentials', async () => {
    const words = await compress(SAMPLE_SDP);
    const restored = await decompress(words);

    // Credentials should be derived, not the original ones
    assert.ok(!restored.includes('abcd1234'), 'original ufrag leaked through');
    assert.ok(!restored.includes('aabbccddee112233445566'), 'original pwd leaked through');
    assert.ok(restored.includes('a=ice-ufrag:'));
    assert.ok(restored.includes('a=ice-pwd:'));
  });

  it('preserves fingerprint bytes exactly', async () => {
    const words = await compress(SAMPLE_SDP);
    const restored = await decompress(words);

    const fpLine = restored.split('\r\n').find(l => l.startsWith('a=fingerprint:'));
    assert.ok(fpLine);
    assert.ok(fpLine.includes('AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'));
  });

  it('handles SDP with no candidates', async () => {
    const noCandidate = SAMPLE_SDP.replace(/a=candidate:.*\r\n/, '');
    const words = await compress(noCandidate);
    const restored = await decompress(words);

    assert.ok(!restored.includes('a=candidate:'));
    assert.ok(restored.includes('a=fingerprint:sha-256'));
  });

  it('handles passive setup', async () => {
    const passive = SAMPLE_SDP.replace('a=setup:actpass', 'a=setup:passive');
    const words = await compress(passive);
    const restored = await decompress(words);
    assert.ok(restored.includes('a=setup:passive'));
  });

  it('handles srflx candidates', async () => {
    const sdpWithSrflx = SAMPLE_SDP.replace('typ host', 'typ srflx');
    const words = await compress(sdpWithSrflx);
    const restored = await decompress(words);
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
    const words = await compress(sdpMulti);
    const restored = await decompress(words);

    assert.ok(restored.includes('192.168.1.42'));
    assert.ok(!restored.includes('10.0.0.1'), 'second candidate should be dropped');
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

  it('encode/decode DISCONNECT', () => {
    const msg = encode(MSG.DISCONNECT);
    const decoded = decode(msg);
    assert.equal(decoded.t, MSG.DISCONNECT);
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
    const words = await compress(SAMPLE_SDP);
    const upper = words.toUpperCase();
    const restored = await decompress(upper);
    assert.ok(restored.includes('a=fingerprint:sha-256'));
  });
});
