// SAS vector test — the contract that prevents silent cross-browser
// divergence in HKDF inputs, byte ordering, or bit extraction.
//
// Vectors at tests/sas-vectors.json are hand-computed from the spec
// (HKDF-SHA256 over canonical fp_lo||fp_hi with info "YEET-SAS-v1"||nonce,
// L = 24 bits, low 20 bits -> 6-digit zero-padded decimal "XXX XXX") and
// independently cross-verified against Node's crypto.hkdfSync.
//
// If a future change requires updating the vectors, that PR must:
//   1. Bump PROTOCOL_VERSION in js/signaling.js.
//   2. Justify the change in the PR description.
//   3. Retain the old vectors as tests/sas-vectors-v1.json if backward
//      parsing is ever supported.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { computeSAS, parseHexFingerprint } from '../js/sas.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(resolve(__dirname, 'sas-vectors.json'), 'utf8'),
);

function nonceFromHex(hex) {
  return new Uint8Array([
    parseInt(hex.slice(0, 2), 16),
    parseInt(hex.slice(2, 4), 16),
  ]);
}

describe('SAS vectors', () => {
  for (const v of vectors) {
    it(v.name, async () => {
      const sas = await computeSAS(v.fp_a, v.fp_b, nonceFromHex(v.nonce_hex));
      assert.equal(sas, v.expected_sas);
    });
  }

  it('canonicalization is order-independent (computeSAS(a,b) === computeSAS(b,a))', async () => {
    for (const v of vectors) {
      const fwd = await computeSAS(v.fp_a, v.fp_b, nonceFromHex(v.nonce_hex));
      const rev = await computeSAS(v.fp_b, v.fp_a, nonceFromHex(v.nonce_hex));
      assert.equal(fwd, rev, v.name);
    }
  });
});

describe('parseHexFingerprint', () => {
  it('accepts colon-separated upper-case hex (the SDP form)', () => {
    const bytes = parseHexFingerprint('AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89');
    assert.equal(bytes.length, 32);
    assert.equal(bytes[0], 0xAB);
    assert.equal(bytes[31], 0x89);
  });

  it('accepts lowercase, hyphenated, or unseparated forms', () => {
    const same = [
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef',
      '01-23-45-67-89-AB-CD-EF-01-23-45-67-89-AB-CD-EF-01-23-45-67-89-AB-CD-EF-01-23-45-67-89-AB-CD-EF',
    ].map(parseHexFingerprint);
    assert.deepEqual(Array.from(same[0]), Array.from(same[1]));
    assert.deepEqual(Array.from(same[1]), Array.from(same[2]));
  });

  it('rejects wrong length', () => {
    assert.throws(() => parseHexFingerprint('AB:CD'), /must be 32 bytes/);
  });

  it('rejects non-hex characters', () => {
    const bad = 'ZZ' + 'AB'.repeat(31);
    assert.throws(() => parseHexFingerprint(bad), /non-hex/);
  });
});

describe('computeSAS guards', () => {
  it('aborts on identical fingerprints (bug or replay attack)', async () => {
    const fp = '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF';
    await assert.rejects(
      () => computeSAS(fp, fp, new Uint8Array([0, 0])),
      /identical fingerprints/,
    );
  });

  it('rejects malformed nonce', async () => {
    const a = '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF';
    const b = 'FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00';
    await assert.rejects(() => computeSAS(a, b, new Uint8Array(1)), /nonce/);
    await assert.rejects(() => computeSAS(a, b, new Uint8Array(3)), /nonce/);
    await assert.rejects(() => computeSAS(a, b, [0, 0]), /nonce/);
  });

  it('SAS output is "XXX XXX" — 7 chars, digits and one space', async () => {
    for (const v of vectors) {
      const sas = await computeSAS(v.fp_a, v.fp_b, nonceFromHex(v.nonce_hex));
      assert.match(sas, /^\d{3} \d{3}$/);
    }
  });
});
