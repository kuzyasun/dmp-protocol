/* Independent FRAG_STATUS header/AAD/ciphertext check. Node crypto only.
 * Not a DMP endpoint and not the P16 encoder. Public fixtures only.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

const root = path.join(__dirname, '..');
const recovery = JSON.parse(fs.readFileSync(path.join(root, 'docs/DMP_v2_Recovery_Test_Vectors.json')));
const security = JSON.parse(fs.readFileSync(path.join(root, 'docs/DMP_v2_Security_Test_Vectors.json')));
const suite = security.vectors.find(item => item.protocol_name === 'Noise_NNpsk0_25519_ChaChaPoly_SHA256');
const label = Buffer.from('DMP2-SEC1-DATA');
const illustrative = '480ac109010107050105';

assert.equal(recovery.specification, 'DMP v2 revision 10 / SEC-1 revision 5 / SELECTIVE-32 revision 1');
assert.equal(recovery.supported_suite.cipher, 1);
assert.equal(recovery.supported_suite.protocol_name, suite.protocol_name);
assert.match(recovery.supported_suite.excluded, /Cipher 2/);
assert.equal(recovery.provenance.not_produced_by, 'src/reliability and dmp_core_encode');
assert.equal(recovery.association.handshake_hash, suite.handshake_hash);
assert.equal(recovery.association.handshake_hash, 'a786c7e69cf80b08aafd8d20bcc5efc4fa30968643fa49ae1ad8452cf99844cf');
assert.equal(recovery.association.key, suite.r_to_i_key);
assert.equal(recovery.association.responder_epoch, suite.origin_epochs[1]);
assert.equal(recovery.illustrative_header.header, illustrative);
assert.equal(recovery.illustrative_header.plaintext, '44000000');
assert.equal(recovery.illustrative_header.complete_frame, false);
const ready = suite.packets.find(packet => packet.name === 'ready');
assert.equal(ready.header, '43074100010700');
assert.equal(suite.packets.find(packet => packet.name === 'routed_request').header.startsWith('4018c702310a14'), true);

const key = Buffer.from(recovery.association.key, 'hex');
const handshake = Buffer.from(recovery.association.handshake_hash, 'hex');

function uleb(value) {
  let rest = BigInt(value);
  const out = [];
  while (rest >= 128n) {
    out.push(Number((rest & 127n) | 128n));
    rest >>= 7n;
  }
  out.push(Number(rest));
  return Buffer.from(out);
}

function ext(id, value, unsafe = false) {
  const tag = (id << 2) | (unsafe ? 2 : 0) | 1;
  return Buffer.concat([uleb(tag), uleb(value.length), value]);
}

function readUleb(buf, at, bits) {
  let n = 0n;
  let shift = 0n;
  const start = at;
  const maxBytes = Math.ceil(bits / 7);
  for (;;) {
    assert(at < buf.length && at - start < maxBytes, 'truncated integer');
    const byte = buf[at++];
    n |= BigInt(byte & 127) << shift;
    if ((byte & 128) === 0) {
      assert(n < (1n << BigInt(bits)), 'integer overflow');
      let probe = n;
      let width = 1;
      while (probe >= 128n) {
        probe >>= 7n;
        width += 1;
      }
      assert.equal(at - start, width, 'non-minimal integer');
      return {value: n, end: at};
    }
    shift += 7n;
  }
}

function maskAccept(mask, count) {
  if (!Number.isInteger(count) || count < 2 || count > 32) return false;
  if (!Number.isInteger(mask) || mask <= 0 || mask > 0xffffffff) return false;
  if (count < 32 && Math.floor(mask / (2 ** count)) !== 0) return false;
  const every = count === 32 ? 0xffffffff : (2 ** count) - 1;
  return mask !== every;
}

function le32(mask) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(mask >>> 0);
  return out;
}

function build(entry) {
  let extensions = Buffer.alloc(0);
  if (entry.reply === 'compact') extensions = Buffer.concat([extensions, ext(1, uleb(entry.reply_seq))]);
  else if (entry.reply === 'full') {
    const epoch = Buffer.alloc(8);
    epoch.writeBigUInt64LE(BigInt(entry.full_epoch));
    const body = Buffer.concat([uleb(entry.full_namespace), uleb(entry.full_origin), epoch, uleb(entry.reply_seq)]);
    extensions = Buffer.concat([extensions, ext(1, body)]);
  } else if (entry.reply === 'nonminimal') extensions = Buffer.concat([extensions, ext(1, Buffer.from([0x80, 0x00]))]);
  else assert.equal(entry.reply, 'absent');
  if (entry.context_epoch !== null && entry.context_epoch !== undefined) {
    const body = Buffer.concat([uleb(1), Buffer.alloc(8)]);
    body.writeBigUInt64LE(BigInt(entry.context_epoch), 1);
    extensions = Buffer.concat([extensions, ext(2, body, true)]);
  }
  if (entry.service !== null && entry.service !== undefined) {
    extensions = Buffer.concat([extensions, ext(4, uleb(entry.service))]);
  }
  if (entry.status !== null && entry.status !== undefined) {
    extensions = Buffer.concat([extensions, ext(5, uleb(entry.status))]);
  }
  if (entry.freshness) extensions = Buffer.concat([extensions, ext(6, Buffer.alloc(16))]);
  let opts = 1;
  if (entry.ack_req) opts |= 2;
  if (entry.route) opts |= 4;
  if (entry.frag) opts |= 8;
  if (entry.integrity) opts |= 0x10;
  if (entry.payload_desc) opts |= 0x20;
  if (entry.security) opts |= 0x40;
  if (extensions.length) opts |= 0x80;
  let fields = Buffer.concat([Buffer.from([opts]), uleb(entry.seq)]);
  let routeOffset = null;
  if (entry.route) {
    routeOffset = 2 + fields.length;
    const [ttl, source, destination] = entry.route;
    fields = Buffer.concat([fields, Buffer.from([(ttl << 4) | 1]), uleb(source), uleb(destination)]);
  }
  if (entry.frag) fields = Buffer.concat([fields, uleb(entry.frag[0]), uleb(entry.frag[1]), uleb(entry.frag[2])]);
  if (entry.payload_desc) fields = Buffer.concat([fields, Buffer.from([0]), uleb(0)]);
  if (entry.integrity) fields = Buffer.concat([fields, Buffer.from([1])]);
  if (entry.security) fields = Buffer.concat([fields, Buffer.from([entry.cipher]), uleb(entry.cid), uleb(entry.pn)]);
  fields = Buffer.concat([fields, extensions]);
  const header = Buffer.concat([Buffer.from([0x48, fields.length + 2]), fields]);
  let plain;
  if (entry.name === 'payload_short') plain = Buffer.from([0x44, 0x00, 0x00]);
  else if (entry.name === 'payload_long') plain = Buffer.from([0x44, 0x00, 0x00, 0x00, 0xff]);
  else plain = le32(entry.mask);
  return {header, routeOffset, plain};
}

function encrypt(plain, header, routeOffset, pn) {
  const canon = Buffer.from(header);
  if (routeOffset !== null) canon[routeOffset] &= 0x0f;
  const aad = Buffer.concat([label, handshake, canon]);
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64LE(BigInt(pn), 4);
  const enc = crypto.createCipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  enc.setAAD(aad);
  const body = Buffer.concat([enc.update(plain), enc.final()]);
  const tag = enc.getAuthTag();
  const dec = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  dec.setAAD(aad);
  dec.setAuthTag(tag);
  const opened = Buffer.concat([dec.update(body), dec.final()]);
  assert.deepEqual(opened, plain);
  return {aad, nonce, body, tag, frame: Buffer.concat([header, body, tag])};
}

function openAt(frame) {
  const hdr = frame[1];
  assert(hdr >= 4 && hdr < frame.length);
  const opts = frame[2];
  assert(opts & 0x40);
  let at = 3;
  at = readUleb(frame, at, 32).end;
  let routeAt = null;
  if (opts & 4) {
    routeAt = at;
    at += 1;
    at = readUleb(frame, at, 32).end;
    if ((frame[routeAt] & 15) === 1) at = readUleb(frame, at, 32).end;
  }
  if (opts & 8) {
    at = readUleb(frame, at, 32).end;
    at = readUleb(frame, at, 32).end;
    at = readUleb(frame, at, 32).end;
  }
  if (opts & 0x20) {
    at += 1;
    at = readUleb(frame, at, 32).end;
  }
  if (opts & 0x10) at += 1;
  assert.equal(frame[at], 1);
  at += 1;
  at = readUleb(frame, at, 32).end;
  const pn = readUleb(frame, at, 64);
  const canon = Buffer.from(frame.subarray(0, hdr));
  if (routeAt !== null) canon[routeAt] &= 0x0f;
  const aad = Buffer.concat([label, handshake, canon]);
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64LE(pn.value, 4);
  const dec = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  dec.setAAD(aad);
  dec.setAuthTag(frame.subarray(frame.length - 16));
  const plain = Buffer.concat([dec.update(frame.subarray(hdr, frame.length - 16)), dec.final()]);
  return {plain};
}

function decide(entry, plain, aeadValid) {
  if (entry.cipher !== 1) return 'reject_suite';
  if (entry.omit_tag || entry.integrity || entry.ack_req || entry.frag || entry.payload_desc ||
      entry.status !== null || entry.freshness) return 'reject_structure';
  if (entry.reply !== 'compact') return 'reject_reference';
  if (plain.length !== 4) return 'reject_length';
  if (!aeadValid) return 'reject_altered';
  if (entry.pn >= 16777216) return 'reject_pn';
  if (entry.service === 1) return 'reject_role';
  if (!maskAccept(entry.mask, entry.n)) return 'reject_mask';
  return 'accept';
}

const expected = {
  two_of_eight: 'accept', n2_index0: 'accept', n32_index31: 'accept', explicit_service: 'accept',
  routed_return: 'accept', pn_two_byte: 'accept', mask_zero: 'reject_mask', mask_all_n2: 'reject_mask',
  mask_out_of_range_n2: 'reject_mask', mask_all_n32: 'reject_mask', payload_short: 'reject_length',
  payload_long: 'reject_length', explicit_default_service: 'reject_role', pn_at_limit: 'reject_pn',
  missing_reply: 'reject_reference', full_reply: 'reject_reference', nonminimal_reply: 'reject_reference',
  ack_req: 'reject_structure', frag: 'reject_structure', payload_desc: 'reject_structure',
  status_extension: 'reject_structure', freshness_extension: 'reject_structure',
  integrity_with_security: 'reject_structure', illustrative_header_only: 'reject_structure',
  cipher_3: 'reject_suite', cipher_2_outside_suite: 'reject_suite',
};

assert.equal(Object.keys(expected).length, recovery.cases.length);
for (const entry of recovery.cases) {
  const built = build(entry);
  assert.equal(built.header.toString('hex'), entry.header, entry.name);
  if (entry.name === 'illustrative_header_only') assert.equal(entry.header, illustrative);
  if (built.plain.length === 4) assert.deepEqual(built.plain, le32(entry.mask));
  assert.equal(built.plain.toString('hex'), entry.plaintext, entry.name);
  let aeadValid = false;
  if (entry.sealed) {
    assert.equal(entry.cipher, 1);
    const sealed = encrypt(built.plain, built.header, built.routeOffset, entry.pn);
    assert.equal(sealed.frame.toString('hex'), entry.frame, entry.name);
    assert.equal(sealed.aad.toString('hex'), entry.aad, entry.name);
    assert.equal(sealed.nonce.toString('hex'), entry.nonce, entry.name);
    assert.equal(sealed.body.toString('hex'), entry.ciphertext, entry.name);
    assert.equal(sealed.tag.toString('hex'), entry.tag, entry.name);
    aeadValid = true;
    if (entry.name === 'two_of_eight') assert.equal(sealed.frame.length, 30);
  } else {
    const tag = entry.omit_tag ? Buffer.alloc(0) : Buffer.alloc(16);
    const frame = Buffer.concat([built.header, built.plain, tag]);
    assert.equal(frame.toString('hex'), entry.frame, entry.name);
    assert.equal(entry.aead_valid, false);
  }
  assert.equal(decide(entry, built.plain, aeadValid), expected[entry.name], entry.name);
}

const altered = Buffer.from(handshake);
altered[0] ^= 1;
const golden = recovery.cases.find(entry => entry.name === 'two_of_eight');
const goldenFrame = Buffer.from(golden.frame, 'hex');
const badAad = Buffer.concat([label, altered, goldenFrame.subarray(0, goldenFrame[1])]);
const bad = crypto.createDecipheriv('chacha20-poly1305', key, Buffer.from(golden.nonce, 'hex'), {authTagLength: 16});
bad.setAAD(badAad);
bad.setAuthTag(goldenFrame.subarray(goldenFrame.length - 16));
assert.throws(() => Buffer.concat([bad.update(goldenFrame.subarray(goldenFrame[1], goldenFrame.length - 16)), bad.final()]));

const mutationExpect = {
  ttl_only: true, destination: false, sequence: false, reply_to: false,
  receive_cid: false, packet_number: false, ciphertext: false, tag: false,
};
assert.equal(recovery.mutations.length, Object.keys(mutationExpect).length);
for (const mutation of recovery.mutations) {
  const base = recovery.cases.find(entry => entry.name === mutation.base);
  const built = build(base);
  const frame = Buffer.from(base.frame, 'hex');
  const changed = Buffer.from(frame);
  const hdr = built.header.length;
  const offset = {
    route: built.routeOffset,
    destination: built.routeOffset + 2,
    seq: 3,
    reply: hdr - 1,
    cid: 5,
    pn: 6,
    ciphertext: hdr,
    tag: frame.length - 1,
  }[{
    ttl_only: 'route', destination: 'destination', sequence: 'seq', reply_to: 'reply',
    receive_cid: 'cid', packet_number: 'pn', ciphertext: 'ciphertext', tag: 'tag',
  }[mutation.name]];
  assert.equal(offset, mutation.offset, mutation.name);
  changed[offset] ^= mutation.xor;
  assert.equal(changed.toString('hex'), mutation.frame, mutation.name);
  let opened = true;
  let plain = null;
  try {
    plain = openAt(changed).plain;
  } catch (error) {
    opened = false;
  }
  assert.equal(opened, mutationExpect[mutation.name], mutation.name);
  if (opened) assert.equal(plain.toString('hex'), '44000000');
  assert.equal(mutation.aead_valid, opened);
}

assert.equal(maskAccept(0x44, 8), true);
assert.equal(maskAccept(0x01, 2), true);
assert.equal(maskAccept(0x80000000, 32), true);
assert.equal(maskAccept(0, 8), false);
assert.equal(maskAccept(0x03, 2), false);
assert.equal(maskAccept(0x04, 2), false);
assert.equal(maskAccept(0xffffffff, 32), false);
console.log(`recovery fixtures: ${recovery.cases.length} cases, ${recovery.mutations.length} mutations, cipher 1 only`);
