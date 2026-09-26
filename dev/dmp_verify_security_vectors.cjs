/* Independent packet parsing/AAD calculation through Node crypto.
 * Public specification fixtures only; not a production DMP implementation.
 * The parser covers these SEQ-bearing fixtures (no core CRC; TO_NODE routes).
 * It checks the published fixture service choices, not general deployment policy,
 * association state or lifecycle timing.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '../docs/DMP_v2_Security_Test_Vectors.json')));
assert.equal(data.specification, 'DMP v2 revision 10 / SEC-1 revision 5 / BOOT_VERSION 2');
const b = h => Buffer.from(h, 'hex');
const sha = x => crypto.createHash('sha256').update(x).digest();

function plainHeader(extension) {
  const header = Buffer.concat([Buffer.from([0x46, 0, 0x81, 1]), extension]);
  header[1] = header.length;
  return header;
}
const fullReference = plainHeader(Buffer.from([
  5, 11, 1, 10, 8, 7, 6, 5, 4, 3, 2, 1, 2,
]));
assert.deepEqual(parse(fullReference).extensions.get(1), {
  namespace: 1n, origin: 10n, epoch: 0x0102030405060708n, seq: 2n,
});
assert.throws(() => parse(plainHeader(Buffer.from([5, 4, 1, 10, 7, 2]))));

function parse(frame) {
  assert(frame.length >= 3);
  assert.equal(frame[0] >> 5, 2);
  const end = frame[1];
  const opts = frame[2];
  const type = frame[0] & 31;
  const secured = !!(opts & 64);
  assert(end >= 4 && end <= frame.length - (secured ? 16 : 0));
  assert(opts & 1); assert.equal(opts & 16, 0);
  let at = 3;
  function uleb(limit = end, bits = 32) {
    let n = 0n, shift = 0n, start = at;
    for (;;) {
      assert(at < limit && at - start < Math.ceil(bits / 7));
      const v = frame[at++];
      n |= BigInt(v & 127) << shift;
      if (!(v & 128)) {
        assert(n < (1n << BigInt(bits)));
        assert(at - start === 1 || (v & 127) !== 0);
        return n;
      }
      shift += 7n;
    }
  }
  const seq = uleb();
  let routeOffset = null;
  if (opts & 4) {
    routeOffset = at;
    assert(at < end);
    assert.equal(frame[at++] & 15, 1);
    uleb(); uleb();
  }
  let frag = null, fragOffset = null;
  if (opts & 8) {
    fragOffset = at;
    const index = uleb(), chunkSize = uleb(), totalLength = uleb();
    assert(chunkSize > 0n && totalLength > chunkSize);
    const count = 1n + (totalLength - 1n) / chunkSize;
    assert(count <= 0xffffffffn && index < count);
    frag = {index, chunkSize, totalLength, count,
      offset: index * chunkSize,
      sliceLength: (totalLength - index * chunkSize < chunkSize ?
        totalLength - index * chunkSize : chunkSize)};
  }
  if (opts & 32) {
    assert(at < end);
    const flags = frame[at++];
    assert((flags & 252) === 0 && (!(flags & 2) || (flags & 1)));
    uleb(); if (flags & 1) uleb(); if (flags & 2) uleb();
  }
  let cipher = null, cid = null, pn = null;
  if (secured) {
    assert(at < end);
    cipher = frame[at++]; cid = uleb(); pn = uleb(end, 64);
    assert(cipher === 1 || cipher === 2); assert(cid > 0n);
  }
  const extensionStart = at;
  const extensions = new Map();
  if (opts & 128) {
    let last = -1n, count = 0;
    while (at < end) {
      const tag = uleb(), length = Number(uleb()), id = tag >> 2n;
      assert(id > last && at + length <= end);
      if (id >= 1n && id <= 6n) {
        assert.equal(Number(tag & 3n), id === 2n || id === 3n ? 3 : 1);
      }
      if (id === 6n) {
        assert.equal(length, 16);
        assert(secured);
      }
      const value = frame.subarray(at, at + length);
      if (id === 1n) {
        const save = at, limit = at + length;
        const reference = secured ? {seq: uleb(limit)} :
          {namespace: uleb(limit), origin: uleb(limit),
            epoch: (() => { assert(at + 8 <= limit); const e = frame.readBigUInt64LE(at); at += 8; return e; })(),
            seq: uleb(limit)};
        assert.equal(at, limit);
        at = save;
        extensions.set(1, reference);
      } else if (id === 2n) {
        const save = at, limit = at + length;
        const namespace = uleb(limit);
        assert.equal(at + 8, limit);
        const epoch = frame.readBigUInt64LE(at);
        extensions.set(2, {namespace, epoch});
        at = save;
      } else if (id === 3n || id === 4n || id === 5n) {
        const save = at, limit = at + length;
        const value = uleb(limit);
        assert.equal(at, limit);
        extensions.set(Number(id), value);
        at = save;
      } else {
        extensions.set(Number(id), value);
      }
      at += length; last = id; count++;
    }
    assert(count > 0);
  }
  assert.equal(at, end);
  assert(!(routeOffset !== null && extensions.has(3)));
  if (type === 1 || type === 2 || type === 6) assert(extensions.has(1));
  if (type === 2) {
    assert(extensions.has(5));
    const status = extensions.get(5);
    if (status >= 1n && status <= 7n) assert.equal(opts & 2, 0);
    assert(!(status >= 8n && status <= 63n));
  }
  if (type === 6) {
    assert.equal(opts & (2 | 8 | 32), 0);
    assert(!extensions.has(5));
    assert.equal(frame.length - end - (secured ? 16 : 0), 0);
  }
  const canonical = Buffer.from(frame.subarray(0, end));
  if (routeOffset !== null) canonical[routeOffset] &= 15;
  let nonce = null;
  if (secured) {
    nonce = Buffer.alloc(12);
    if (cipher === 1) nonce.writeBigUInt64LE(pn, 4);
    else nonce.writeBigUInt64BE(pn, 4);
  }
  const slice = frame.length - end - (secured ? 16 : 0);
  if (frag) assert.equal(BigInt(slice), frag.sliceLength);
  return {type, secured, cipher, cid, pn, seq, end, canonical, nonce, routeOffset,
    frag, fragOffset, extensionStart, extensions};
}

function open(v, frame, key) {
  const p = parse(frame);
  assert(p.secured);
  const aad = Buffer.concat([Buffer.from('DMP2-SEC1-DATA'), b(v.handshake_hash), p.canonical]);
  const algorithm = p.cipher === 1 ? 'chacha20-poly1305' : 'aes-256-gcm';
  const dec = crypto.createDecipheriv(algorithm, key, p.nonce, {authTagLength: 16});
  dec.setAAD(aad);
  dec.setAuthTag(frame.subarray(frame.length - 16));
  const plaintext = Buffer.concat([dec.update(frame.subarray(p.end, frame.length - 16)), dec.final()]);
  return {p, aad, plaintext};
}

// Public-fixture test helper only: variants reuse a fixture key and nonce and are
// mutually exclusive parser tests, never packets to send or a production pattern.
function sealedVariant(v, base, header, plaintext = b(base.plaintext)) {
  header = Buffer.from(header);
  header[1] = header.length;
  const original = parse(b(base.frame));
  const canonical = Buffer.from(header);
  if (original.routeOffset !== null) canonical[original.routeOffset] &= 15;
  const aad = Buffer.concat([Buffer.from('DMP2-SEC1-DATA'), b(v.handshake_hash), canonical]);
  const algorithm = original.cipher === 1 ? 'chacha20-poly1305' : 'aes-256-gcm';
  const enc = crypto.createCipheriv(algorithm, b(base.key), original.nonce, {authTagLength: 16});
  enc.setAAD(aad);
  return Buffer.concat([header, enc.update(plaintext), enc.final(), enc.getAuthTag()]);
}

// The public encoding corpus fixes application default=1 and nondefault=2.
// This is a fixture assertion, not the future manifest or endpoint validator.
function fixtureService(frame) {
  const p = parse(frame), service = p.extensions.get(4);
  if (p.type === 3) { assert.equal(service, undefined); return null; }
  assert.notEqual(service, 1n, 'explicit application default is noncanonical');
  return service ?? 1n;
}
let packets = 0, mutations = 0, structuralRejections = 0, fixturePolicyRejections = 0;
for (const v of data.vectors) {
  const input = v.test_only_inputs;
  assert.equal(b(input.manifest_bytes).toString(),
    'DMP-SEC1-PUBLIC-VECTOR-PROFILE/3\nmain=10;sec1=5;handshake_error=abort-first;default_service=1;explicit_application_service=2\n');
  for (const packet of v.packets) fixtureService(b(packet.frame));
  for (const [replyName, requestName] of [
    ['request_receipt', 'routed_request'], ['request_receipt_retry', 'routed_request'],
    ['freshness_grant', 'freshness_request'], ['freshness_grant_receipt', 'freshness_grant'],
  ]) {
    const replyPacket = v.packets.find(p => p.name === replyName);
    const requestPacket = v.packets.find(p => p.name === requestName);
    assert.equal(fixtureService(b(replyPacket.frame)), fixtureService(b(requestPacket.frame)));
    assert.equal(parse(b(replyPacket.frame)).extensions.get(1).seq, BigInt(requestPacket.seq));
  }
  assert.equal(sha(b(input.manifest_bytes)).toString('hex'), input.profile_hash);
  const prefix = b(v.flights[0].bootstrap_payload).subarray(0, 72);
  assert.equal(prefix.length, 72);
  assert.equal(prefix[0], 2);
  assert.equal(prefix[1], v.mode);
  assert.equal(prefix[2], v.cipher);
  assert.equal(prefix[3], 1);
  assert.equal(prefix.subarray(4, 20).toString('hex'), input.attempt_id);
  assert.equal(prefix.readUInt32LE(20), 1);
  assert.equal(prefix.readUInt32LE(24), 10);
  assert.equal(prefix.readUInt32LE(28), 20);
  assert.equal(prefix.subarray(32, 64).toString('hex'), input.profile_hash);
  assert.equal(prefix.readUInt32LE(64), v.mode === 1 ? 5 : 0);
  assert.equal(prefix.readUInt32LE(68), 7);
  assert.equal(Buffer.concat([Buffer.from('DMP2-SEC1-BOOT'), prefix.subarray(0, 3), prefix.subarray(4)]).toString('hex'), v.prologue);
  assert.equal(sha(Buffer.concat([Buffer.from('DMP2-SEC1-BOOT-EPOCH'), b(input.attempt_id)])).readBigUInt64LE().toString(), v.bootstrap_epoch);
  for (const direction of [0, 1]) {
    const epoch = sha(Buffer.concat([Buffer.from('DMP2-SEC1-EPOCH'), b(v.handshake_hash), Buffer.from([direction])])).readBigUInt64LE();
    assert.equal(epoch.toString(), v.origin_epochs[direction]);
  }
  const flightLengths = v.mode === 1 ? [120, 70] : [104, 118, 82];
  const pending = new Set();
  function verifyFlight(f, state) {
    const payload = b(f.bootstrap_payload);
    const frame = b(f.direct_unfragmented_frame), parsed = parse(frame);
    assert.equal(parsed.secured, false);
    assert.equal(frame[0] & 31, 3);
    assert.equal(frame[2] & (2 | 8 | 64), 0);
    assert.equal(parsed.seq, BigInt(f.flight));
    assert.equal(frame.subarray(parsed.end).toString('hex'), payload.toString('hex'));
    assert.equal(parsed.extensions.get(2).namespace, 1n);
    assert.equal(parsed.extensions.get(2).epoch.toString(), v.bootstrap_epoch);
    assert.equal(parsed.extensions.get(3), BigInt(f.flight === 2 ? 20 : 10));
    assert.equal(payload.length, flightLengths[f.flight - 1]);
    assert(payload.length <= 120);
    const preLength = f.flight === 1 ? 72 : 18;
    assert.equal(payload[0], 2);
    if (f.flight === 1) {
      assert(payload.subarray(0, 72).equals(prefix));
      state.add(input.attempt_id);
    } else {
      assert.equal(payload[1], f.flight);
      assert.equal(payload.subarray(2, 18).toString('hex'), input.attempt_id);
      assert(state.has(input.attempt_id), 'continuation requires original pending context');
    }
    assert.equal(payload.subarray(preLength).toString('hex'), f.noise_message);
  }
  for (const f of v.flights) {
    if (f.flight === 2) assert.throws(() => verifyFlight(f, new Set()));
    verifyFlight(f, pending);
  }
  const used = new Set();
  const fragments = new Map();
  for (const p of v.packets) {
    const unique = `${p.direction}:${p.pn}`;
    assert(!used.has(unique)); used.add(unique);
    const frame = b(p.frame), result = open(v, frame, b(p.key));
    assert.equal(result.plaintext.toString('hex'), p.plaintext);
    assert.equal(result.aad.toString('hex'), p.aad);
    assert.equal(result.p.nonce.toString('hex'), p.nonce);
    assert.equal(result.p.seq.toString(), String(p.seq));
    assert.equal(result.p.pn.toString(), String(p.pn));
    assert.equal(result.p.routeOffset, p.route_control_offset);
    assert.equal(result.p.cipher, v.cipher);
    assert.equal(result.p.secured, true);
    if (result.p.extensions.has(2)) {
      assert.equal(result.p.extensions.get(2).namespace, 1n);
      assert.equal(result.p.extensions.get(2).epoch.toString(), v.origin_epochs[p.direction]);
    }
    if (result.p.extensions.has(1)) {
      const expected = p.name === 'freshness_grant' ? 6n : 2n;
      assert.deepEqual(result.p.extensions.get(1), {seq: expected});
    }
    if (result.p.frag) {
      assert.equal(result.p.frag.chunkSize, 2n);
      assert.equal(result.p.frag.totalLength, 3n);
      assert.equal(result.p.frag.count, 2n);
      assert.equal(result.p.frag.offset, result.p.frag.index * 2n);
      const index = Number(result.p.frag.index);
      if (!fragments.has(index)) fragments.set(index, result.plaintext);
      else assert(fragments.get(index).equals(result.plaintext));
    }
    assert.equal(frame.length, p.frame_bytes);
    assert.equal(frame.length - result.plaintext.length, p.overhead_bytes);
    const wrongKey = Buffer.from(b(p.key)); wrongKey[0] ^= 1;
    assert.throws(() => open(v, frame, wrongKey));
    packets++;
  }
  for (const m of v.mutations) {
    const base = v.packets.find(p => p.name === m.base);
    let valid = true;
    try { open(v, b(m.frame), b(base.key)); } catch { valid = false; }
    assert.equal(valid, m.aead_valid, `${v.protocol_name}/${m.name}`);
    mutations++;
  }
  const low = v.packets.find(p => p.name === 'fragment_retry_pn_127');
  const high = v.packets.find(p => p.name === 'fragment_retry_pn_128');
  assert.equal(low.seq, high.seq);
  assert.equal(low.plaintext, high.plaintext);
  assert.equal(high.overhead_bytes, low.overhead_bytes + 1);
  assert.equal(high.frame_bytes, low.frame_bytes + 1);
  assert.equal(Buffer.concat([fragments.get(0), fragments.get(1)]).toString('hex'), 'aabbcc');

  function reject(base, header, plaintext) {
    const frame = sealedVariant(v, base, header, plaintext);
    assert.throws(() => open(v, frame, b(base.key)));
    structuralRejections++;
  }
  const frag0 = v.packets.find(p => p.name === 'fragment_0');
  const frag1 = v.packets.find(p => p.name === 'fragment_1');
  const h0 = b(frag0.header), h1 = b(frag1.header);
  const off = parse(b(frag0.frame)).fragOffset;
  for (const [name, fields] of [
    ['zero chunk', [0, 0, 3]],
    ['total not above chunk', [0, 2, 2]],
    ['out of range index', [2, 2, 3]],
    ['total exceeds u32', [0, 2, 0x80, 0x80, 0x80, 0x80, 0x10]],
    ['noncanonical index', [0x80, 0, 2, 3]],
  ]) {
    assert(name);
    reject(frag0, Buffer.concat([h0.subarray(0, off), Buffer.from(fields), h0.subarray(off + 3)]));
  }
  reject(frag1, h1, Buffer.from('bbcc', 'hex')); // final slice must be exactly one byte
  const receipt = v.packets.find(p => p.name === 'request_receipt');
  const replyHeader = b(receipt.header), replyExt = parse(b(receipt.frame)).extensionStart;
  const badReplyFlag = Buffer.from(replyHeader);
  badReplyFlag[replyExt] = 4;
  reject(receipt, badReplyFlag); // registered REPLY_TO requires C=1, U=0
  const ackRequest = Buffer.from(replyHeader);
  ackRequest[2] |= 2;
  reject(receipt, ackRequest);
  reject(receipt, replyHeader, Buffer.from([0xaa]));
  reject(receipt, Buffer.concat([replyHeader, Buffer.from([0x15, 0])]));
  const fragmentedAck = Buffer.concat([
    replyHeader.subarray(0, 4), Buffer.from([0, 1, 2]), replyHeader.subarray(4),
  ]);
  fragmentedAck[2] |= 8;
  reject(receipt, fragmentedAck);
  const describedAck = Buffer.concat([
    replyHeader.subarray(0, 4), Buffer.from([0, 1]), replyHeader.subarray(4),
  ]);
  describedAck[2] |= 32;
  reject(receipt, describedAck);
  for (const extension of [
    Buffer.from([5, 1, 0x80]), // truncated ULEB
    Buffer.from([5, 2, 0x82, 0]), // noncanonical ULEB
    Buffer.from([5, 2, 2, 0]), // obsolete multi-field reference
  ]) reject(receipt, Buffer.concat([replyHeader.subarray(0, replyExt), extension]));
  const request = v.packets.find(p => p.name === 'routed_request');
  const requestHeader = b(request.header), contextExt = parse(b(request.frame)).extensionStart;
  reject(request, Buffer.concat([requestHeader.subarray(0, contextExt),
    Buffer.from([11, 8, 1, 1, 0, 0, 0, 0, 0, 0, 17, 1, 1])]));
  const routedOrigin = Buffer.from(requestHeader);
  const serviceTag = routedOrigin.indexOf(Buffer.from([17, 1, 2]), contextExt);
  assert(serviceTag >= 0);
  routedOrigin[serviceTag] = 15;
  reject(request, routedOrigin); // ROUTE and ORIGIN_ID cannot coexist

  const grant = v.packets.find(p => p.name === 'freshness_grant');
  const grantHeader = b(grant.header);
  // Explicit default is a profile-level failure even with a valid test tag.
  const explicitDefault = Buffer.from(requestHeader);
  explicitDefault[serviceTag + 2] = 1;
  const noncanonical = sealedVariant(v, request, explicitDefault);
  open(v, noncanonical, b(request.key));
  assert.throws(() => fixtureService(noncanonical)); fixturePolicyRejections++;
  const wrongService = Buffer.from(replyHeader);
  wrongService[wrongService.length - 1] = 3;
  const wrongServiceFrame = sealedVariant(v, receipt, wrongService);
  open(v, wrongServiceFrame, b(receipt.key));
  assert.throws(() => assert.equal(fixtureService(wrongServiceFrame), fixtureService(b(request.frame))));
  fixturePolicyRejections++;
  // Application-service STATUS examples; interpreting application codes is profile work.
  const appHeader = Buffer.from(grantHeader);
  assert.equal(appHeader.subarray(-3).toString('hex'), '110100');
  appHeader[appHeader.length - 1] = 2; // explicit application service, not control
  const statusHeader = Buffer.concat([appHeader, Buffer.from([0x15, 1, 64])]);
  const statusRsp = sealedVariant(v, grant, statusHeader, Buffer.alloc(0));
  assert.equal(open(v, statusRsp, b(grant.key)).p.extensions.get(5), 64n);
  const statusErrHeader = Buffer.from(statusHeader);
  statusErrHeader[0] = (statusErrHeader[0] & 0xe0) | 2;
  const statusErr = sealedVariant(v, grant, statusErrHeader, Buffer.alloc(0));
  assert.equal(open(v, statusErr, b(grant.key)).p.extensions.get(5), 64n);
  for (let code = 1; code <= 7; code++) {
    const rejection = Buffer.from(statusErrHeader);
    rejection[rejection.length - 1] = code;
    reject(grant, rejection, Buffer.alloc(0)); // protocol rejection cannot ACK_REQ
    rejection[2] &= ~2;
    const frame = sealedVariant(v, grant, rejection, Buffer.alloc(0));
    assert.equal(open(v, frame, b(grant.key)).p.extensions.get(5), BigInt(code));
  }
  for (const code of [8, 63]) {
    const reserved = Buffer.from(statusErrHeader);
    reserved[2] &= ~2;
    reserved[reserved.length - 1] = code;
    reject(grant, reserved, Buffer.alloc(0));
  }
  const largeStatus = sealedVariant(v, grant, Buffer.concat([
    appHeader, Buffer.from([0x15, 2, 0x80, 1]),
  ]), Buffer.alloc(0));
  assert.equal(open(v, largeStatus, b(grant.key)).p.extensions.get(5), 128n);
  const noStatusErr = Buffer.from(grantHeader);
  noStatusErr[0] = (noStatusErr[0] & 0xe0) | 2;
  reject(grant, noStatusErr);
  for (const invalidStatus of [
    [0x15, 0], // known STATUS must contain exactly one ULEB32
    [0x15, 2, 0x80, 0], // nonminimal encoding
    [0x15, 5, 0x80, 0x80, 0x80, 0x80, 0x10], // u32 overflow
    [0x14, 1, 0], // registered STATUS requires C=1
  ]) reject(grant, Buffer.concat([grantHeader, Buffer.from(invalidStatus)]));
  const missingReply = Buffer.from(replyHeader.subarray(0, replyExt));
  missingReply[2] &= ~128;
  reject(receipt, missingReply);
  const grantExt = parse(b(grant.frame)).extensionStart;
  const missingResultReply = Buffer.concat([
    grantHeader.subarray(0, grantExt), Buffer.from([0x11, 1, 0]),
  ]);
  reject(grant, missingResultReply);
  missingResultReply[0] = (missingResultReply[0] & 0xe0) | 2;
  reject(grant, Buffer.concat([missingResultReply, Buffer.from([0x15, 1, 0])]));

  const knownFlagCases = [
    [v.flights[0].direct_unfragmented_frame, 2, 0x0a],
    [v.flights[0].direct_unfragmented_frame, 3, 0x0e],
    [grant.frame, 4, 0x10],
    [v.packets.find(p => p.name === 'freshness_command_encoding').frame, 6, 0x18],
  ];
  for (const [hex, id, wrongTag] of knownFlagCases) {
    const original = b(hex), parsed = parse(original);
    const header = Buffer.from(original.subarray(0, parsed.end));
    let position = parsed.extensionStart;
    while (position < header.length && (header[position] >> 2) !== id) {
      // These fixtures use one-byte tags and lengths; assert that premise.
      assert(position + 1 < header.length && header[position] < 128 && header[position + 1] < 128);
      position += 2 + header[position + 1];
    }
    assert(position < header.length && header[position] < 128);
    header[position] = wrongTag;
    if (parsed.secured) {
      const base = v.packets.find(p => p.frame === hex);
      reject(base, header);
    } else {
      header[1] = header.length;
      assert.throws(() => parse(Buffer.concat([header, original.subarray(parsed.end)])));
      structuralRejections++;
    }
  }
  const unprotectedFreshness = Buffer.concat([
    fullReference, Buffer.from([0x19, 16]), Buffer.alloc(16),
  ]);
  unprotectedFreshness[1] = unprotectedFreshness.length;
  assert.throws(() => parse(unprotectedFreshness));
  structuralRejections++;
  const second = v.flights[1], secondPayload = b(second.bootstrap_payload);
  const changedAttempt = Buffer.from(secondPayload);
  changedAttempt[2] ^= 1;
  assert.throws(() => verifyFlight({...second, bootstrap_payload: changedAttempt.toString('hex'),
    direct_unfragmented_frame: Buffer.concat([
      b(second.direct_unfragmented_frame).subarray(0, b(second.direct_unfragmented_frame)[1]),
      changedAttempt]).toString('hex')}, pending));
  structuralRejections++;
  const oldPrefix = Buffer.concat([prefix.subarray(0, 3), Buffer.from([2]), prefix.subarray(4)]);
  const oldPayload = Buffer.concat([oldPrefix, b(second.noise_message)]);
  assert.throws(() => verifyFlight({...second, bootstrap_payload: oldPayload.toString('hex'),
    direct_unfragmented_frame: Buffer.concat([
      b(second.direct_unfragmented_frame).subarray(0, b(second.direct_unfragmented_frame)[1]),
      oldPayload]).toString('hex')}, pending));
  structuralRejections++;
}
console.log(JSON.stringify({runtime: 'Node crypto', fixtures: data.vectors.length, packets, mutations,
  wrongKeyRejections: packets, structuralRejections, fixturePolicyRejections}));
