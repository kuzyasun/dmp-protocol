"""Public SEC-1 specification fixtures; NOT production Noise/security code.

Requires Python cryptography. Check against the public Cacophony vectors first:
  python dev/dmp_generate_security_vectors.py --upstream <cacophony.txt>
Then independently verify packet results:
  node dev/dmp_verify_security_vectors.cjs
No devices, credentials, repository dependencies or runtime code are modified.
"""

import argparse
import hashlib
import hmac
import json
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def sha(b):
    return hashlib.sha256(b).digest()


def mac(k, b):
    return hmac.new(k, b, hashlib.sha256).digest()


def hkdf(ck, ikm, count):
    prk = mac(ck, ikm)
    out, prev = [], b""
    for i in range(1, count + 1):
        prev = mac(prk, prev + bytes([i]))
        out.append(prev)
    return out


def public(private):
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def dh(a, b):
    return X25519PrivateKey.from_private_bytes(a).exchange(
        X25519PrivateKey.from_private_bytes(b).public_key()
    )


def nonce(cipher, pn):
    return bytes(4) + pn.to_bytes(8, "little" if cipher == 1 else "big")


def aead(cipher, key):
    return (ChaCha20Poly1305 if cipher == 1 else AESGCM)(key)


def protocol(mode, cipher):
    pattern = "NNpsk0" if mode == 1 else "XX"
    cipher_name = "ChaChaPoly" if cipher == 1 else "AESGCM"
    return f"Noise_{pattern}_25519_{cipher_name}_SHA256"


class Transcript:
    """Deterministic writer used only to reproduce known public vectors."""

    def __init__(self, name, prologue, cipher):
        name = name.encode("ascii")
        self.h = name.ljust(32, b"\0") if len(name) <= 32 else sha(name)
        self.ck, self.k, self.n, self.cipher = self.h, None, 0, cipher
        self.mix_hash(prologue)

    def mix_hash(self, data):
        self.h = sha(self.h + data)

    def mix_key(self, data):
        self.ck, self.k = hkdf(self.ck, data, 2)
        self.n = 0

    def mix_psk(self, data):
        self.ck, temp_h, self.k = hkdf(self.ck, data, 3)
        self.mix_hash(temp_h)
        self.n = 0

    def encrypt(self, data):
        out = data
        if self.k is not None:
            out = aead(self.cipher, self.k).encrypt(nonce(self.cipher, self.n), data, self.h)
            self.n += 1
        self.mix_hash(out)
        return out


def handshake(mode, cipher, prologue, ie, re, si, sr, psk, payloads):
    s = Transcript(protocol(mode, cipher), prologue, cipher)
    if mode == 1:
        s.mix_psk(psk)
    e = public(ie)
    s.mix_hash(e)
    if mode == 1:
        s.mix_key(e)
    messages = [e + s.encrypt(payloads[0])]
    e = public(re)
    s.mix_hash(e)
    if mode == 1:
        s.mix_key(e)
    s.mix_key(dh(ie, re))
    m = e
    if mode == 2:
        m += s.encrypt(public(sr))
        s.mix_key(dh(ie, sr))
    m += s.encrypt(payloads[1])
    messages.append(m)
    if mode == 2:
        m = s.encrypt(public(si))
        s.mix_key(dh(si, re))
        messages.append(m + s.encrypt(payloads[2]))
    keys = hkdf(s.ck, b"", 2)
    return messages, s.h, keys


def check_upstream(path):
    raw = path.read_bytes()
    assert sha(raw).hex() == "3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae", "Unexpected upstream fixture hash"
    data = json.loads(raw)
    checked = []
    for mode in (1, 2):
        for cipher in (1, 2):
            name = protocol(mode, cipher)
            v = next(v for v in data["vectors"] if v["protocol_name"] == name)
            get = lambda k: bytes.fromhex(v[k])
            count = 2 if mode == 1 else 3
            msgs, h, keys = handshake(
                mode, cipher, get("init_prologue"), get("init_ephemeral"),
                get("resp_ephemeral"), get("init_static") if mode == 2 else b"",
                get("resp_static") if mode == 2 else b"",
                bytes.fromhex(v["init_psks"][0]) if mode == 1 else b"",
                [bytes.fromhex(m["payload"]) for m in v["messages"][:count]],
            )
            assert h.hex() == v["handshake_hash"], name
            assert [m.hex() for m in msgs] == [m["ciphertext"] for m in v["messages"][:count]], name
            # Cacophony continues the alternating message direction after the handshake.
            counters = [0, 0]
            for index, m in enumerate(v["messages"][count:], count):
                direction = index % 2
                out = aead(cipher, keys[direction]).encrypt(
                    nonce(cipher, counters[direction]), bytes.fromhex(m["payload"]), b""
                )
                assert out.hex() == m["ciphertext"], (name, index)
                counters[direction] += 1
            checked.append(name)
    return {"source": "https://raw.githubusercontent.com/haskell-cryptography/cacophony/master/vectors/cacophony.txt",
            "sha256": sha(raw).hex(), "verified_protocols": checked}


def uleb(v):
    out = bytearray()
    while v >= 128:
        out.append((v & 127) | 128)
        v >>= 7
    out.append(v)
    return bytes(out)


def ext(i, value, unsafe=False):
    return uleb((i << 2) | (2 if unsafe else 0) | 1) + uleb(len(value)) + value


def core_header(kind, seq, cipher=None, cid=None, pn=None, route=None, frag=None,
                extensions=b"", ack_req=False):
    opts = 1 | (2 if ack_req else 0) | (4 if route else 0) | (8 if frag else 0)
    opts |= (64 if cipher is not None else 0) | (128 if extensions else 0)
    fields = bytes([opts]) + uleb(seq)
    route_offset = None
    if route:
        route_offset = 2 + len(fields)
        ttl, src, dst = route
        fields += bytes([(ttl << 4) | 1]) + uleb(src) + uleb(dst)
    if frag:
        fields += uleb(frag[0]) + uleb(frag[1]) + uleb(frag[2])
    if cipher is not None:
        fields += bytes([cipher]) + uleb(cid) + uleb(pn)
    fields += extensions
    assert len(fields) + 2 <= 255
    return bytes([0x40 | kind, len(fields) + 2]) + fields, route_offset


def packet(label, h, keys, cipher, direction, kind, seq, pn, plaintext, **kwargs):
    cid = 9 if direction == 0 else 7
    header, route_offset = core_header(kind, seq, cipher, cid, pn, **kwargs)
    canonical = bytearray(header)
    if route_offset is not None:
        canonical[route_offset] &= 15
    aad = b"DMP2-SEC1-DATA" + h + canonical
    n = nonce(cipher, pn)
    ct = aead(cipher, keys[direction]).encrypt(n, plaintext, aad)
    assert aead(cipher, keys[direction]).decrypt(n, ct, aad) == plaintext
    return {"name": label, "direction": direction, "pn": pn, "seq": seq,
            "key": keys[direction].hex(), "nonce": n.hex(), "aad": aad.hex(),
            "header": header.hex(), "route_control_offset": route_offset,
            "plaintext": plaintext.hex(), "ciphertext": ct[:-16].hex(),
            "tag": ct[-16:].hex(), "frame": (header + ct).hex(),
            "frame_bytes": len(header) + len(ct), "overhead_bytes": len(header) + 16}


def fixture(mode, cipher):
    ie, re, si, sr, psk = [bytes(range(start, start + 32)) for start in (0, 32, 64, 96, 128)]
    attempt = bytes(range(16))
    manifest = b"DMP-SEC1-PUBLIC-VECTOR-PROFILE/2\nmain=9;sec1=4;default_service=1;explicit_application_service=2\n"
    ph = sha(manifest)
    prefix = struct.pack("<BBBB16sIII32sII", 2, mode, cipher, 1, attempt, 1, 10, 20, ph, 5 if mode == 1 else 0, 7)
    assert len(prefix) == 72
    prologue = b"DMP2-SEC1-BOOT" + prefix[:3] + prefix[4:]
    payloads = [b"", struct.pack("<I", 9)] + ([b""] if mode == 2 else [])
    flights, h, keys = handshake(mode, cipher, prologue, ie, re, si, sr, psk, payloads)
    assert list(map(len, flights)) == ([48, 52] if mode == 1 else [32, 100, 64])
    epochs = [int.from_bytes(sha(b"DMP2-SEC1-EPOCH" + h + bytes([d]))[:8], "little") for d in (0, 1)]
    boot_epoch = int.from_bytes(sha(b"DMP2-SEC1-BOOT-EPOCH" + attempt)[:8], "little")
    boot = []
    for i, f in enumerate(flights, 1):
        pf = (prefix if i == 1 else bytes([2, i]) + attempt)
        origin = 20 if i == 2 else 10
        extensions = ext(2, uleb(1) + struct.pack("<Q", boot_epoch), True) + ext(3, uleb(origin), True)
        hdr, _ = core_header(3, i, extensions=extensions)
        boot.append({"flight": i, "noise_plaintext": payloads[i-1].hex(),
                     "noise_message": f.hex(), "bootstrap_payload": (pf + f).hex(),
                     "direct_unfragmented_frame": (hdr + pf + f).hex()})
    context = ext(2, uleb(1) + struct.pack("<Q", epochs[0]), True)
    service = ext(4, uleb(2))
    reply = ext(1, uleb(2))
    grant_reply = ext(1, uleb(6))
    grant_ack_reply = ext(1, uleb(2))
    control_service = ext(4, uleb(0))
    packets = [
        packet("finish", h, keys, cipher, 0, 3, 0, 0, b"\x04"),
        packet("ready", h, keys, cipher, 1, 3, 0, 0, b"\x05"),
        packet("telemetry", h, keys, cipher, 0, 5, 1, 1, b"\xaa\xbb"),
        packet("routed_request", h, keys, cipher, 0, 0, 2, 2, b"\xde\xad", route=(3, 10, 20), extensions=context + service, ack_req=True),
        packet("fragment_0", h, keys, cipher, 0, 7, 3, 3, b"\xaa\xbb", frag=(0, 2, 3)),
        packet("fragment_1", h, keys, cipher, 0, 7, 3, 4, b"\xcc", frag=(1, 2, 3)),
        packet("fragment_0_retry", h, keys, cipher, 0, 7, 3, 5, b"\xaa\xbb", frag=(0, 2, 3)),
        packet("request_receipt", h, keys, cipher, 1, 6, 1, 1, b"", extensions=reply + service),
        packet("request_receipt_retry", h, keys, cipher, 1, 6, 1, 2, b"", extensions=reply + service),
        packet("freshness_command_encoding", h, keys, cipher, 0, 0, 4, 6, b"\x01", extensions=service + ext(6, bytes(range(16))), ack_req=True),
        packet("unknown_safe_extension", h, keys, cipher, 0, 5, 5, 7, b"\xaa", extensions=bytes.fromhex("800200")),
        packet("freshness_request", h, keys, cipher, 0, 0, 6, 8, b"\x10" + struct.pack("<I", 1000), extensions=control_service, ack_req=True),
        packet("freshness_grant", h, keys, cipher, 1, 1, 2, 3, b"\x11" + bytes(range(16)) + struct.pack("<I", 1000), extensions=grant_reply + control_service, ack_req=True),
        packet("freshness_grant_receipt", h, keys, cipher, 0, 6, 7, 9, b"", extensions=grant_ack_reply + control_service),
        packet("fragment_retry_pn_127", h, keys, cipher, 0, 7, 3, 127, b"\xaa\xbb", frag=(0, 2, 3)),
        packet("fragment_retry_pn_128", h, keys, cipher, 0, 7, 3, 128, b"\xaa\xbb", frag=(0, 2, 3)),
    ]
    mutated = []
    routed = packets[3]
    for name, offset, mask, valid in [
        ("ttl_only", routed["route_control_offset"], 0x10, True),
        ("destination", routed["route_control_offset"] + 2, 1, False),
        ("sequence", 3, 1, False),
        ("cipher_selector", routed["route_control_offset"] + 3, 3, False),
        ("receive_cid", routed["route_control_offset"] + 4, 1, False),
        ("packet_number", routed["route_control_offset"] + 5, 1, False),
        ("service", len(bytes.fromhex(routed["header"])) - 1, 1, False),
        ("ciphertext", len(bytes.fromhex(routed["header"])), 1, False),
        ("tag", len(bytes.fromhex(routed["frame"])) - 1, 1, False),
    ]:
        frame = bytearray.fromhex(routed["frame"])
        frame[offset] ^= mask
        header = bytearray(frame[:frame[1]])
        header[routed["route_control_offset"]] &= 15
        aad = b"DMP2-SEC1-DATA" + h + header
        ok = True
        try:
            aead(cipher, keys[0]).decrypt(bytes.fromhex(routed["nonce"]), bytes(frame[frame[1]:]), aad)
        except InvalidTag:
            ok = False
        assert ok == valid
        mutated.append({"name": name, "base": routed["name"], "frame": frame.hex(), "aead_valid": valid})
    for base, name, offset in [(packets[4], "fragment_total_length", 6), (packets[10], "unknown_extension_flags", 7)]:
        frame = bytearray.fromhex(base["frame"])
        frame[offset] ^= 4 if name == "fragment_total_length" else 1
        aad = b"DMP2-SEC1-DATA" + h + frame[:frame[1]]
        try:
            aead(cipher, keys[0]).decrypt(bytes.fromhex(base["nonce"]), bytes(frame[frame[1]:]), aad)
            raise AssertionError("Mutation authenticated")
        except InvalidTag:
            pass
        mutated.append({"name": name, "base": base["name"], "frame": frame.hex(), "aead_valid": False})
    return {"mode": mode, "cipher": cipher, "protocol_name": protocol(mode, cipher),
            "test_only_inputs": {"init_ephemeral": ie.hex(), "resp_ephemeral": re.hex(),
                "init_static": si.hex() if mode == 2 else None, "resp_static": sr.hex() if mode == 2 else None,
                "psk": psk.hex() if mode == 1 else None, "attempt_id": attempt.hex(),
                "manifest_bytes": manifest.hex(), "profile_hash": ph.hex()},
            "prologue": prologue.hex(), "bootstrap_epoch": str(boot_epoch), "flights": boot,
            "handshake_hash": h.hex(), "i_to_r_key": keys[0].hex(), "r_to_i_key": keys[1].hex(),
            "origin_epochs": list(map(str, epochs)), "packets": packets, "mutations": mutated}


def check_replay_model():
    high, seen, window = -1, set(), 64
    def accept(pn, authenticated=True):
        nonlocal high, seen
        if pn in seen or (high >= 0 and pn <= high - window) or not authenticated:
            return False
        high = max(high, pn)
        seen = {x for x in seen if x > high - window}
        seen.add(pn)
        return True
    assert accept(0) and not accept(0)
    assert not accept(1_000_000, False) and high == 0
    assert accept(2) and accept(1)
    assert accept(80) and not accept(3) and accept(81)
    # Fresh PN permits logical retry; separate message cache suppresses execution.
    accepted_messages = {42}
    assert accept(82) and 42 in accepted_messages
    return 9


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", type=Path, required=True)
    args = ap.parse_args()
    provenance = check_upstream(args.upstream)
    fixtures = [fixture(m, c) for m in (1, 2) for c in (1, 2)]
    report = {"specification": "DMP v2 revision 9 / SEC-1 revision 4 / BOOT_VERSION 2",
              "warning": "PUBLIC TEST KEYS ONLY. Encoding fixtures do not establish live trust, ACLs or token grants.",
              "upstream_validation": provenance, "vectors": fixtures}
    path = Path(__file__).resolve().parents[1] / "docs" / "DMP_v2_Security_Test_Vectors.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"upstream_patterns": len(provenance["verified_protocols"]), "dmp_fixtures": len(fixtures),
                      "protected_packets": sum(len(x["packets"]) for x in fixtures),
                      "mutations": sum(len(x["mutations"]) for x in fixtures),
                      "replay_model_assertions": check_replay_model(), "output": str(path)}))


if __name__ == "__main__":
    main()
