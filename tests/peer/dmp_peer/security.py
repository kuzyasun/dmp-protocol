"""DMP v2 Security Profile SEC-1 implementation (dev/P20_Independent_Peer_Brief.md, docs/DMP_v2_Security_Profile.md).

Independently implemented Noise NNpsk0 and XX state machines, SEC-1 bootstrap framing,
traffic keys, epochs, AEAD encryption/decryption, replay window, and lifecycle.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .frame import (
    CoreFrame,
    Extension,
    FrameError,
    Security,
    decode_uleb,
    encode_frame,
    encode_uleb,
    parse_frame,
)


class SecurityError(ValueError):
    """Base class for SEC-1 errors."""


class HandshakeError(SecurityError):
    """Noise handshake failure."""


class ReplayError(SecurityError):
    """Packet replay check failure."""


class AuthenticationError(SecurityError):
    """AEAD verification failure."""


class AuthorizationError(SecurityError):
    """Peer authorization or ACL check failure."""


class FreshnessError(SecurityError):
    """Command freshness token check failure."""


BOOT_VERSION = 2
MODE_NNPSK0 = 1
MODE_XX = 2
CIPHER_CHACHAPOLY = 1

MSG_HELLO = 3
PAYLOAD_FINISH = b"\x04"
PAYLOAD_READY = b"\x05"

PROLOGUE_PREFIX = b"DMP2-SEC1-BOOT"
BOOT_EPOCH_PREFIX = b"DMP2-SEC1-BOOT-EPOCH"
ASSOC_EPOCH_PREFIX = b"DMP2-SEC1-EPOCH"
DATA_AAD_PREFIX = b"DMP2-SEC1-DATA"

MAX_PN = 16_777_215  # 2^24 - 1
MAX_PLAINTEXT_BYTES = 1_073_741_823  # 2^30 - 1


def hkdf_extract_and_expand(
    chaining_key: bytes, input_key_material: bytes, num_outputs: int = 2
) -> tuple[bytes, ...]:
    """HKDF (RFC 5869) as specified in Noise framework rev 34 section 5.1."""
    temp_key = hmac.new(chaining_key, input_key_material, hashlib.sha256).digest()
    out1 = hmac.new(temp_key, b"\x01", hashlib.sha256).digest()
    out2 = hmac.new(temp_key, out1 + b"\x02", hashlib.sha256).digest()
    if num_outputs == 2:
        return out1, out2
    out3 = hmac.new(temp_key, out2 + b"\x03", hashlib.sha256).digest()
    return out1, out2, out3


def x25519_dh(private_key: x25519.X25519PrivateKey, public_bytes: bytes) -> bytes:
    """X25519 DH with mandatory low-order and all-zero shared secret rejection (§S2.2)."""
    if len(public_bytes) != 32:
        raise HandshakeError("X25519 public key must be exactly 32 bytes")
    try:
        peer_pub = x25519.X25519PublicKey.from_public_bytes(public_bytes)
        shared = private_key.exchange(peer_pub)
    except Exception as exc:
        raise HandshakeError("X25519 DH exchange failed (low-order or invalid point)") from exc
    if shared == b"\x00" * 32:
        raise HandshakeError("All-zero X25519 shared secret rejected")
    return shared


class CipherState:
    """Noise CipherState with 12-byte nonce (4 zero bytes || LE64(n))."""

    def __init__(self, key: bytes | None = None) -> None:
        self.k: bytes | None = key
        self.n: int = 0

    def initialize_key(self, key: bytes | None) -> None:
        self.k = key
        self.n = 0

    def has_key(self) -> bool:
        return self.k is not None

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.k is None:
            return plaintext
        nonce = b"\x00\x00\x00\x00" + self.n.to_bytes(8, "little")
        self.n += 1
        return ChaCha20Poly1305(self.k).encrypt(nonce, plaintext, ad)

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.k is None:
            return ciphertext
        nonce = b"\x00\x00\x00\x00" + self.n.to_bytes(8, "little")
        self.n += 1
        try:
            return ChaCha20Poly1305(self.k).decrypt(nonce, ciphertext, ad)
        except Exception as exc:
            raise AuthenticationError("Noise decrypt_with_ad tag verification failed") from exc


class SymmetricState:
    """Noise SymmetricState managing chaining key, handshake hash, and cipher state."""

    def __init__(self, protocol_name: str) -> None:
        p_bytes = protocol_name.encode("ascii")
        if len(p_bytes) <= 32:
            self.h = p_bytes.ljust(32, b"\x00")
        else:
            self.h = hashlib.sha256(p_bytes).digest()
        self.ck: bytes = self.h
        self.cs: CipherState = CipherState()

    def mix_key(self, input_key_material: bytes) -> None:
        self.ck, k = hkdf_extract_and_expand(self.ck, input_key_material, 2)
        self.cs.initialize_key(k)

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key_and_hash(self, input_key_material: bytes) -> None:
        self.ck, temp_h, temp_k = hkdf_extract_and_expand(self.ck, input_key_material, 3)
        self.mix_hash(temp_h)
        self.cs.initialize_key(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ct = self.cs.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        pt = self.cs.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[bytes, bytes]:
        k1, k2 = hkdf_extract_and_expand(self.ck, b"", 2)
        return k1, k2


def compute_prologue(flight1_prefix_72: bytes) -> bytes:
    """Noise prologue per §S3: ASCII('DMP2-SEC1-BOOT') || PREFIX[0:3] || PREFIX[4:72]."""
    if len(flight1_prefix_72) < 72:
        raise HandshakeError("Flight 1 prefix too short for prologue")
    return PROLOGUE_PREFIX + flight1_prefix_72[0:3] + flight1_prefix_72[4:72]


def compute_bootstrap_epoch(attempt_id: bytes) -> int:
    """Bootstrap provisional epoch per §S3."""
    digest = hashlib.sha256(BOOT_EPOCH_PREFIX + attempt_id).digest()
    return int.from_bytes(digest[:8], "little")


def compute_origin_epoch(handshake_hash: bytes, direction: int) -> int:
    """Origin epoch for association direction per §S4."""
    digest = hashlib.sha256(ASSOC_EPOCH_PREFIX + handshake_hash + bytes([direction])).digest()
    return int.from_bytes(digest[:8], "little")


def compute_canonical_header(header_bytes: bytes) -> bytes:
    """
    CANONICAL_HEADER per §S5: core header from VT through HDR_LEN-1,
    with ROUTE_CONTROL's upper TTL nibble replaced by zero when ROUTE is present.
    """
    if len(header_bytes) < 3:
        return header_bytes
    hdr_len = header_bytes[1]
    opts = header_bytes[2]
    if not (opts & 4):
        return header_bytes[:hdr_len]
    # Locate ROUTE_CONTROL:
    offset = 3
    if opts & 1:  # SEQ
        _, offset = decode_uleb(header_bytes, offset, end=hdr_len)
    if offset >= hdr_len:
        return header_bytes[:hdr_len]
    canonical = bytearray(header_bytes[:hdr_len])
    canonical[offset] = canonical[offset] & 0x0F
    return bytes(canonical)


class ReplayWindow:
    """Sliding replay window per §S6: highest PN H and W-bit bitmap."""

    def __init__(self, window_size: int = 1024) -> None:
        if (window_size & (window_size - 1)) != 0 or window_size < 64:
            raise ValueError("Replay window size must be power of two >= 64")
        self.window_size = window_size
        self._mask = (1 << window_size) - 1
        self.h: int | None = None
        self.bitmap: int = 0

    def check(self, pn: int) -> bool:
        if pn < 0 or pn > MAX_PN:
            return False
        if self.h is None:
            return True
        if pn > self.h:
            return True
        diff = self.h - pn
        if diff >= self.window_size:
            return False
        if (self.bitmap >> diff) & 1:
            return False
        return True

    def commit(self, pn: int) -> None:
        if self.h is None:
            self.h = pn
            self.bitmap = 1
            return
        if pn > self.h:
            shift = pn - self.h
            if shift >= self.window_size:
                self.bitmap = 1
            else:
                self.bitmap = ((self.bitmap << shift) | 1) & self._mask
            self.h = pn
        else:
            diff = self.h - pn
            if diff < self.window_size:
                self.bitmap = (self.bitmap | (1 << diff)) & self._mask
        self.bitmap &= self._mask


@dataclass
class SecurityAssociation:
    """Live or candidate traffic association per §S4, §S5, §S8."""

    h: bytes  # 32-byte final handshake hash
    send_key: bytes  # 32-byte directional key for sending
    recv_key: bytes  # 32-byte directional key for receiving
    local_rx_cid: int  # local receive selector advertised to peer
    peer_rx_cid: int  # peer receive selector used when encrypting
    local_epoch: int
    peer_epoch: int
    is_initiator: bool
    status: str = "candidate"  # candidate, active, draining, closed
    next_send_pn: int = 0
    replay_window: ReplayWindow = field(default_factory=ReplayWindow)
    failed_aead_count: int = 0
    failed_aead_limit: int = 1000
    total_plaintext_bytes_sent: int = 0
    split_time_ms: int = 0
    association_lifetime_ms: int = 100_000_000
    drain_lifetime_ms: int = 10_000

    def is_expired(self, now_ms: int) -> bool:
        return now_ms >= self.split_time_ms + self.association_lifetime_ms

    def alloc_send_pn(self) -> int:
        if self.status == "closed":
            raise SecurityError("Cannot encrypt on closed association")
        if self.next_send_pn > MAX_PN:
            raise SecurityError("PN exhaustion (>= 2^24)")
        pn = self.next_send_pn
        self.next_send_pn += 1
        return pn

    def encrypt_frame(
        self, core_header: bytes, plaintext: bytes, pn: int | None = None
    ) -> tuple[int, bytes]:
        """
        Encrypt plaintext with explicit PN. Returns (pn, ciphertext_with_tag).
        Applies §S8 encryption and byte limits.
        """
        if self.status == "closed":
            raise SecurityError("Cannot encrypt on closed association")
        if pn is None:
            if self.next_send_pn > MAX_PN:
                raise SecurityError("PN exhaustion (>= 2^24)")
            pn = self.next_send_pn
            self.next_send_pn += 1
        elif pn > MAX_PN:
            raise SecurityError("PN exhaustion (>= 2^24)")

        if self.total_plaintext_bytes_sent + len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise SecurityError("Plaintext byte exhaustion (>= 2^30)")

        self.total_plaintext_bytes_sent += len(plaintext)

        canonical_hdr = compute_canonical_header(core_header)
        aad = DATA_AAD_PREFIX + self.h + canonical_hdr
        nonce = b"\x00\x00\x00\x00" + pn.to_bytes(8, "little")
        ct_and_tag = ChaCha20Poly1305(self.send_key).encrypt(nonce, plaintext, aad)
        return pn, ct_and_tag

    def decrypt_frame(
        self,
        core_header: bytes,
        ciphertext: bytes,
        tag: bytes,
        pn: int,
        rx_cid: int,
    ) -> bytes:
        """
        Authenticate and decrypt frame per §S5, §S6.
        Commits replay window ONLY after valid AEAD verification.
        """
        if self.status == "closed":
            raise SecurityError("Cannot decrypt on closed association")
        if rx_cid != self.local_rx_cid:
            raise SecurityError(f"CID mismatch: expected {self.local_rx_cid}, got {rx_cid}")
        if pn > MAX_PN:
            raise SecurityError("PN out of range (>= 2^24)")
        if not self.replay_window.check(pn):
            raise ReplayError(f"PN {pn} rejected by replay window")

        canonical_hdr = compute_canonical_header(core_header)
        aad = DATA_AAD_PREFIX + self.h + canonical_hdr
        nonce = b"\x00\x00\x00\x00" + pn.to_bytes(8, "little")
        try:
            plaintext = ChaCha20Poly1305(self.recv_key).decrypt(nonce, ciphertext + tag, aad)
        except Exception as exc:
            self.failed_aead_count += 1
            if self.failed_aead_count >= self.failed_aead_limit:
                self.status = "closed"
            raise AuthenticationError("AEAD decryption failed") from exc

        # Valid AEAD: atomically commit replay window
        self.replay_window.commit(pn)
        return plaintext


@dataclass
class TokenGrant:
    token: bytes
    issued_at_ms: int
    granted_lifetime_ms: int
    association_h: bytes
    requester_id: int
    record_until_ms: int = 0
    bound_identity: tuple[int, int, int, int] | None = None
    bound_service_id: int | None = None
    bound_message_digest: bytes | None = None
    consumed: bool = False


class FreshnessManager:
    """Manages Service 0 freshness tokens and grants per §S7, §S7.1."""

    def __init__(self, entropy_source: Callable[[int], bytes]) -> None:
        self.entropy_source = entropy_source
        self.grants: dict[bytes, TokenGrant] = {}
        self.requests_by_pair: dict[tuple[bytes, int], int] = {}

    def _prune(self, at_ms: int) -> None:
        for token, grant in list(self.grants.items()):
            if at_ms >= grant.record_until_ms:
                del self.grants[token]

    def issue_grant(
        self,
        association_h: bytes,
        requester_id: int,
        requested_lifetime_ms: int,
        at_ms: int,
        max_policy_ms: int = 60_000,
        max_tokens_per_association: int = 64,
        max_tokens_per_principal: int = 256,
        max_requests_per_pair: int = 64,
        token_record_ms: int | None = None,
    ) -> tuple[bytes, int] | None:
        if not (1 <= requested_lifetime_ms <= 60_000 and 1 <= max_policy_ms <= 60_000):
            return None
        self._prune(at_ms)
        pair_key = (association_h, requester_id)
        requests = self.requests_by_pair.get(pair_key, 0)
        if requests >= max_requests_per_pair or max_requests_per_pair <= 0:
            return None
        # Count every structurally valid request, including one refused by table
        # capacity, without allowing attacker-controlled counters to grow.
        self.requests_by_pair[pair_key] = requests + 1

        association_count = sum(1 for grant in self.grants.values() if grant.association_h == association_h)
        principal_count = sum(1 for grant in self.grants.values() if grant.requester_id == requester_id)
        if (association_count >= max_tokens_per_association
                or principal_count >= max_tokens_per_principal
                or max_tokens_per_association <= 0
                or max_tokens_per_principal <= 0):
            return None

        granted = min(requested_lifetime_ms, max_policy_ms)
        try:
            token = self.entropy_source(16)
        except Exception as exc:
            raise FreshnessError("Freshness token entropy source failed") from exc
        if len(token) != 16 or token in self.grants:
            raise FreshnessError("Freshness token entropy did not produce a unique 16-byte token")
        retention = max_policy_ms if token_record_ms is None else token_record_ms
        if retention < granted:
            raise FreshnessError("Freshness token record retention is shorter than its lease")
        grant = TokenGrant(
            token=token,
            issued_at_ms=at_ms,
            granted_lifetime_ms=granted,
            association_h=association_h,
            requester_id=requester_id,
            record_until_ms=at_ms + retention,
        )
        self.grants[token] = grant
        return token, granted

    def validate_command_token(
        self,
        token: bytes,
        association_h: bytes,
        requester_id: int,
        message_id: tuple[int, int, int, int],
        at_ms: int,
        service_id: int | None = None,
        message_digest: bytes | None = None,
    ) -> bool:
        self._prune(at_ms)
        grant = self.grants.get(token)
        if not grant:
            return False
        if grant.association_h != association_h or grant.requester_id != requester_id:
            return False
        if grant.consumed and grant.bound_identity != message_id:
            return False
        if grant.bound_service_id is not None and service_id != grant.bound_service_id:
            return False
        if (grant.bound_message_digest is not None
                and message_digest != grant.bound_message_digest):
            return False
        if at_ms >= grant.issued_at_ms + grant.granted_lifetime_ms:
            return False
        if grant.bound_identity is not None and grant.bound_identity != message_id:
            return False
        grant.bound_identity = message_id
        if grant.bound_service_id is None:
            grant.bound_service_id = service_id
        if grant.bound_message_digest is None:
            grant.bound_message_digest = message_digest
        return True

    def consume_identity(self, association_h: bytes, message_id: tuple[int, int, int, int]) -> None:
        for grant in self.grants.values():
            if grant.association_h == association_h and grant.bound_identity == message_id:
                grant.consumed = True

    def consume_token(self, token: bytes) -> None:
        if token in self.grants:
            self.grants[token].consumed = True

    def clear_association(self, association_h: bytes) -> None:
        for t, g in list(self.grants.items()):
            if g.association_h == association_h:
                del self.grants[t]
        for key in list(self.requests_by_pair):
            if key[0] == association_h:
                del self.requests_by_pair[key]


class BootstrapManager:
    """
    Manages Noise handshake flights, abort-first transitions,
    and credential enrollment per §S2, §S3, §S3.1.
    """

    def __init__(
        self,
        mode: int,
        manifest_digest: bytes,
        namespace: int,
        local_node_id: int,
        remote_node_id: int,
        entropy_source: Callable[[int], bytes],
        psk: bytes | None = None,
        key_hint: int | None = None,
        local_rx_cid: int = 0,
        static_private_key: bytes | None = None,
        peer_static_public_key: bytes | None = None,
        replay_window_bits: int = 1024,
        failed_aead_limit: int = 1000,
        association_lifetime_ms: int = 100_000_000,
    ) -> None:
        if mode == MODE_XX:
            if not isinstance(static_private_key, bytes) or len(static_private_key) != 32:
                raise SecurityError("XX requires a provisioned 32-byte local static private key")
            if peer_static_public_key is not None and (
                not isinstance(peer_static_public_key, bytes) or len(peer_static_public_key) != 32
            ):
                raise SecurityError("XX peer pin must be exactly 32 bytes")
        self.mode = mode
        self.manifest_digest = manifest_digest
        self.namespace = namespace
        self.local_node_id = local_node_id
        self.remote_node_id = remote_node_id
        self.entropy_source = entropy_source
        self.psk = psk
        self.key_hint = (1 if mode == MODE_NNPSK0 else 0) if key_hint is None else key_hint
        self.local_rx_cid = local_rx_cid
        self.static_private_key = static_private_key
        self.peer_static_public_key = peer_static_public_key
        self.replay_window_bits = replay_window_bits
        self.failed_aead_limit = failed_aead_limit
        self.association_lifetime_ms = association_lifetime_ms

        # Committed pin storage (survives restart if already committed)
        self.committed_pins: set[bytes] = set()
        if peer_static_public_key is not None:
            self.committed_pins.add(peer_static_public_key)

        # Active attempt state
        self.current_attempt_id: bytes | None = None
        self.attempt_start_ms: int = 0
        self.prologue: bytes | None = None
        self.sym_state: SymmetricState | None = None
        self.ephemeral_private: x25519.X25519PrivateKey | None = None
        self.remote_ephemeral_pub: bytes | None = None
        self.remote_static_pub: bytes | None = None
        self.remote_rx_cid: int = 0
        self.cached_outgoing_flights: dict[int, bytes] = {}
        self.flight1_cache: bytes | None = None
        self.flight2_cache: bytes | None = None
        self.flight3_cache: bytes | None = None
        self.handshake_completed: bool = False
        self.enrollment_committed: bool = False
        self.attempt_aborted: bool = False
        self.final_handshake_hash: bytes | None = None

    def approve_oob_peer_static_key(self, peer_static_public_key: bytes) -> None:
        """Commit an owner-verified XX peer key before any attempt uses it."""
        if self.mode != MODE_XX:
            raise AuthorizationError("OOB static-key enrollment is valid only for XX")
        if self.static_private_key is None or len(self.static_private_key) != 32:
            raise AuthorizationError("XX local static key must be provisioned before peer enrollment")
        if not isinstance(peer_static_public_key, bytes) or len(peer_static_public_key) != 32:
            raise AuthorizationError("OOB peer static key must be exactly 32 bytes")
        if self.current_attempt_id is not None:
            raise AuthorizationError("Cannot enroll a peer key during an active attempt")
        if self.committed_pins and peer_static_public_key not in self.committed_pins:
            raise AuthorizationError("Changing an enrolled peer key requires explicit trusted revocation")
        self.peer_static_public_key = bytes(peer_static_public_key)
        self.committed_pins.add(self.peer_static_public_key)

    def abort_attempt(self) -> None:
        """Abort current attempt and erase transient candidate secrets (§S3.1)."""
        self.attempt_aborted = True
        self.current_attempt_id = None
        self.prologue = None
        self.sym_state = None
        self.ephemeral_private = None
        self.remote_ephemeral_pub = None
        self.remote_static_pub = None
        self.handshake_completed = False
        self.enrollment_committed = False
        self.final_handshake_hash = None
        self.cached_outgoing_flights.clear()
        self.flight1_cache = None
        self.flight2_cache = None
        self.flight3_cache = None

    def _attempt_entropy(self, size: int) -> bytes:
        """Read attempt entropy and erase partially constructed Noise state on failure."""
        try:
            value = self.entropy_source(size)
            if not isinstance(value, bytes) or len(value) != size:
                raise HandshakeError("Entropy source returned an invalid value")
            return value
        except Exception as exc:
            self.abort_attempt()
            if isinstance(exc, SecurityError):
                raise
            raise HandshakeError("Entropy source failed during handshake") from exc

    def _attempt_dh(self, private_key: x25519.X25519PrivateKey, public_bytes: bytes) -> bytes:
        """Abort the attempt if DH fails after the Noise state has been mutated."""
        try:
            return x25519_dh(private_key, public_bytes)
        except SecurityError:
            self.abort_attempt()
            raise

    def build_flight_1(
        self,
        attempt_id: bytes,
        at_ms: int,
        key_hint: int | None = None,
        local_rx_cid: int | None = None,
    ) -> tuple[int, bytes]:
        """Initiator builds Flight 1 (72-byte prefix + Noise message)."""
        if self.mode == MODE_XX and (
            self.peer_static_public_key is None or self.peer_static_public_key not in self.committed_pins
        ):
            raise AuthorizationError("XX requires an explicitly committed OOB peer pin")
        self.current_attempt_id = attempt_id
        self.attempt_start_ms = at_ms
        self.attempt_aborted = False
        self.handshake_completed = False
        self.enrollment_committed = False

        # Allocate local receive CID
        if local_rx_cid is not None:
            self.local_rx_cid = local_rx_cid
        elif self.local_rx_cid == 0:
            cid_bytes = self._attempt_entropy(4)
            self.local_rx_cid = int.from_bytes(cid_bytes, "little") & 0x7FFFFFFF
            if self.local_rx_cid == 0:
                self.local_rx_cid = 1

        if key_hint is not None:
            self.key_hint = key_hint

        # Construct 72-byte flight 1 prefix
        prefix = bytearray()
        prefix.append(BOOT_VERSION)
        prefix.append(self.mode)
        prefix.append(CIPHER_CHACHAPOLY)
        prefix.append(1)  # FLIGHT = 1
        prefix.extend(attempt_id)
        prefix.extend(self.namespace.to_bytes(4, "little"))
        prefix.extend(self.local_node_id.to_bytes(4, "little"))
        prefix.extend(self.remote_node_id.to_bytes(4, "little"))
        prefix.extend(self.manifest_digest)
        prefix.extend(self.key_hint.to_bytes(4, "little"))
        prefix.extend(self.local_rx_cid.to_bytes(4, "little"))
        prefix_bytes = bytes(prefix)

        self.prologue = compute_prologue(prefix_bytes)
        proto_name = (
            "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
            if self.mode == MODE_NNPSK0
            else "Noise_XX_25519_ChaChaPoly_SHA256"
        )
        self.sym_state = SymmetricState(proto_name)
        self.sym_state.mix_hash(self.prologue)

        if self.mode == MODE_NNPSK0:
            if not self.psk:
                raise HandshakeError("PSK required for Mode 1")
            self.sym_state.mix_key_and_hash(self.psk)

        # Generate ephemeral key
        e_seed = self._attempt_entropy(32)
        self.ephemeral_private = x25519.X25519PrivateKey.from_private_bytes(e_seed)
        e_pub = self.ephemeral_private.public_key().public_bytes_raw()

        self.sym_state.mix_hash(e_pub)
        if self.mode == MODE_NNPSK0:
            self.sym_state.mix_key(e_pub)

        noise_msg = e_pub + self.sym_state.encrypt_and_hash(b"")
        bootstrap_payload = prefix_bytes + noise_msg
        self.flight1_cache = bootstrap_payload
        self.cached_outgoing_flights[1] = bootstrap_payload
        return self.local_rx_cid, bootstrap_payload

    def process_flight_1(self, payload: bytes, at_ms: int) -> tuple[int, bytes]:
        """Responder processes Flight 1 and builds Flight 2."""
        if len(payload) < 72:
            raise HandshakeError("Flight 1 payload too short for 72-byte prefix")

        prefix = payload[:72]
        boot_ver = prefix[0]
        mode = prefix[1]
        cipher = prefix[2]
        flight = prefix[3]
        attempt_id = prefix[4:20]
        namespace = int.from_bytes(prefix[20:24], "little")
        init_id = int.from_bytes(prefix[24:28], "little")
        resp_id = int.from_bytes(prefix[28:32], "little")
        p_hash = prefix[32:64]
        key_hint = int.from_bytes(prefix[64:68], "little")
        i_rx_cid = int.from_bytes(prefix[68:72], "little")

        # Pre-read checks (§S3, §S3.1)
        if boot_ver != BOOT_VERSION:
            raise HandshakeError(f"Unsupported BOOT_VERSION: {boot_ver}")
        if mode != self.mode or cipher != CIPHER_CHACHAPOLY or flight != 1:
            raise HandshakeError("Incompatible mode, cipher, or flight")
        if namespace != self.namespace or init_id != self.remote_node_id or resp_id != self.local_node_id:
            raise HandshakeError("Namespace or endpoint ID mismatch")
        if p_hash != self.manifest_digest:
            raise HandshakeError("PROFILE_HASH mismatch")
        if mode == MODE_XX and key_hint != 0:
            raise HandshakeError("KEY_HINT must be 0 in Mode 2")
        if key_hint != self.key_hint:
            raise HandshakeError("KEY_HINT does not match the provisioned credential")
        if mode == MODE_XX and (
            self.peer_static_public_key is None
            or self.peer_static_public_key not in self.committed_pins
        ):
            raise AuthorizationError("XX Flight 1 requires an explicitly committed OOB peer pin")
        if i_rx_cid == 0:
            raise HandshakeError("Zero initiator RX_CID rejected")

        # If identical duplicate of active flight 1, return cached flight 2
        if self.current_attempt_id == attempt_id and self.flight2_cache is not None:
            if self.flight1_cache == payload:
                return self.local_rx_cid, self.flight2_cache
            else:
                # Conflicting duplicate: cheap drop without aborting (§S3.1)
                raise HandshakeError("Conflicting duplicate flight 1 dropped")

        self.current_attempt_id = attempt_id
        self.attempt_start_ms = at_ms
        self.attempt_aborted = False
        self.remote_rx_cid = i_rx_cid
        self.flight1_cache = payload

        # Setup responder Noise state
        self.prologue = compute_prologue(prefix)
        proto_name = (
            "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
            if self.mode == MODE_NNPSK0
            else "Noise_XX_25519_ChaChaPoly_SHA256"
        )
        self.sym_state = SymmetricState(proto_name)
        self.sym_state.mix_hash(self.prologue)

        if self.mode == MODE_NNPSK0:
            if not self.psk:
                raise HandshakeError("PSK required for Mode 1")
            self.sym_state.mix_key_and_hash(self.psk)

        noise_msg = payload[72:]
        if len(noise_msg) < 32:
            self.abort_attempt()
            raise HandshakeError("Noise message 1 truncated")

        re_pub = noise_msg[:32]
        self.remote_ephemeral_pub = re_pub
        self.sym_state.mix_hash(re_pub)
        if self.mode == MODE_NNPSK0:
            self.sym_state.mix_key(re_pub)

        try:
            pt = self.sym_state.decrypt_and_hash(noise_msg[32:])
        except Exception as exc:
            self.abort_attempt()
            raise HandshakeError("Flight 1 decrypt failed") from exc

        if pt != b"":
            self.abort_attempt()
            raise HandshakeError("Flight 1 decrypted payload must be empty")

        # Allocate responder receive CID
        if self.local_rx_cid == 0:
            r_cid_bytes = self._attempt_entropy(4)
            self.local_rx_cid = int.from_bytes(r_cid_bytes, "little") & 0x7FFFFFFF
            if self.local_rx_cid == 0:
                self.local_rx_cid = 2

        # Generate responder ephemeral
        resp_seed = self._attempt_entropy(32)
        self.ephemeral_private = x25519.X25519PrivateKey.from_private_bytes(resp_seed)
        resp_e_pub = self.ephemeral_private.public_key().public_bytes_raw()

        self.sym_state.mix_hash(resp_e_pub)
        if self.mode == MODE_NNPSK0:
            self.sym_state.mix_key(resp_e_pub)

        ee = self._attempt_dh(self.ephemeral_private, re_pub)
        self.sym_state.mix_key(ee)

        f2_noise = bytearray(resp_e_pub)
        if self.mode == MODE_XX:
            if not self.static_private_key:
                raise HandshakeError("Static private key required for Mode 2")
            resp_s = x25519.X25519PrivateKey.from_private_bytes(self.static_private_key)
            resp_s_pub = resp_s.public_key().public_bytes_raw()
            f2_noise.extend(self.sym_state.encrypt_and_hash(resp_s_pub))
            es = self._attempt_dh(resp_s, re_pub)
            self.sym_state.mix_key(es)

        f2_noise.extend(self.sym_state.encrypt_and_hash(self.local_rx_cid.to_bytes(4, "little")))

        # Continuation prefix (18 bytes)
        c_prefix = bytes([BOOT_VERSION, 2]) + attempt_id
        f2_payload = c_prefix + bytes(f2_noise)
        self.flight2_cache = f2_payload
        self.cached_outgoing_flights[2] = f2_payload

        if self.mode == MODE_NNPSK0:
            self.handshake_completed = True
            self.enrollment_committed = True

        return self.local_rx_cid, f2_payload

    def process_flight_2(self, payload: bytes, at_ms: int) -> tuple[int | None, bytes | None]:
        """Initiator processes Flight 2; returns Flight 3 if Mode 2, or (None, None) if Mode 1."""
        if len(payload) < 18:
            raise HandshakeError("Flight 2 payload too short for 18-byte continuation prefix")

        boot_ver = payload[0]
        flight = payload[1]
        attempt_id = payload[2:18]

        # Pre-read checks (§S3.1)
        if boot_ver != BOOT_VERSION or flight != 2:
            raise HandshakeError("Invalid BOOT_VERSION or FLIGHT for Flight 2")
        if self.current_attempt_id != attempt_id or self.sym_state is None or self.ephemeral_private is None:
            raise HandshakeError("Unknown or expired attempt for Flight 2")

        noise_msg = payload[18:]
        if len(noise_msg) < 32:
            self.abort_attempt()
            raise HandshakeError("Flight 2 noise message truncated")

        resp_re_pub = noise_msg[:32]
        self.remote_ephemeral_pub = resp_re_pub
        self.sym_state.mix_hash(resp_re_pub)
        if self.mode == MODE_NNPSK0:
            self.sym_state.mix_key(resp_re_pub)

        ee = self._attempt_dh(self.ephemeral_private, resp_re_pub)
        self.sym_state.mix_key(ee)

        offset = 32
        if self.mode == MODE_XX:
            # Decrypt responder static key
            s_cipher = noise_msg[offset : offset + 48]
            if len(s_cipher) < 48:
                self.abort_attempt()
                raise HandshakeError("Flight 2 static key ciphertext truncated")
            try:
                resp_s_pub = self.sym_state.decrypt_and_hash(s_cipher)
            except Exception as exc:
                self.abort_attempt()
                raise HandshakeError("Flight 2 static key decrypt failed") from exc
            offset += 48
            self.remote_static_pub = resp_s_pub

            # Verify responder static key against committed pin / OOB approval (§S2)
            if (self.peer_static_public_key is None
                    or resp_s_pub != self.peer_static_public_key
                    or resp_s_pub not in self.committed_pins):
                self.abort_attempt()
                raise AuthorizationError("Peer static key does not match pinned key")

            es = self._attempt_dh(self.ephemeral_private, resp_s_pub)
            self.sym_state.mix_key(es)

        try:
            pt = self.sym_state.decrypt_and_hash(noise_msg[offset:])
        except Exception as exc:
            self.abort_attempt()
            raise HandshakeError("Flight 2 payload decrypt failed") from exc

        if len(pt) != 4:
            self.abort_attempt()
            raise HandshakeError("Flight 2 decrypted payload must be exactly 4 bytes")
        r_cid = int.from_bytes(pt, "little")
        if r_cid == 0:
            self.abort_attempt()
            raise HandshakeError("Zero responder RX_CID rejected")
        self.remote_rx_cid = r_cid

        if self.mode == MODE_NNPSK0:
            self.handshake_completed = True
            self.enrollment_committed = True
            return None, None

        # Mode 2: Initiator builds Flight 3
        if not self.static_private_key:
            raise HandshakeError("Static private key required for Mode 2")
        init_s = x25519.X25519PrivateKey.from_private_bytes(self.static_private_key)
        init_s_pub = init_s.public_key().public_bytes_raw()
        f3_noise = bytearray(self.sym_state.encrypt_and_hash(init_s_pub))
        se = self._attempt_dh(init_s, resp_re_pub)
        self.sym_state.mix_key(se)
        f3_noise.extend(self.sym_state.encrypt_and_hash(b""))

        c_prefix = bytes([BOOT_VERSION, 3]) + attempt_id
        f3_payload = c_prefix + bytes(f3_noise)
        self.flight3_cache = f3_payload
        self.cached_outgoing_flights[3] = f3_payload

        # The owner-approved pin was committed before the handshake; Noise only
        # confirms that this association is using that existing credential.
        self.enrollment_committed = True
        self.handshake_completed = True
        return self.local_rx_cid, f3_payload

    def process_flight_3(self, payload: bytes, at_ms: int) -> None:
        """Responder processes Flight 3 for Mode 2."""
        if self.mode != MODE_XX:
            raise HandshakeError("Flight 3 is valid only in Mode 2")
        if len(payload) < 18:
            raise HandshakeError("Flight 3 continuation prefix truncated")

        boot_ver = payload[0]
        flight = payload[1]
        attempt_id = payload[2:18]

        if boot_ver != BOOT_VERSION or flight != 3:
            raise HandshakeError("Invalid BOOT_VERSION or FLIGHT for Flight 3")
        if self.current_attempt_id != attempt_id or self.sym_state is None or self.ephemeral_private is None:
            raise HandshakeError("Unknown or expired attempt for Flight 3")

        noise_msg = payload[18:]
        if len(noise_msg) < 48:
            self.abort_attempt()
            raise HandshakeError("Flight 3 truncated")

        try:
            init_s_pub = self.sym_state.decrypt_and_hash(noise_msg[:48])
        except Exception as exc:
            self.abort_attempt()
            raise HandshakeError("Flight 3 static key decrypt failed") from exc
        self.remote_static_pub = init_s_pub

        if (self.peer_static_public_key is None
                or init_s_pub != self.peer_static_public_key
                or init_s_pub not in self.committed_pins):
            self.abort_attempt()
            raise AuthorizationError("Peer static key does not match pinned key")

        se = self._attempt_dh(self.ephemeral_private, init_s_pub)
        self.sym_state.mix_key(se)

        try:
            pt = self.sym_state.decrypt_and_hash(noise_msg[48:])
        except Exception as exc:
            self.abort_attempt()
            raise HandshakeError("Flight 3 payload decrypt failed") from exc
        if pt != b"":
            self.abort_attempt()
            raise HandshakeError("Flight 3 decrypted payload must be empty")

        self.enrollment_committed = True
        self.handshake_completed = True

    def create_association(self, is_initiator: bool, at_ms: int) -> SecurityAssociation:
        """Derive Split keys, origin epochs, and construct SecurityAssociation (§S4)."""
        if not self.handshake_completed or self.sym_state is None:
            raise HandshakeError("Handshake not completed")

        k1, k2 = self.sym_state.split()
        h = self.sym_state.h
        self.final_handshake_hash = h

        # Direction 0: initiator -> responder (uses k1)
        # Direction 1: responder -> initiator (uses k2)
        send_key = k1 if is_initiator else k2
        recv_key = k2 if is_initiator else k1

        init_epoch = compute_origin_epoch(h, 0)
        resp_epoch = compute_origin_epoch(h, 1)
        local_epoch = init_epoch if is_initiator else resp_epoch
        peer_epoch = resp_epoch if is_initiator else init_epoch

        assoc = SecurityAssociation(
            h=h,
            send_key=send_key,
            recv_key=recv_key,
            local_rx_cid=self.local_rx_cid,
            peer_rx_cid=self.remote_rx_cid,
            local_epoch=local_epoch,
            peer_epoch=peer_epoch,
            is_initiator=is_initiator,
            status="candidate",
            replay_window=ReplayWindow(self.replay_window_bits),
            failed_aead_limit=self.failed_aead_limit,
            split_time_ms=at_ms,
            association_lifetime_ms=self.association_lifetime_ms,
        )
        # Split is the terminal secret boundary. Retain public flight caches and
        # identity metadata for bounded confirmation replay, then erase Noise and
        # ephemeral private state so restart/late-flight paths cannot reuse it.
        self.sym_state = None
        self.ephemeral_private = None
        self.remote_ephemeral_pub = None
        self.remote_static_pub = None
        self.prologue = None
        return assoc
