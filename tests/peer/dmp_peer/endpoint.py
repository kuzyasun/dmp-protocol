"""DMP-PEER-TEST/1 endpoint implementation (dev/P20_Independent_Peer_Brief.md)."""

from __future__ import annotations

import hashlib
import struct
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .delivery import DeliveryManager, OutgoingExchange, RetainedResult, AcceptedRecord, RejectionRecord
from .events import (
    Advance,
    ApplicationEvent,
    ApplicationRequest,
    Cancel,
    Disconnect,
    EventValidationError,
    Open,
    PublishSample,
    Receive,
    Restart,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from .frame import CoreFrame, Extension, Fragment, FrameError, Route, Security, decode_uleb, encode_frame, encode_uleb, parse_frame
from .manifest import Manifest, ManifestError, identify_frozen_manifest
from .reassembly import ConflictError, QuotaError, ReassemblyError, ReassemblyManager
from .sample1 import Sample, SampleConsumer, SampleEpochStore, SampleProducer
from .selective import SelectiveTransfer
from .security import (
    BOOT_VERSION,
    CIPHER_CHACHAPOLY,
    MODE_NNPSK0,
    MODE_XX,
    MAX_PLAINTEXT_BYTES,
    PAYLOAD_FINISH,
    PAYLOAD_READY,
    AuthenticationError,
    AuthorizationError,
    BootstrapManager,
    FreshnessManager,
    FreshnessError,
    HandshakeError,
    ReplayError,
    SecurityAssociation,
    SecurityError,
    compute_bootstrap_epoch,
    compute_canonical_header,
    compute_origin_epoch,
    compute_prologue,
)
from .stream_r import StreamRDecoder, encode_stream_r


class _SequenceExhausted(SecurityError):
    """Internal signal that the SEC-1 association must be retired atomically."""


@dataclass
class _OutgoingDataTransfer:
    service_id: int
    seq: int
    namespace: int
    origin: int
    epoch: int
    destination: int
    payload: bytes
    ack_req: bool
    selective_state: SelectiveTransfer
    freshness_token: bytes | None = None
    association_h: bytes = b""
    possibly_transmitted: bool = False


class PeerEndpoint:
    """Independent DMP v2 peer exposing the DMP-PEER-TEST/1 API."""

    def __init__(
        self,
        manifest_bytes: bytes,
        test_credentials: Any,
        entropy_source: Callable[[int], bytes],
        test_services: Any,
        *,
        test_only_disable_sec1: bool = False,
    ) -> None:
        # Legacy P21B plaintext unit fixtures opt into this explicitly. P21C uses
        # the default secure path and cannot claim evidence from this bypass.
        self.manifest = identify_frozen_manifest(bytes(manifest_bytes))
        self.manifest_bytes = bytes(manifest_bytes)
        self.test_credentials = test_credentials
        self.entropy_source = entropy_source
        self.test_services = test_services

        # Extract manifest parameters
        ident = self.manifest.values["identity"]
        self.namespace = ident["namespace"]
        self.nodes = ident["nodes"]
        self.default_service = ident["default_service"]
        self.sample_producer_node = ident["sample_producer"]

        # Determine local and remote node identities
        if isinstance(test_credentials, dict):
            self.local_node_id = test_credentials.get(
                "node_id", test_credentials.get("local_node", self.nodes[0])
            )
            self.local_epoch = test_credentials.get("epoch", 7 if self.local_node_id == self.nodes[0] else 9)
            self.remote_epoch = test_credentials.get("remote_epoch", 9 if self.local_node_id == self.nodes[0] else 7)
        elif isinstance(test_credentials, int):
            self.local_node_id = test_credentials
            self.local_epoch = 7 if self.local_node_id == self.nodes[0] else 9
            self.remote_epoch = 9 if self.local_node_id == self.nodes[0] else 7
        else:
            self.local_node_id = self.nodes[0]
            self.local_epoch = 7
            self.remote_epoch = 9

        self.remote_node_id = next(n for n in self.nodes if n != self.local_node_id)

        # Binding configuration
        binding = self.manifest.values["binding"]
        self.binding_kind = binding["kind"]  # "stream-r" or "packet"
        self.forward_mtu = binding["forward_mtu"]
        self.return_mtu = binding["return_mtu"]
        self.encoded_mtu = binding["encoded_mtu"]

        # Limits and timing
        limits = self.manifest.values["limits"]
        timing = self.manifest.values["timing"]
        endpoint_resources = next(
            (r for r in self.manifest.values.get("resources", []) if r.get("role") == "endpoint"), {}
        )
        resource_slots = {
            item["component"]: item["count"]
            for item in endpoint_resources.get("charges", [])
        }

        self.reassembly = ReassemblyManager(
            max_message_bytes=limits["message_bytes"],
            max_fragments=limits["fragments"],
            assemblies_per_peer=limits["assemblies_per_peer"],
            tombstones_per_peer=limits["assembly_tombstones_per_peer"],
            assembly_ms=timing["assembly_ms"],
            tombstone_ms=timing["tombstone_ms"],
        )

        self.delivery = DeliveryManager(
            response_timeout_ms=timing["response_timeout_ms"],
            receipt_delay_ms=timing["receipt_delay_ms"],
            result_deadline_ms=timing["result_deadline_ms"],
            result_cache_ms=timing["result_cache_ms"],
            dedup_ms=timing["dedup_ms"],
            rejection_ms=timing["rejection_ms"],
            correlation_ms=timing["correlation_ms"],
            max_bursts=timing["max_bursts"],
            receipt_limit=timing["receipt_limit"],
            app_queue_slots=limits["application_queue_slots"],
            sender_slots=resource_slots.get("sender"),
            result_slots=resource_slots.get("result"),
            history_slots=resource_slots.get("history"),
            correlation_slots=resource_slots.get("correlation"),
        )
        self.outgoing_data: dict[tuple[bytes, int], _OutgoingDataTransfer] = {}
        self.adapter_slots = limits["adapter_slots"]
        self.max_queued_frames = (
            (resource_slots.get("sender", 0) + resource_slots.get("result", 0)) * limits["fragments"]
            + resource_slots.get("control", 0)
        )

        # SAMPLE-1 state
        sample_cfg = self.manifest.values.get("sample", {})
        init_attempts = sample_cfg.get("init_attempts", 1)
        init_retry_ms = sample_cfg.get("init_retry_ms", 5)
        init_deadline_ms = sample_cfg.get("init_deadline_ms", 12000)

        if self.local_node_id == self.sample_producer_node:
            init_epoch = 1
            if isinstance(test_credentials, dict) and "sample_epoch" in test_credentials:
                init_epoch = test_credentials["sample_epoch"]
            self.sample_epoch_store = SampleEpochStore(init_epoch)
            self.sample_producer: Optional[SampleProducer] = SampleProducer(self.sample_epoch_store)
            self.sample_consumer: Optional[SampleConsumer] = None
        else:
            self.sample_epoch_store = None
            self.sample_producer = None
            self.sample_consumer = SampleConsumer(
                max_attempts=init_attempts,
                init_retry_ms=init_retry_ms,
                init_deadline_ms=init_deadline_ms,
            )

        # Operational state
        self.is_open: bool = False
        self.link: Optional[int] = None
        self.deadline_capability: Optional[str] = None
        self.generation: int = 1
        self.next_handle: int = 1
        self.next_seq: int = 1
        self.next_exchange_id: int = 1
        self.now_ms: int = 0

        self.stream_r_decoder: Optional[StreamRDecoder] = None

        # Tracking active submission borrows
        self.active_submissions: dict[int, dict[str, Any]] = {}
        # Outgoing queued transmission frames
        self.tx_queue: list[dict[str, Any]] = []
        # Injected deterministic entropy history to prevent reuse
        self.used_entropy: set[bytes] = set()

        # Bounded local diagnostics and telemetry queue counters (§18.1, §18.2)
        self.sample_coalesced_count: int = 0
        self.sample_dropped_count: int = 0
        self.counters: dict[str, int] = {
            "coalesced_samples": 0,
            "dropped_samples": 0,
        }

        # SEC-1 security configuration
        sec_cfg = self.manifest.values.get("security", {})
        self.test_only_disable_sec1 = test_only_disable_sec1
        self.sec_mode_str = None if test_only_disable_sec1 else sec_cfg.get("mode")
        if self.sec_mode_str == "NNpsk0":
            self.sec_mode = MODE_NNPSK0
        elif self.sec_mode_str == "XX":
            self.sec_mode = MODE_XX
        else:
            self.sec_mode = None

        self.sec_cipher = sec_cfg.get("cipher", CIPHER_CHACHAPOLY)
        self.psk: bytes | None = None
        self.key_hint: int | None = None
        self.static_private_key: bytes | None = None
        self.peer_static_public_key: bytes | None = None
        self.local_rx_cid: int = 0

        if isinstance(test_credentials, dict):
            self.psk = test_credentials.get("psk")
            self.key_hint = test_credentials.get("key_hint")
            self.static_private_key = test_credentials.get("static_private_key")
            self.peer_static_public_key = test_credentials.get("peer_static_public_key")
            self.local_rx_cid = test_credentials.get("local_rx_cid", 0)

        if self.sec_mode == MODE_NNPSK0 and (not isinstance(self.psk, bytes) or len(self.psk) != 32):
            raise SecurityError("NNpsk0 requires a provisioned 32-byte pairwise PSK")
        if self.sec_mode == MODE_XX:
            if not isinstance(self.static_private_key, bytes) or len(self.static_private_key) != 32:
                raise SecurityError("XX requires a provisioned 32-byte local static private key")
            if self.peer_static_public_key is not None and (
                not isinstance(self.peer_static_public_key, bytes) or len(self.peer_static_public_key) != 32
            ):
                raise SecurityError("XX peer pin must be exactly 32 bytes")
        if self.sec_mode is not None and self.sec_cipher != CIPHER_CHACHAPOLY:
            raise SecurityError("This peer enables mandatory ChaChaPoly only")

        if self.sec_mode is not None:
            m_digest = bytes.fromhex(self.manifest.sha256) if getattr(self.manifest, "sha256", None) else b"\x00" * 32
            self.bootstrap_mgr: Optional[BootstrapManager] = BootstrapManager(
                mode=self.sec_mode,
                manifest_digest=m_digest,
                namespace=self.namespace,
                local_node_id=self.local_node_id,
                remote_node_id=self.remote_node_id,
                entropy_source=self.entropy_source,
                psk=self.psk,
                key_hint=self.key_hint,
                local_rx_cid=self.local_rx_cid,
                static_private_key=self.static_private_key,
                peer_static_public_key=self.peer_static_public_key,
                replay_window_bits=sec_cfg.get("replay_window_bits", 1024),
                failed_aead_limit=sec_cfg.get("failed_aead_limit", 1000),
                association_lifetime_ms=sec_cfg.get("association_ms", 100_000_000),
            )
            self.freshness_manager: Optional[FreshnessManager] = FreshnessManager(self.entropy_source)
        else:
            self.bootstrap_mgr = None
            self.freshness_manager = None

        self._active_association: Optional[SecurityAssociation] = None
        self._rx_association: Optional[SecurityAssociation] = None
        self._allow_draining_tx = False
        self.draining_associations: dict[int, SecurityAssociation] = {}
        self.pending_association: Optional[SecurityAssociation] = None
        self.active_freshness_token: Optional[bytes] = None

        # Confirmation timer state (§S4)
        self.confirmation_timeout_ms = sec_cfg.get("confirmation_timeout_ms", 512)
        self.confirmation_attempts = sec_cfg.get("confirmation_attempts", 2)
        self.confirmation_attempts_used: int = 0
        self.next_confirmation_retry_ms: Optional[int] = None
        self.cached_finish_wire: Optional[bytes] = None
        self.cached_ready_wire: Optional[bytes] = None
        self._processed_flight2_payload: Optional[bytes] = None
        self._processed_flight3_payload: Optional[bytes] = None
        # Manifest-bounded bootstrap admission and response accounting. State is
        # kept per endpoint/pair rather than keyed by attacker-controlled IDs.
        self._bootstrap_ingress_window_start_ms: int | None = None
        self._bootstrap_ingress_packets = 0
        self._bootstrap_response_window_start_ms: int | None = None
        self._bootstrap_response_count = 0
        self._bootstrap_response_bytes = 0
        self._bootstrap_attempt_id: bytes | None = None
        self._bootstrap_attempt_start_ms: int | None = None
        self._bootstrap_attempt_local_initiated = False
        self._bootstrap_attempt_tx_bytes = 0
        self._bootstrap_attempt_crypto_ms = 0
        self._bootstrap_duplicate_responses = 0
        self._bootstrap_flight1_wire: bytes | None = None
        self._bootstrap_flight_attempts_used = 0
        self._bootstrap_next_flight_retry_ms: int | None = None
        self._bootstrap_episode_start_ms: int | None = None
        self._bootstrap_episode_attempts = 0
        self._bootstrap_episode_tx_bytes = 0
        self._bootstrap_episode_crypto_ms = 0
        self._bootstrap_crypto_window_start_ms: int | None = None
        self._bootstrap_crypto_window_ms = 0
        self._bootstrap_later_window_start_ms: int | None = None
        self._bootstrap_later_episodes = 0
        self._bootstrap_last_attempt_end_ms: int | None = None

    @property
    def association(self) -> Optional[SecurityAssociation]:
        """Current association, or the CID-selected association during RX dispatch."""
        return self._rx_association or self._active_association

    @association.setter
    def association(self, value: Optional[SecurityAssociation]) -> None:
        self._active_association = value

    @property
    def local_epoch(self) -> int:
        assoc = getattr(self, "_rx_association", None)
        return assoc.local_epoch if assoc is not None else self._local_epoch

    @local_epoch.setter
    def local_epoch(self, value: int) -> None:
        self._local_epoch = value

    @property
    def remote_epoch(self) -> int:
        assoc = getattr(self, "_rx_association", None)
        return assoc.peer_epoch if assoc is not None else self._remote_epoch

    @remote_epoch.setter
    def remote_epoch(self, value: int) -> None:
        self._remote_epoch = value

    @property
    def next_seq(self) -> int:
        assoc = getattr(self, "_rx_association", None) or getattr(self, "_active_association", None)
        return assoc.next_send_seq if assoc is not None else self._next_seq

    @next_seq.setter
    def next_seq(self, value: int) -> None:
        assoc = getattr(self, "_rx_association", None)
        if assoc is not None:
            assoc.next_send_seq = value
        elif getattr(self, "_active_association", None) is not None:
            self._active_association.next_send_seq = value
        self._next_seq = value

    def _all_associations(self) -> tuple[SecurityAssociation, ...]:
        values = [self._active_association, self.pending_association, *self.draining_associations.values()]
        return tuple({id(item): item for item in values if item is not None}.values())

    def _association_by_cid(self, cid: int) -> SecurityAssociation | None:
        return next((item for item in self._all_associations() if item.local_rx_cid == cid), None)

    def _association_by_hash(self, association_h: bytes) -> SecurityAssociation | None:
        return next((item for item in self._all_associations() if item.h == association_h), None)

    def _clear_completed_bootstrap(self) -> None:
        if (self.bootstrap_mgr is not None and self.bootstrap_mgr.handshake_completed
                and self.pending_association is None):
            self.bootstrap_mgr.abort_attempt()
            self._end_bootstrap_attempt()
            self.cached_finish_wire = None
            self.cached_ready_wire = None
            self._processed_flight2_payload = None
            self._processed_flight3_payload = None

    @contextmanager
    def _use_association(self, assoc: SecurityAssociation | None, *, allow_draining: bool = False):
        previous = self._rx_association
        previous_allow = self._allow_draining_tx
        self._rx_association = assoc
        self._allow_draining_tx = allow_draining
        try:
            yield
        finally:
            self._rx_association = previous
            self._allow_draining_tx = previous_allow

    def _register_pending_association(self, assoc: SecurityAssociation) -> None:
        if self._association_by_cid(assoc.local_rx_cid) not in (None, assoc):
            raise SecurityError("Receive CID collides with a retained association")
        self.pending_association = assoc

    def _activate_pending_association(self, assoc: SecurityAssociation) -> None:
        if self.pending_association is not assoc:
            raise SecurityError("Only the current pending association can activate")
        old = self._active_association
        if old is not None and old is not assoc and old.status == "active":
            sec_cfg = self.manifest.values.get("security", {})
            draining_limit = sec_cfg.get("draining_per_pair", 0)
            if len(self.draining_associations) >= draining_limit:
                raise SecurityError("Draining association capacity is exhausted")
            old.begin_drain(self.now_ms, sec_cfg.get("drain_ms", 0))
            if old.status == "draining":
                self.draining_associations[old.local_rx_cid] = old
            else:
                self._close_association(old)
        assoc.status = "active"
        assoc.next_send_seq = 1
        self._active_association = assoc
        self.pending_association = None
        self._next_seq = 1
        self._local_epoch = assoc.local_epoch
        self._remote_epoch = assoc.peer_epoch

    def _close_association(self, assoc: SecurityAssociation) -> None:
        assoc.status = "closed"
        self.draining_associations.pop(assoc.local_rx_cid, None)
        if self.freshness_manager is not None:
            self.freshness_manager.clear_association(assoc.h)

    def revoke_peer_credential(self, peer_static_public_key: bytes | None = None) -> tuple[Any, ...]:
        """Trusted local revocation; no received protocol message calls this API."""
        if self.bootstrap_mgr is None or self.sec_mode != MODE_XX:
            raise AuthorizationError("Trusted credential revocation is available only for XX")
        key = self.peer_static_public_key if peer_static_public_key is None else peer_static_public_key
        if key is None or key not in self.bootstrap_mgr.committed_pins:
            raise AuthorizationError("Peer credential is not currently authorized")
        self.bootstrap_mgr.committed_pins.discard(key)
        if self.peer_static_public_key == key:
            self.peer_static_public_key = None
            self.bootstrap_mgr.peer_static_public_key = None
        out: list[Any] = []
        # Revocation is immediate: old operation outcomes are unknown, never
        # migrated to another credential or association.
        for exc in list(self.delivery.active_outgoing.values()):
            possible = exc.possibly_transmitted or bool(exc.admitted_schedule_handles)
            out.append(ApplicationEvent(
                kind="diagnostic" if possible else "protocol_rejection",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=0 if possible else 4,
                payload=b"unknown" if possible else b"revoked",
                at_ms=self.now_ms,
            ))
        for handle, sub in self.active_submissions.items():
            if sub.get("association_h") and not sub.get("cancel_requested"):
                sub["cancel_requested"] = True
                if sub.get("admitted"):
                    out.append(Cancel(handle=handle, generation=sub["generation"], at_ms=self.now_ms))
        self.tx_queue = [item for item in self.tx_queue if not item.get("association_h")]
        self._retire_security_context()
        self._retire_delivery_state()
        self.reassembly.retire()
        return tuple(out)

    def _alloc_handle(self) -> int:
        handle = self.next_handle
        self.next_handle = (self.next_handle + 1) & 0xFFFFFFFF
        if self.next_handle == 0:
            self.next_handle = 1
        return handle

    def approve_oob_peer_static_key(self, peer_static_public_key: bytes) -> None:
        """Install the 32-byte XX peer key after the operator verifies it out of band."""
        if self.bootstrap_mgr is None or self.sec_mode != MODE_XX:
            raise AuthorizationError("OOB peer-key approval is available only for XX")
        if self.association is not None or self.pending_association is not None:
            raise AuthorizationError("Cannot enroll an XX peer while an association exists")
        self.bootstrap_mgr.approve_oob_peer_static_key(peer_static_public_key)
        self.peer_static_public_key = bytes(peer_static_public_key)

    def _alloc_seq(self) -> int:
        seq = self.next_seq
        if seq > 0xFFFFFFFF:
            # The event boundary performs bounded teardown, cancellation, and
            # reports a terminal result. Never permit any recovery profile to wrap.
            for assoc in (self.association, self.pending_association):
                if assoc is not None:
                    assoc.status = "closed"
            raise _SequenceExhausted("association SEQ space is exhausted")
        self.next_seq = seq + 1
        return seq

    def _routed_fields(self) -> tuple[Route | None, Extension | None]:
        """Return the frozen explicit ROUTE/CONTEXT pair for a routed test profile."""
        topology = self.manifest.values.get("binding", {}).get("topology")
        if topology not in ("static-unicast", "relay-routed"):
            return None, None
        ttl = self.manifest.values.get("binding", {}).get("ttl", 0)
        route = Route(ttl=ttl, mode=1, source_id=self.local_node_id,
                      destination_id=self.remote_node_id)
        assoc = self.association or self.pending_association
        epoch = assoc.local_epoch if assoc is not None else self.local_epoch
        context = Extension(
            2, True, True, encode_uleb(self.namespace) + epoch.to_bytes(8, "little")
        )
        return route, context

    def _selective_enabled(self, service_id: int) -> bool:
        service = next((s for s in self.manifest.values.get("services", [])
                        if s.get("id") == service_id), None)
        return bool(service and service.get("recovery") == "selective-32")

    def _new_selective_transfer(self, fragment_count: int) -> SelectiveTransfer:
        timing = self.manifest.values["timing"]
        return SelectiveTransfer(
            fragment_count=fragment_count,
            started_at_ms=self.now_ms,
            send_horizon_ms=timing["send_horizon_ms"],
            response_timeout_ms=timing["response_timeout_ms"],
            max_bursts=timing["max_bursts"],
            max_probes=timing["max_probes"],
            max_status=timing["max_status"],
            burst_starts_ms=tuple(timing["burst_starts_ms"]),
            frames_remaining=fragment_count,
        )

    def _alloc_exchange_id(self) -> int:
        eid = self.next_exchange_id
        self.next_exchange_id += 1
        return eid

    def _admit_bootstrap_ingress(self) -> bool:
        cfg = self.manifest.values.get("security", {})
        window_ms = cfg.get("ingress_window_ms", 1)
        if (self._bootstrap_ingress_window_start_ms is None
                or self.now_ms - self._bootstrap_ingress_window_start_ms >= window_ms):
            self._bootstrap_ingress_window_start_ms = self.now_ms
            self._bootstrap_ingress_packets = 0
        if self._bootstrap_ingress_packets >= cfg.get("ingress_packets_per_window", 1):
            return False
        self._bootstrap_ingress_packets += 1
        return True

    def _begin_bootstrap_attempt(self, attempt_id: bytes, *, local_initiated: bool) -> bool:
        cfg = self.manifest.values.get("security", {})
        if self._bootstrap_attempt_id is not None:
            return self._bootstrap_attempt_id == attempt_id
        if local_initiated:
            if (self._bootstrap_last_attempt_end_ms is not None
                    and self.now_ms - self._bootstrap_last_attempt_end_ms < cfg.get("restart_backoff_ms", 0)):
                return False

            episode_ms = cfg.get("episode_ms", 1)
            if (self._bootstrap_episode_start_ms is None
                    or self.now_ms - self._bootstrap_episode_start_ms >= episode_ms):
                if self._bootstrap_episode_start_ms is not None:
                    later_window_ms = cfg.get("later_window_ms", episode_ms)
                    if (self._bootstrap_later_window_start_ms is None
                            or self.now_ms - self._bootstrap_later_window_start_ms >= later_window_ms):
                        self._bootstrap_later_window_start_ms = self.now_ms
                        self._bootstrap_later_episodes = 0
                    if self._bootstrap_later_episodes >= cfg.get("later_episodes_per_window", 1):
                        return False
                    self._bootstrap_later_episodes += 1
                self._bootstrap_episode_start_ms = self.now_ms
                self._bootstrap_episode_attempts = 0
                self._bootstrap_episode_tx_bytes = 0
                self._bootstrap_episode_crypto_ms = 0
            if self._bootstrap_episode_attempts >= cfg.get("episode_attempts", 1):
                return False
            self._bootstrap_episode_attempts += 1
        self._bootstrap_attempt_id = attempt_id
        self._bootstrap_attempt_start_ms = self.now_ms
        self._bootstrap_attempt_local_initiated = local_initiated
        self._bootstrap_attempt_tx_bytes = 0
        self._bootstrap_attempt_crypto_ms = 0
        self._bootstrap_duplicate_responses = 0
        self._bootstrap_flight1_wire = None
        self._bootstrap_flight_attempts_used = 0
        self._bootstrap_next_flight_retry_ms = None
        return True

    def _bootstrap_attempt_expired(self, attempt_id: bytes) -> bool:
        cfg = self.manifest.values.get("security", {})
        return (
            self._bootstrap_attempt_id == attempt_id
            and self._bootstrap_attempt_start_ms is not None
            and self.now_ms - self._bootstrap_attempt_start_ms >= cfg.get("attempt_ms", 1)
        )

    def _bootstrap_attempt_deadline(self, attempt_id: bytes) -> int | None:
        if self._bootstrap_attempt_id != attempt_id or self._bootstrap_attempt_start_ms is None:
            return None
        return self._bootstrap_attempt_start_ms + self.manifest.values.get("security", {}).get("attempt_ms", 1)

    def _end_bootstrap_attempt(self) -> None:
        if self._bootstrap_attempt_id is not None and self._bootstrap_attempt_local_initiated:
            self._bootstrap_last_attempt_end_ms = self.now_ms
        self._bootstrap_attempt_id = None
        self._bootstrap_attempt_start_ms = None
        self._bootstrap_attempt_local_initiated = False
        self._bootstrap_attempt_tx_bytes = 0
        self._bootstrap_attempt_crypto_ms = 0
        self._bootstrap_duplicate_responses = 0
        self._bootstrap_flight1_wire = None
        self._bootstrap_flight_attempts_used = 0
        self._bootstrap_next_flight_retry_ms = None

    def _abort_bootstrap_attempt(self, out: list[Any]) -> None:
        """Erase one bootstrap attempt and retire only its queued or borrowed TX."""
        attempt_id = self._bootstrap_attempt_id
        if attempt_id is None and self.bootstrap_mgr is not None:
            attempt_id = self.bootstrap_mgr.current_attempt_id
        if attempt_id is not None:
            self.tx_queue = [
                item for item in self.tx_queue
                if item.get("bootstrap_attempt_id") != attempt_id
            ]
            for handle, sub in list(self.active_submissions.items()):
                if sub.get("bootstrap_attempt_id") != attempt_id or sub.get("cancel_requested"):
                    continue
                sub["cancel_requested"] = True
                if sub.get("admitted"):
                    out.append(Cancel(handle=handle, generation=sub["generation"], at_ms=self.now_ms))
        if self.bootstrap_mgr is not None:
            self.bootstrap_mgr.abort_attempt()
        if self.pending_association is not None:
            self.pending_association.status = "closed"
            if self.freshness_manager is not None:
                self.freshness_manager.clear_association(self.pending_association.h)
        self.pending_association = None
        self.cached_finish_wire = None
        self.cached_ready_wire = None
        self._processed_flight2_payload = None
        self._processed_flight3_payload = None
        self.next_confirmation_retry_ms = None
        self.confirmation_attempts_used = 0
        self._end_bootstrap_attempt()
        self._drain_tx_queue(out)

    def _start_bootstrap_crypto(self) -> int | None:
        cfg = self.manifest.values.get("security", {})
        window_ms = cfg.get("ingress_window_ms", 1)
        if (self._bootstrap_crypto_window_start_ms is None
                or self.now_ms - self._bootstrap_crypto_window_start_ms >= window_ms):
            self._bootstrap_crypto_window_start_ms = self.now_ms
            self._bootstrap_crypto_window_ms = 0
        if self._bootstrap_attempt_id is None:
            return None
        if self._bootstrap_crypto_window_ms >= cfg.get("global_crypto_ms_per_window", 1):
            return None
        if self._bootstrap_attempt_crypto_ms >= cfg.get("crypto_per_attempt_ms", 1):
            return None
        if (self._bootstrap_attempt_local_initiated
                and self._bootstrap_episode_crypto_ms >= cfg.get("episode_crypto_ms", 1)):
            return None
        return time.process_time_ns()

    def _finish_bootstrap_crypto(self, start_ns: int) -> bool:
        cfg = self.manifest.values.get("security", {})
        spent_ms = max(1, (time.process_time_ns() - start_ns + 999_999) // 1_000_000)
        self._bootstrap_crypto_window_ms += spent_ms
        self._bootstrap_attempt_crypto_ms += spent_ms
        if self._bootstrap_attempt_local_initiated:
            self._bootstrap_episode_crypto_ms += spent_ms
        return (
            self._bootstrap_crypto_window_ms <= cfg.get("global_crypto_ms_per_window", 1)
            and self._bootstrap_attempt_crypto_ms <= cfg.get("crypto_per_attempt_ms", 1)
            and (not self._bootstrap_attempt_local_initiated
                 or self._bootstrap_episode_crypto_ms <= cfg.get("episode_crypto_ms", 1))
        )

    def _admit_bootstrap_duplicate_response(self) -> bool:
        maximum = self.manifest.values.get("security", {}).get("duplicate_responses_per_attempt", 0)
        if self._bootstrap_duplicate_responses >= maximum:
            return False
        self._bootstrap_duplicate_responses += 1
        return True

    def _enqueue_bootstrap_tx(self, raw_bytes: bytes, attempt_id: bytes, out: list[Any]) -> bool:
        cfg = self.manifest.values.get("security", {})
        if self._bootstrap_attempt_id != attempt_id:
            return False
        attempt_deadline_ms = self._bootstrap_attempt_deadline(attempt_id)
        if attempt_deadline_ms is None or self.now_ms >= attempt_deadline_ms:
            self._abort_bootstrap_attempt(out)
            return False
        if self.binding_kind == "stream-r":
            accounted_bytes = len(encode_stream_r(raw_bytes, max_core=self.forward_mtu, max_encoded=self.encoded_mtu))
        else:
            accounted_bytes = len(raw_bytes)

        window_ms = cfg.get("response_window_ms", 1)
        if (self._bootstrap_response_window_start_ms is None
                or self.now_ms - self._bootstrap_response_window_start_ms >= window_ms):
            self._bootstrap_response_window_start_ms = self.now_ms
            self._bootstrap_response_count = 0
            self._bootstrap_response_bytes = 0
        if self._bootstrap_response_count >= cfg.get("responses_per_window", 1):
            return False
        if self._bootstrap_response_bytes + accounted_bytes > cfg.get("response_bytes_per_window", 1):
            return False
        if self._bootstrap_attempt_tx_bytes + accounted_bytes > cfg.get("attempt_tx_bytes", 1):
            return False
        if (self._bootstrap_attempt_local_initiated
                and self._bootstrap_episode_tx_bytes + accounted_bytes > cfg.get("episode_tx_bytes", 1)):
            return False

        self._bootstrap_response_count += 1
        self._bootstrap_response_bytes += accounted_bytes
        self._bootstrap_attempt_tx_bytes += accounted_bytes
        if self._bootstrap_attempt_local_initiated:
            self._bootstrap_episode_tx_bytes += accounted_bytes
        self._enqueue_tx(
            raw_bytes,
            not_after_ms=attempt_deadline_ms,
            service_id=0,
            bootstrap_attempt_id=attempt_id,
            out=out,
        )
        return True

    def handle(self, input_event: Any) -> tuple:
        """Process one input event and return an ordered tuple of output events."""
        # Cancellation is a peer output event per P20, not a controller input
        if isinstance(input_event, Cancel):
            raise EventValidationError("Cancel is a peer output event, not a controller input")

        # Validation and monotonic time check
        if not isinstance(
            input_event,
            (Open, Receive, Advance, TxAdmit, TxTerminal, Disconnect, Restart, ApplicationRequest, PublishSample),
        ):
            raise EventValidationError(f"unsupported input event: {type(input_event).__name__}")

        # Check state before mutating
        if isinstance(input_event, Open):
            if self.is_open:
                raise EventValidationError("endpoint is already open")
            if self.binding_kind == "stream-r":
                if input_event.deadline_capability != "strict_latest_start":
                    raise ValueError("Stream R profile requires strict_latest_start capability")
        elif isinstance(input_event, Receive):
            if not self.is_open:
                raise EventValidationError("endpoint is not open for Receive")

        if isinstance(input_event, (TxAdmit, TxTerminal)):
            if input_event.handle not in self.active_submissions:
                raise EventValidationError(f"unknown submission handle {input_event.handle}")
            sub = self.active_submissions[input_event.handle]
            if (isinstance(input_event, TxTerminal)
                    and not sub.get("admitted")
                    and not sub.get("cancel_requested")):
                return ()
            if isinstance(input_event, TxAdmit) and (sub.get("admitted") or sub.get("admit_resolved")):
                return ()

        if isinstance(input_event, Restart):
            if not input_event.entropy or len(input_event.entropy) < 8:
                raise EventValidationError("Restart requires at least 8 bytes of entropy")
            if input_event.entropy in self.used_entropy:
                raise EventValidationError("Restart entropy has already been used")

        # Monotonic time check
        event_time = getattr(input_event, "at_ms", getattr(input_event, "now_ms", None))
        if event_time is not None:
            if event_time < self.now_ms:
                raise ValueError(f"time cannot move backwards: current {self.now_ms}, event {event_time}")
            self.now_ms = event_time

        output_events: list[Any] = []

        existing_handles = set(self.active_submissions)
        try:
            if isinstance(input_event, Open):
                self._handle_open(input_event, output_events)
            elif isinstance(input_event, Advance):
                self._handle_advance(input_event, output_events)
            elif isinstance(input_event, TxAdmit):
                self._handle_tx_admit(input_event, output_events)
            elif isinstance(input_event, TxTerminal):
                self._handle_tx_terminal(input_event, output_events)
            elif isinstance(input_event, Receive):
                self._handle_receive(input_event, output_events)
            elif isinstance(input_event, Disconnect):
                self._handle_disconnect(input_event, output_events)
            elif isinstance(input_event, Restart):
                self._handle_restart(input_event, output_events)
            elif isinstance(input_event, ApplicationRequest):
                self._handle_application_request(input_event, output_events)
            elif isinstance(input_event, PublishSample):
                self._handle_publish_sample(input_event, output_events)
        except _SequenceExhausted:
            # A submission built during this input was never returned to the
            # adapter. Remove it before teardown so no invisible borrow is kept.
            unpublished = set(self.active_submissions) - existing_handles
            for handle in unpublished:
                self.active_submissions.pop(handle, None)
            output_events[:] = [
                event for event in output_events
                if not (isinstance(event, TxSubmit) and event.handle in unpublished)
            ]
            self._expire_security_context(output_events, cancel_unadmitted=True)
            if isinstance(input_event, ApplicationRequest):
                output_events.append(ApplicationEvent(
                    kind="protocol_rejection",
                    service_id=input_event.service_id,
                    exchange_id=input_event.exchange_id or max(0, self.next_exchange_id - 1),
                    status=4,
                    payload=b"sequence_exhausted",
                    at_ms=self.now_ms,
                ))
            else:
                output_events.append(ApplicationEvent(
                    kind="diagnostic",
                    service_id=0,
                    exchange_id=0,
                    status=0,
                    payload=b"sequence_exhausted",
                    at_ms=self.now_ms,
                ))

        # Enforce contract bounds: at most 4,096 events and 1 MiB byte payload
        if len(output_events) > 4096:
            raise RuntimeError("endpoint output exceeded 4,096 events")
        total_bytes = sum(len(getattr(e, "bytes", b"")) + len(getattr(e, "payload", b"")) for e in output_events)
        if total_bytes > 1_048_576:
            raise RuntimeError("endpoint output exceeded 1 MiB byte payload")

        return tuple(output_events)

    def _handle_open(self, event: Open, out: list[Any]) -> None:
        self.is_open = True
        self.link = event.link
        self.deadline_capability = event.deadline_capability

        if self.binding_kind == "stream-r":
            timing = self.manifest.values["timing"]
            cand_timeout = (
                self.manifest.values["binding"]["frame_tx_ms"]
                + max(timing["forward_delay_ms"], timing["return_delay_ms"])
                + timing["record_margin_ms"]
            )
            self.stream_r_decoder = StreamRDecoder(
                max_encoded=self.encoded_mtu,
                max_core=self.forward_mtu,
                candidate_timeout_ms=cand_timeout,
                await_sync=True,
            )
            # Emit initial sync delimiter b"\x00"
            self._enqueue_tx(b"\x00", not_after_ms=None, out=out)

        if self.sample_consumer is not None:
            # Consumer starts initialization on open
            self.sample_consumer.start_initialization(association_id=1, at_ms=self.now_ms)

    def _handle_tx_admit(self, event: TxAdmit, out: list[Any]) -> None:
        sub = self.active_submissions.get(event.handle)
        if not sub or sub["generation"] != event.generation:
            return  # Stale admit: ignored without error

        exc_id = sub.get("exchange_id")
        exc = self.delivery.active_outgoing.get(exc_id) if exc_id else None
        recovery_seq = sub.get("recovery_seq")

        sub["admit_resolved"] = True
        if event.accepted:
            sub["admitted"] = True
            if exc:
                exc.admitted_schedule_handles.add(event.handle)
            if sub.get("cancel_requested") and not sub.get("cancel_emitted"):
                out.append(Cancel(handle=event.handle, generation=event.generation, at_ms=self.now_ms))
                sub["cancel_emitted"] = True
        else:
            # Rejected by adapter: caller retains ownership; no subsequent terminal event
            del self.active_submissions[event.handle]
            bootstrap_attempt_id = sub.get("bootstrap_attempt_id")
            if bootstrap_attempt_id is not None:
                if event.reason != "busy" and self._bootstrap_attempt_id == bootstrap_attempt_id:
                    self._abort_bootstrap_attempt(out)
                self._drain_tx_queue(out)
                return
            if exc:
                exc.pending_schedule_handles.discard(event.handle)
                exc.admitted_schedule_handles.discard(event.handle)
                if not exc.pending_schedule_handles and (exc.queued_schedule_frames or any(self.active_submissions.get(h, {}).get("admitted") for h in exc.active_submission_handles)):
                    exc.schedule_admitted = True
                    exc.next_retry_ms = self.now_ms + exc.response_timeout_ms
                elif not exc.pending_schedule_handles and not exc.admitted_schedule_handles and not exc.queued_schedule_frames:
                    # All slices rejected or single-frame exchange rejected
                    if event.reason == "busy" and exc.attempts_used < exc.max_attempts:
                        exc.schedule_admitted = True
                        exc.next_retry_ms = self.now_ms + exc.response_timeout_ms
                    else:
                        is_expired = (event.reason == "expired")
                        exc.state = "expired" if is_expired else "failed"
                        self.delivery.active_outgoing.pop(exc_id, None)
                        self.delivery._release_gate(exc)
                        if exc.service_id == 1 and self.sample_consumer and exc.request_payload == b"\x01":
                            if self.sample_consumer.designated_request_seq == exc.seq:
                                self.sample_consumer.designated_request_seq = None
                        reason_payload = b"local_expiry" if is_expired else (
                            event.reason.encode("utf-8") if isinstance(event.reason, str) else b"tx_rejected"
                        )
                        out.append(ApplicationEvent(
                            kind="diagnostic",
                            service_id=exc.service_id,
                            exchange_id=exc_id,
                            status=0,
                            payload=reason_payload,
                            at_ms=self.now_ms,
                        ))
            elif event.reason == "expired":
                out.append(ApplicationEvent(
                    kind="diagnostic",
                    service_id=sub.get("service_id", 1),
                    exchange_id=exc_id or 0,
                    status=0,
                    payload=b"local_expiry",
                    at_ms=self.now_ms,
                ))
            elif event.reason:
                out.append(ApplicationEvent(
                    kind="diagnostic",
                    service_id=sub.get("service_id", 1),
                    exchange_id=exc_id or 0,
                    status=0,
                    payload=event.reason.encode("utf-8") if isinstance(event.reason, str) else b"tx_rejected",
                    at_ms=self.now_ms,
                ))
            if exc is not None and exc.selective_state is not None:
                exc.selective_state.terminate()
                if exc_id in self.delivery.active_outgoing:
                    self._retire_selective_attempts(exc.seq, out, association_h=exc.association_h)
                    exc.state = "failed"
                    self.delivery.active_outgoing.pop(exc_id, None)
                    self.delivery._release_gate(exc)
                    uncertain = exc.possibly_transmitted or bool(exc.admitted_schedule_handles)
                    out.append(ApplicationEvent(
                        kind="diagnostic" if uncertain else "protocol_rejection",
                        service_id=exc.service_id,
                        exchange_id=exc.exchange_id,
                        status=0 if uncertain else 4,
                        payload=b"unknown" if uncertain else b"tx_rejected",
                        at_ms=self.now_ms,
                    ))
            elif recovery_seq is not None:
                association_h = sub.get("association_h", b"")
                matched = self._selective_transfer_for_sequence(recovery_seq, association_h)
                if matched is not None:
                    kind, owner = matched
                    self._retire_selective_attempts(recovery_seq, out, association_h=association_h)
                    owner.selective_state.terminate()
                    if hasattr(owner, "attempts_left"):
                        owner.attempts_left = 0
                    if kind == "data":
                        self.outgoing_data.pop((association_h, recovery_seq), None)
            self._drain_tx_queue(out)

    def _handle_tx_terminal(self, event: TxTerminal, out: list[Any]) -> None:
        sub = self.active_submissions.get(event.handle)
        if not sub or sub["generation"] != event.generation:
            # Stale completion: must not free current slot!
            return

        del self.active_submissions[event.handle]

        bootstrap_attempt_id = sub.get("bootstrap_attempt_id")
        if (bootstrap_attempt_id is not None
                and bootstrap_attempt_id == self._bootstrap_attempt_id
                and event.outcome not in ("transmitted", "possibly_transmitted")):
            self._abort_bootstrap_attempt(out)
            return

        exc_id = sub.get("exchange_id")
        exc = self.delivery.active_outgoing.get(exc_id) if exc_id else None
        recovery_seq = sub.get("recovery_seq")

        if exc:
            exc.pending_schedule_handles.discard(event.handle)
            exc.admitted_schedule_handles.discard(event.handle)

        if event.outcome in ("transmitted", "possibly_transmitted"):
            # Successfully handed to physical/link layer
            if exc:
                exc.possibly_transmitted = True
                if not exc.pending_schedule_handles and not exc.queued_schedule_frames and not exc.schedule_admitted:
                    exc.schedule_admitted = True
                    exc.next_retry_ms = self.now_ms + exc.response_timeout_ms
            elif recovery_seq is not None:
                association_h = sub.get("association_h", b"")
                matched = self._selective_transfer_for_sequence(recovery_seq, association_h)
                if matched is not None and matched[0] == "data":
                    matched[1].possibly_transmitted = True
            self._settle_selective_frame(recovery_seq, sub.get("association_h", b""), out)
        elif event.outcome in ("expired_unsent", "cancelled_unsent", "failed_unsent"):
            if exc:
                if exc.selective_state is not None:
                    exc.selective_state.terminate()
                self._retire_exchange_attempts(exc, out, trigger_handle=event.handle)
                exc.state = "expired" if event.outcome == "expired_unsent" else "failed"
                self.delivery.active_outgoing.pop(exc_id, None)
                self.delivery._release_gate(exc)
                if exc.service_id == 1 and self.sample_consumer and exc.request_payload == b"\x01":
                    if self.sample_consumer.designated_request_seq == exc.seq:
                        self.sample_consumer.designated_request_seq = None
                may_have_reached_peer = exc.possibly_transmitted or bool(exc.admitted_schedule_handles)
                if may_have_reached_peer:
                    out.append(ApplicationEvent(kind="diagnostic", service_id=exc.service_id, exchange_id=exc.exchange_id, status=0, payload=b"unknown", at_ms=self.now_ms))
                elif event.outcome == "expired_unsent":
                    out.append(ApplicationEvent(kind="protocol_rejection", service_id=exc.service_id, exchange_id=exc.exchange_id, status=4, payload=b"expired", at_ms=self.now_ms))
                else:
                    out.append(ApplicationEvent(kind="diagnostic", service_id=exc.service_id, exchange_id=exc.exchange_id, status=0, payload=event.outcome.encode("utf-8"), at_ms=self.now_ms))
            elif recovery_seq is not None:
                association_h = sub.get("association_h", b"")
                matched = self._selective_transfer_for_sequence(recovery_seq, association_h)
                if matched is not None:
                    kind, owner = matched
                    self._retire_selective_attempts(recovery_seq, out, association_h=association_h)
                    owner.selective_state.terminate()
                    if hasattr(owner, "attempts_left"):
                        owner.attempts_left = 0
                    if kind == "data":
                        self.outgoing_data.pop((association_h, recovery_seq), None)

        self._drain_tx_queue(out)

    def _retire_exchange_attempts(
        self,
        exc: OutgoingExchange,
        out: list[Any],
        trigger_handle: int | None = None,
        *,
        cancel_unadmitted: bool = False,
    ) -> None:
        kept = []
        for item in self.tx_queue:
            if item.get("exchange_id") == exc.exchange_id:
                exc.queued_schedule_frames = max(0, exc.queued_schedule_frames - 1)
            else:
                kept.append(item)
        self.tx_queue = kept
        for handle in exc.active_submission_handles:
            sub = self.active_submissions.get(handle)
            if (handle != trigger_handle and sub
                    and (cancel_unadmitted or sub.get("admitted"))
                    and not sub.get("cancel_emitted")):
                sub["cancel_requested"] = True
                out.append(Cancel(handle=handle, generation=sub["generation"], at_ms=self.now_ms))
                sub["cancel_emitted"] = True

    def _expire_outgoing_exchange(self, exc: OutgoingExchange, out: list[Any]) -> None:
        if exc.selective_state is not None:
            exc.selective_state.terminate()
        self._retire_exchange_attempts(exc, out)
        exc.state = "expired"
        self.delivery.active_outgoing.pop(exc.exchange_id, None)
        self.delivery._release_gate(exc)
        if exc.service_id == 1 and self.sample_consumer and exc.request_payload == b"\x01":
            if self.sample_consumer.designated_request_seq == exc.seq:
                self.sample_consumer.designated_request_seq = None
        may_have_reached_peer = (
            exc.possibly_transmitted
            or bool(exc.admitted_schedule_handles)
            or any(self.active_submissions.get(h, {}).get("admitted") for h in exc.active_submission_handles)
        )
        if may_have_reached_peer:
            out.append(ApplicationEvent(
                kind="diagnostic",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=0,
                payload=b"unknown",
                at_ms=self.now_ms,
            ))
        else:
            out.append(ApplicationEvent(
                kind="protocol_rejection",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=4,
                payload=b"expired",
                at_ms=self.now_ms,
            ))

    def _complete_outgoing_exchange(self, exc: OutgoingExchange, out: list[Any]) -> None:
        if exc.selective_state is not None:
            exc.selective_state.terminate()
            self._retire_selective_attempts(exc.seq, out, association_h=exc.association_h)
        self._retire_exchange_attempts(exc, out)
        self.delivery.complete_exchange(exc)
        if exc.service_id == 1 and self.sample_consumer and exc.request_payload == b"\x01":
            if self.sample_consumer.designated_request_seq == exc.seq:
                self.sample_consumer.designated_request_seq = None

    def _handle_disconnect(self, event: Disconnect, out: list[Any]) -> None:
        for exc in list(self.delivery.active_outgoing.values()):
            possible = exc.possibly_transmitted or bool(exc.admitted_schedule_handles)
            out.append(ApplicationEvent(
                kind="diagnostic" if possible else "protocol_rejection",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=0 if possible else 4,
                payload=b"unknown" if possible else b"cancelled",
                at_ms=self.now_ms,
            ))
        for exc in self.delivery.queue:
            out.append(ApplicationEvent(
                kind="protocol_rejection",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=4,
                payload=b"cancelled",
                at_ms=self.now_ms,
            ))
        self.is_open = False
        self.generation = (self.generation + 1) & 0xFFFFFFFF
        for handle, sub in self.active_submissions.items():
            if sub.get("admitted") and not sub.get("cancel_requested"):
                sub["cancel_requested"] = True
                out.append(Cancel(handle=handle, generation=sub["generation"], at_ms=self.now_ms))
        # Accepted borrows stay retained until the generation-matched terminal callback.
        self.active_submissions = {h: sub for h, sub in self.active_submissions.items() if sub.get("admitted")}
        self.tx_queue.clear()
        self._retire_security_context()
        self._retire_delivery_state()
        self.reassembly.retire()
        if self.sample_consumer:
            self.sample_consumer.start_initialization(association_id=self.generation, at_ms=self.now_ms)

    def _retire_delivery_state(self) -> None:
        self.delivery.active_outgoing.clear()
        self.delivery.active_per_dest_service.clear()
        self.delivery.result_gates.clear()
        self.delivery.queue.clear()
        self.delivery.retained_results.clear()
        self.delivery.accepted_messages.clear()
        self.delivery.rejections.clear()
        self.delivery.caller_tombstones.clear()

    def _retire_security_context(self) -> None:
        """Destroy volatile SEC-1 state whenever its complete context is not retained."""
        self._end_bootstrap_attempt()
        for assoc in self._all_associations():
            self._close_association(assoc)
        self.association = None
        self.pending_association = None
        self.draining_associations.clear()
        for transfer in self.outgoing_data.values():
            transfer.selective_state.terminate()
        self.outgoing_data.clear()
        if self.bootstrap_mgr is not None:
            self.bootstrap_mgr.abort_attempt()
        self.active_freshness_token = None
        self.cached_finish_wire = None
        self.cached_ready_wire = None
        self._processed_flight2_payload = None
        self._processed_flight3_payload = None
        self.next_confirmation_retry_ms = None
        self.confirmation_attempts_used = 0

    def _expire_draining_association(self, assoc: SecurityAssociation, out: list[Any]) -> None:
        """Cancel old-key work at its fixed drain boundary and retire its state."""
        for exc in list(self.delivery.active_outgoing.values()):
            if exc.association_h != assoc.h:
                continue
            self._retire_exchange_attempts(exc, out, cancel_unadmitted=True)
            self.delivery.active_outgoing.pop(exc.exchange_id, None)
            self.delivery._release_gate(exc)
            exc.state = "failed"
            uncertain = exc.possibly_transmitted or bool(exc.admitted_schedule_handles)
            out.append(ApplicationEvent(
                kind="diagnostic" if uncertain else "protocol_rejection",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=0 if uncertain else 4,
                payload=b"unknown" if uncertain else b"drain_expired",
                at_ms=self.now_ms,
            ))
        for queued in list(self.delivery.queue):
            if queued.association_h == assoc.h:
                self.delivery.queue.remove(queued)
                out.append(ApplicationEvent(
                    kind="protocol_rejection", service_id=queued.service_id,
                    exchange_id=queued.exchange_id, status=4,
                    payload=b"drain_expired", at_ms=self.now_ms,
                ))
        for key, result in list(self.delivery.retained_results.items()):
            if result.association_h == assoc.h:
                del self.delivery.retained_results[key]
                self.delivery.release_result_gate(key)
        for seq, transfer in list(self.outgoing_data.items()):
            if transfer.association_h == assoc.h:
                transfer.selective_state.terminate()
                del self.outgoing_data[seq]
                out.append(ApplicationEvent(
                    kind="diagnostic", service_id=transfer.service_id, exchange_id=0,
                    status=0, payload=b"unknown", at_ms=self.now_ms,
                ))
        self.tx_queue = [item for item in self.tx_queue if item.get("association_h") != assoc.h]
        for handle, sub in list(self.active_submissions.items()):
            if sub.get("association_h") != assoc.h or sub.get("cancel_requested"):
                continue
            sub["cancel_requested"] = True
            if sub.get("admitted"):
                out.append(Cancel(handle=handle, generation=sub["generation"], at_ms=self.now_ms))
        self._close_association(assoc)

    def _handle_restart(self, event: Restart, out: list[Any]) -> None:
        # Restart uses injected deterministic entropy; fails closed when absent or reused
        if not event.entropy or len(event.entropy) < 8:
            raise EventValidationError("Restart requires at least 8 bytes of entropy")
        if event.entropy in self.used_entropy:
            raise EventValidationError("Restart entropy has already been used")
        self.used_entropy.add(event.entropy)

        # Restart never resumes a bootstrap attempt, even if Split has not occurred.
        self._retire_security_context()

        # Establish non-reused logical identity before any new SEQ
        seed = int.from_bytes(event.entropy[:8], "little")
        epoch_delta = (seed & 0xFFFFFF) + 1
        self.local_epoch = (self.local_epoch + epoch_delta) & 0xFFFFFFFFFFFFFFFF
        if self.local_epoch == 0:
            self.local_epoch = 1
        self.next_seq = ((seed >> 24) & 0x7FFFFFFF) + 1
        self.next_exchange_id = ((seed >> 32) & 0x7FFFFFFF) + 1

        self.is_open = False
        self.generation = (self.generation + 1) & 0xFFFFFFFF

        # Report unresolved remote outcomes for active exchanges
        cancelled_handles: set[int] = set()
        for exc in list(self.delivery.active_outgoing.values()):
            if exc.possibly_transmitted or (exc.attempts_used > 0 and any(self.active_submissions.get(h, {}).get("admitted") for h in exc.active_submission_handles)):
                out.append(ApplicationEvent(
                    kind="diagnostic",
                    service_id=exc.service_id,
                    exchange_id=exc.exchange_id,
                    status=0,
                    payload=b"unknown",
                    at_ms=self.now_ms,
                ))
            else:
                out.append(ApplicationEvent(
                    kind="protocol_rejection",
                    service_id=exc.service_id,
                    exchange_id=exc.exchange_id,
                    status=4,
                    payload=b"cancelled",
                    at_ms=self.now_ms,
                ))
            for h in exc.active_submission_handles:
                if h in self.active_submissions and self.active_submissions[h]["admitted"]:
                    out.append(Cancel(handle=h, generation=self.active_submissions[h]["generation"], at_ms=self.now_ms))
                    cancelled_handles.add(h)

        for handle, sub in self.active_submissions.items():
            if sub.get("admitted") and handle not in cancelled_handles:
                out.append(Cancel(handle=handle, generation=sub["generation"], at_ms=self.now_ms))

        # Accepted borrows settle exactly once via TxTerminal; unadmitted submissions cannot settle
        self.active_submissions = {h: sub for h, sub in self.active_submissions.items() if sub.get("admitted")}
        self.tx_queue.clear()
        self._retire_delivery_state()
        self.reassembly.active.clear()
        self.reassembly.tombstones.clear()
        self.reassembly.completed.clear()
        if self.stream_r_decoder:
            if hasattr(self.stream_r_decoder, "reset"):
                self.stream_r_decoder.reset()
            else:
                self.stream_r_decoder = None
        if self.sample_producer:
            self.sample_producer.restart()
        if self.sample_consumer:
            self.sample_consumer.start_initialization(association_id=self.generation, at_ms=self.now_ms)

    def _handle_advance(self, event: Advance, out: list[Any]) -> None:
        if not self.is_open:
            return
        for draining in list(self.draining_associations.values()):
            if draining.drain_expired(self.now_ms) or draining.is_expired(self.now_ms):
                self._expire_draining_association(draining, out)
        if (
            self.bootstrap_mgr is not None
            and self.bootstrap_mgr.current_attempt_id is not None
            and self._bootstrap_attempt_expired(self.bootstrap_mgr.current_attempt_id)
        ):
            self._abort_bootstrap_attempt(out)
        if (
            self.pending_association is None
            and self.bootstrap_mgr is not None
            and self._bootstrap_attempt_id is not None
            and self.bootstrap_mgr.current_attempt_id == self._bootstrap_attempt_id
            and self._bootstrap_flight1_wire is not None
            and self._bootstrap_next_flight_retry_ms is not None
            and self.now_ms >= self._bootstrap_next_flight_retry_ms
        ):
            cfg = self.manifest.values.get("security", {})
            if self._bootstrap_flight_attempts_used < cfg.get("flight_attempts", 1):
                if not self._enqueue_bootstrap_tx(self._bootstrap_flight1_wire, self._bootstrap_attempt_id, out):
                    self._abort_bootstrap_attempt(out)
                else:
                    self._bootstrap_flight_attempts_used += 1
                    self._bootstrap_next_flight_retry_ms = self.now_ms + cfg.get("flight_retry_ms", 1)
            else:
                self._bootstrap_next_flight_retry_ms = None
        assoc = self.association or self.pending_association
        if assoc is not None and (assoc.status == "closed" or assoc.is_expired(self.now_ms)):
            self._expire_security_context(out)
        if self.stream_r_decoder:
            stream_events = self.stream_r_decoder.advance(self.now_ms)
            for se in stream_events:
                if se.kind == "frame" and se.frame:
                    self._process_core_bytes(se.frame, out)

        # Check confirmation retry timer (§S4)
        if self.next_confirmation_retry_ms is not None and self.now_ms >= self.next_confirmation_retry_ms:
            if self.confirmation_attempts_used < self.confirmation_attempts:
                self.confirmation_attempts_used += 1
                self.next_confirmation_retry_ms = self.now_ms + self.confirmation_timeout_ms
                if self.cached_finish_wire is not None:
                    # In Mode 2, also retransmit flight 3 if retained (§S4)
                    if self.sec_mode == MODE_XX and self.bootstrap_mgr and 3 in self.bootstrap_mgr.cached_outgoing_flights:
                        f3_payload = self.bootstrap_mgr.cached_outgoing_flights[3]
                        if self.bootstrap_mgr.current_attempt_id:
                            f3_wire = self._build_bootstrap_frame(
                                flight=3, attempt_id=self.bootstrap_mgr.current_attempt_id, payload=f3_payload
                            )
                            if not self._enqueue_bootstrap_tx(f3_wire, self.bootstrap_mgr.current_attempt_id, out):
                                self._abort_bootstrap_attempt(out)
                                return
                    # Re-send FINISH with fresh PN per §S4 / §S6
                    finish_wire = self._build_protected_finish_frame()
                    attempt_id = self._bootstrap_attempt_id
                    if attempt_id is None or not self._enqueue_bootstrap_tx(finish_wire, attempt_id, out):
                        self._abort_bootstrap_attempt(out)
                        return
            else:
                # Confirmation timeout: discard candidate traffic state
                self._abort_bootstrap_attempt(out)

        # Advance reassembly; incomplete command identities consume any bound
        # freshness lease when their assembly expires.
        self._emit_due_fragment_statuses(out)
        expired_assemblies = self.reassembly.advance(self.now_ms)
        if self.association is not None and self.freshness_manager is not None:
            for message_id in expired_assemblies:
                self.freshness_manager.consume_identity(self.association.h, message_id)
        if self.sample_consumer:
            self.sample_consumer.advance(self.now_ms)

        # Advance delivery: returns due retries and expired exchanges (removed from active list)
        due_reqs, due_results, expired_excs = self.delivery.advance(self.now_ms)

        for exc in due_reqs:
            # Check deadline before retransmitting
            if exc.not_after_ms is not None and self.now_ms >= exc.not_after_ms:
                self._expire_outgoing_exchange(exc, out)
            else:
                retry_assoc = self._association_by_hash(exc.association_h)
                if retry_assoc is not None and retry_assoc.status in ("active", "draining"):
                    # Logical retry with fresh PN (§S6)!
                    with self._use_association(retry_assoc, allow_draining=retry_assoc.status == "draining"):
                        retry_frames = self._build_req_frames(
                            service_id=exc.service_id,
                            seq=exc.seq,
                            payload=exc.request_payload,
                            ack_req=exc.ack_req,
                            freshness_token=exc.freshness_token,
                        )
                    exc.frames = tuple(retry_frames)
                for f_bytes in exc.frames:
                    self._enqueue_tx(f_bytes, not_after_ms=exc.not_after_ms, service_id=exc.service_id, exchange_id=exc.exchange_id, out=out)

        # Retransmit all frames of retained results
        for res in due_results:
            self._reprotect_retained_result(res)
            for rf in res.result_frames:
                self._enqueue_tx(rf, not_after_ms=None, service_id=res.service_id, out=out)

        # Process expired exchanges exactly once (already removed from active_outgoing)
        for exc in expired_excs:
            svc_id = exc.service_id
            exc_id = exc.exchange_id
            self._retire_exchange_attempts(exc, out)
            if exc.service_id == 1 and self.sample_consumer and exc.request_payload == b"\x01":
                if self.sample_consumer.designated_request_seq == exc.seq:
                    self.sample_consumer.designated_request_seq = None
            may_have_reached_peer = (
                exc.possibly_transmitted
                or bool(exc.admitted_schedule_handles)
                or any(self.active_submissions.get(h, {}).get("admitted") for h in exc.active_submission_handles)
            )
            if may_have_reached_peer:
                out.append(ApplicationEvent(
                    kind="diagnostic",
                    service_id=svc_id,
                    exchange_id=exc_id,
                    status=0,
                    payload=b"unknown",
                    at_ms=self.now_ms,
                ))
            else:
                out.append(ApplicationEvent(
                    kind="protocol_rejection",
                    service_id=svc_id,
                    exchange_id=exc_id,
                    status=4,
                    payload=b"expired" if exc.state == "expired" else b"timeout",
                    at_ms=self.now_ms,
                ))

        # Check if queued application requests can now be admitted
        admissible = self.delivery.pop_next_admissible()
        while admissible:
            for f_bytes in admissible.frames:
                self._enqueue_tx(
                    f_bytes,
                    not_after_ms=admissible.not_after_ms,
                    service_id=admissible.service_id,
                    exchange_id=admissible.exchange_id,
                    out=out,
                )
            admissible = self.delivery.pop_next_admissible()

        self._advance_selective_transfers(out)

    def _handle_receive(self, event: Receive, out: list[Any]) -> None:
        if self.binding_kind == "stream-r":
            if not self.stream_r_decoder:
                return
            stream_events = self.stream_r_decoder.feed(event.bytes, at_ms=self.now_ms)
            for se in stream_events:
                if se.kind == "frame" and se.frame:
                    self._process_core_bytes(se.frame, out)
        else:
            if len(event.bytes) <= self.forward_mtu:
                self._process_core_bytes(event.bytes, out)

    def initiate_handshake(self, at_ms: int | None = None, attempt_id: bytes | None = None) -> tuple[Any, ...]:
        if not self.is_open:
            raise EventValidationError("Endpoint must be open before initiating handshake")
        if self.bootstrap_mgr is None:
            raise SecurityError("SEC-1 not configured in manifest")
        self._clear_completed_bootstrap()
        if self.pending_association is not None or self.bootstrap_mgr.current_attempt_id is not None:
            raise SecurityError("SEC-1 pair already has pending or active state")
        sec_cfg = self.manifest.values.get("security", {})
        if (self._active_association is not None
                and len(self.draining_associations) >= sec_cfg.get("draining_per_pair", 0)):
            raise SecurityError("SEC-1 rotation has no bounded draining capacity")
        if self.sec_mode == MODE_XX and self.peer_static_public_key is None:
            raise AuthorizationError("XX requires an already authorized peer pin")
        self._processed_flight2_payload = None
        self._processed_flight3_payload = None
        if at_ms is None:
            at_ms = self.now_ms
        if at_ms < self.now_ms:
            raise EventValidationError("Handshake time must be monotonic")
        self.now_ms = at_ms
        if attempt_id is None:
            attempt_id = self.entropy_source(16)

        if not self._begin_bootstrap_attempt(attempt_id, local_initiated=True):
            raise SecurityError("SEC-1 bootstrap episode or restart budget exhausted")

        out: list[Any] = []
        try:
            # Every association gets a distinct receive selector while old
            # keys or stale ciphertext remain retained for the drain horizon.
            self.bootstrap_mgr.local_rx_cid = 0
            rx_cid, f1_payload = self.bootstrap_mgr.build_flight_1(attempt_id, at_ms)
            f1_wire = self._build_bootstrap_frame(flight=1, attempt_id=attempt_id, payload=f1_payload)
        except Exception:
            self._abort_bootstrap_attempt(out)
            raise
        self.local_rx_cid = rx_cid

        if not self._enqueue_bootstrap_tx(f1_wire, attempt_id, out):
            self._abort_bootstrap_attempt(out)
            raise SecurityError("SEC-1 bootstrap transmission budget exhausted")
        cfg = self.manifest.values.get("security", {})
        self._bootstrap_flight1_wire = f1_wire
        self._bootstrap_flight_attempts_used = 1
        self._bootstrap_next_flight_retry_ms = self.now_ms + cfg.get("flight_retry_ms", 1)
        return tuple(out)

    def _build_bootstrap_frame(self, flight: int, attempt_id: bytes, payload: bytes) -> bytes:
        b_epoch = compute_bootstrap_epoch(attempt_id)
        ext_context = Extension(2, True, True, encode_uleb(self.namespace) + b_epoch.to_bytes(8, "little"))
        route = None
        if self.manifest.values.get("binding", {}).get("topology") in ("static-unicast", "relay-routed"):
            route = Route(
                ttl=self.manifest.values.get("binding", {}).get("ttl", 0),
                mode=1,
                source_id=self.local_node_id,
                destination_id=self.remote_node_id,
            )
            exts = (ext_context,)
        else:
            ext_origin = Extension(3, True, True, encode_uleb(self.local_node_id))
            exts = (ext_context, ext_origin)

        frame = CoreFrame(
            message_type=3,  # HELLO
            options=(1 | (4 if route else 0) | 0x80
                     | (0x10 if self.manifest.values["binding"].get("bootstrap_integrity") == "CRC32C" else 0)),
            sequence=flight,
            route=route,
            integrity=(1 if self.manifest.values["binding"].get("bootstrap_integrity") == "CRC32C"
                       else None),
            extensions=tuple(sorted(exts, key=lambda e: e.extension_id)),
            payload=payload,
        )
        return encode_frame(frame, max_frame=self.forward_mtu)

    def _build_protected_finish_frame(self) -> bytes:
        assoc = self.pending_association or self._rx_association or self._active_association
        with self._use_association(assoc):
            route, context = self._routed_fields()
            frame = CoreFrame(
                message_type=3,  # HELLO
                options=1 | (4 if route else 0) | (0x80 if context else 0),  # SEQ / ROUTE / EXT
                sequence=0,
                route=route,
                extensions=(context,) if context else (),
                payload=b"",
            )
            return self._encrypt_and_encode(frame, plaintext=PAYLOAD_FINISH)

    def _build_protected_ready_frame(self) -> bytes:
        assoc = self._rx_association or self.pending_association or self._active_association
        with self._use_association(assoc):
            route, context = self._routed_fields()
            frame = CoreFrame(
                message_type=3,  # HELLO
                options=1 | (4 if route else 0) | (0x80 if context else 0),  # SEQ / ROUTE / EXT
                sequence=0,
                route=route,
                extensions=(context,) if context else (),
                payload=b"",
            )
            return self._encrypt_and_encode(frame, plaintext=PAYLOAD_READY)

    def _encrypt_and_encode(
        self,
        frame: CoreFrame,
        plaintext: bytes,
        pn: int | None = None,
    ) -> bytes:
        assoc = self.association or self.pending_association
        if assoc is None:
            raise SecurityError("No active association for encryption")
        allow_draining = self._allow_draining_tx and assoc.status == "draining"
        if (assoc.status == "closed" or assoc.is_expired(self.now_ms)
                or (assoc.drain_expired(self.now_ms) and assoc.status == "draining")):
            assoc.status = "closed"
            raise SecurityError("SEC-1 association is closed or expired")
        if assoc.status != "active" and not allow_draining and not (
            assoc.status == "candidate"
            and frame.message_type == 3
            and plaintext in (PAYLOAD_FINISH, PAYLOAD_READY)
        ):
            raise SecurityError("Application traffic is forbidden before SEC-1 activation")

        if pn is None:
            pn = assoc.alloc_send_pn(allow_draining=allow_draining)

        sec_desc = Security(
            cipher=self.sec_cipher,
            receive_cid=assoc.peer_rx_cid,
            packet_number=pn,
        )
        dummy_frame = CoreFrame(
            message_type=frame.message_type,
            options=frame.options | 0x40,  # SECURITY
            sequence=frame.sequence,
            route=frame.route,
            fragment=frame.fragment,
            payload_descriptor=frame.payload_descriptor,
            integrity=None,
            security=sec_desc,
            extensions=frame.extensions,
            payload=b"\x00" * len(plaintext),
            trailer=b"\x00" * 16,
        )
        encoded_dummy = encode_frame(dummy_frame, max_frame=self.forward_mtu)
        hdr_len = encoded_dummy[1]
        core_header = encoded_dummy[:hdr_len]

        _, ct_and_tag = assoc.encrypt_frame(
            core_header, plaintext, pn=pn, allow_draining=allow_draining
        )
        return core_header + ct_and_tag

    def _handle_bootstrap_hello(self, frame: CoreFrame, out: list[Any]) -> None:
        if self.bootstrap_mgr is None:
            return
        self._clear_completed_bootstrap()
        if not self._admit_bootstrap_ingress():
            return
        # An admitted association is never evicted by unauthenticated bootstrap.
        # Rotation is admitted only when the manifest reserves a draining slot.
        sec_cfg = self.manifest.values.get("security", {})
        if len(self.draining_associations) >= sec_cfg.get("draining_per_pair", 0):
            return
        if self.sec_mode == MODE_XX and self.peer_static_public_key is None:
            return
        if frame.sequence not in (1, 2, 3) or (frame.options & 2) or frame.security is not None or frame.fragment is not None:
            return
        if (self.manifest.values.get("binding", {}).get("bootstrap_integrity") == "CRC32C"
                and frame.integrity != 1):
            return
        if any(ext.extension_id not in (2, 3) for ext in frame.extensions):
            return
        topology = self.manifest.values.get("binding", {}).get("topology")
        if topology in ("static-unicast", "relay-routed"):
            if frame.route is None or frame.route.mode != 1:
                return
        elif frame.route is not None:
            return

        ext_context = next((e for e in frame.extensions if e.extension_id == 2), None)
        if not ext_context or len(ext_context.value) < 9:
            return
        ns, at = decode_uleb(ext_context.value, 0)
        if ns != self.namespace or len(ext_context.value) - at != 8:
            return
        prov_epoch = int.from_bytes(ext_context.value[at : at + 8], "little")

        origin = None
        if frame.route:
            if frame.route.destination_id != self.local_node_id:
                return
            origin = frame.route.source_id
        else:
            ext_origin = next((e for e in frame.extensions if e.extension_id == 3), None)
            if ext_origin:
                origin, origin_end = decode_uleb(ext_origin.value, 0)
                if origin_end != len(ext_origin.value):
                    return
        if origin != self.remote_node_id:
            return

        flight = frame.sequence
        expected_payload_lengths = (
            {1: 120, 2: 70}
            if self.sec_mode == MODE_NNPSK0
            else {1: 104, 2: 118, 3: 82}
        )
        if len(frame.payload) != expected_payload_lengths.get(flight):
            return
        if flight == 1:
            if len(frame.payload) < 72:
                return
            attempt_id = frame.payload[4:20]
            if prov_epoch != compute_bootstrap_epoch(attempt_id):
                return
            prefix = frame.payload[:72]
            if (
                prefix[0] != BOOT_VERSION
                or prefix[1] != self.sec_mode
                or prefix[2] != self.sec_cipher
                or prefix[3] != 1
                or int.from_bytes(prefix[20:24], "little") != self.namespace
                or int.from_bytes(prefix[24:28], "little") != self.remote_node_id
                or int.from_bytes(prefix[28:32], "little") != self.local_node_id
                or prefix[32:64] != self.bootstrap_mgr.manifest_digest
                or int.from_bytes(prefix[64:68], "little") != self.bootstrap_mgr.key_hint
                or int.from_bytes(prefix[68:72], "little") == 0
            ):
                return
            current_attempt_id = self.bootstrap_mgr.current_attempt_id
            if current_attempt_id is not None and current_attempt_id != attempt_id:
                return
            if current_attempt_id == attempt_id and self._bootstrap_attempt_local_initiated:
                return
            if current_attempt_id is None and self._bootstrap_attempt_id is not None:
                self._end_bootstrap_attempt()
            if self._bootstrap_attempt_expired(attempt_id):
                self._abort_bootstrap_attempt(out)
                return
            # A same-attempt Flight 1 whose Noise payload differs from the
            # admitted bytes is a cheap conflicting duplicate. Do not clear
            # processed-flight state or charge crypto budget before dropping it.
            if (
                current_attempt_id == attempt_id
                and not self._bootstrap_attempt_local_initiated
                and self.bootstrap_mgr.flight1_cache is not None
                and self.bootstrap_mgr.flight1_cache != frame.payload
            ):
                return
            if current_attempt_id is None and not self._begin_bootstrap_attempt(attempt_id, local_initiated=False):
                return
            duplicate_flight1 = (
                self.bootstrap_mgr.current_attempt_id == attempt_id
                and self.bootstrap_mgr.flight1_cache == frame.payload
                and self.bootstrap_mgr.flight2_cache is not None
            )
            if duplicate_flight1 and not self._admit_bootstrap_duplicate_response():
                return
            if not duplicate_flight1:
                self._processed_flight2_payload = None
                self._processed_flight3_payload = None
            if duplicate_flight1:
                r_cid = self.bootstrap_mgr.local_rx_cid
                f2_payload = self.bootstrap_mgr.flight2_cache
            else:
                crypto_start_ns = self._start_bootstrap_crypto()
                if crypto_start_ns is None:
                    # No-work admission does not invalidate an admitted attempt.
                    if self.bootstrap_mgr.current_attempt_id != attempt_id:
                        self._end_bootstrap_attempt()
                    return
                try:
                    # A new Noise attempt needs a fresh local receive selector;
                    # the prior CID may still identify a bounded draining SA.
                    self.bootstrap_mgr.local_rx_cid = 0
                    r_cid, f2_payload = self.bootstrap_mgr.process_flight_1(frame.payload, self.now_ms)
                except (SecurityError, HandshakeError, AuthorizationError):
                    budget_ok = self._finish_bootstrap_crypto(crypto_start_ns)
                    if self.bootstrap_mgr.attempt_aborted or not budget_ok:
                        self._abort_bootstrap_attempt(out)
                    return
                if not self._finish_bootstrap_crypto(crypto_start_ns):
                    self._abort_bootstrap_attempt(out)
                    return
            self.local_rx_cid = r_cid
            if self.sec_mode == MODE_NNPSK0 and not duplicate_flight1:
                self._register_pending_association(
                    self.bootstrap_mgr.create_association(is_initiator=False, at_ms=self.now_ms)
                )

            f2_wire = self._build_bootstrap_frame(flight=2, attempt_id=attempt_id, payload=f2_payload)
            if not self._enqueue_bootstrap_tx(f2_wire, attempt_id, out):
                self._abort_bootstrap_attempt(out)

        elif flight == 2:
            if len(frame.payload) < 18:
                return
            attempt_id = frame.payload[2:18]
            if prov_epoch != compute_bootstrap_epoch(attempt_id):
                return
            if self._bootstrap_attempt_expired(attempt_id):
                self._abort_bootstrap_attempt(out)
                return
            if (
                self.bootstrap_mgr.current_attempt_id == attempt_id
                and self._processed_flight2_payload is not None
            ):
                if frame.payload != self._processed_flight2_payload:
                    return
                if not self._admit_bootstrap_duplicate_response():
                    return
                # Identical processed continuation: resend cached next flight and
                # use a fresh PN for the logical FINISH, without re-entering Noise.
                if self.sec_mode == MODE_XX and 3 in self.bootstrap_mgr.cached_outgoing_flights:
                    f3_wire = self._build_bootstrap_frame(
                        flight=3,
                        attempt_id=attempt_id,
                        payload=self.bootstrap_mgr.cached_outgoing_flights[3],
                    )
                    if not self._enqueue_bootstrap_tx(f3_wire, attempt_id, out):
                        return
                if self.pending_association is not None and self.cached_finish_wire is not None:
                    finish_wire = self._build_protected_finish_frame()
                    if not self._enqueue_bootstrap_tx(finish_wire, attempt_id, out):
                        return
                return
            if self.bootstrap_mgr.current_attempt_id != attempt_id:
                return
            if not self._bootstrap_attempt_local_initiated:
                return
            crypto_start_ns = self._start_bootstrap_crypto()
            if crypto_start_ns is None:
                return
            try:
                f3_res = self.bootstrap_mgr.process_flight_2(frame.payload, self.now_ms)
            except (SecurityError, HandshakeError, AuthorizationError):
                budget_ok = self._finish_bootstrap_crypto(crypto_start_ns)
                if self.bootstrap_mgr.attempt_aborted or not budget_ok:
                    self._abort_bootstrap_attempt(out)
                return
            if not self._finish_bootstrap_crypto(crypto_start_ns):
                self._abort_bootstrap_attempt(out)
                return
            self._processed_flight2_payload = frame.payload
            self._bootstrap_flight1_wire = None
            self._bootstrap_flight_attempts_used = 0
            self._bootstrap_next_flight_retry_ms = None

            if self.sec_mode == MODE_XX:
                _, f3_payload = f3_res
                if f3_payload is not None:
                    f3_wire = self._build_bootstrap_frame(flight=3, attempt_id=attempt_id, payload=f3_payload)
                    if not self._enqueue_bootstrap_tx(f3_wire, attempt_id, out):
                        self._abort_bootstrap_attempt(out)
                        return

            # Initiator handshake complete!
            self._register_pending_association(
                self.bootstrap_mgr.create_association(is_initiator=True, at_ms=self.now_ms)
            )
            finish_wire = self._build_protected_finish_frame()
            self.cached_finish_wire = finish_wire
            self.confirmation_attempts_used = 1
            self.next_confirmation_retry_ms = self.now_ms + self.confirmation_timeout_ms
            if not self._enqueue_bootstrap_tx(finish_wire, attempt_id, out):
                self._abort_bootstrap_attempt(out)

        elif flight == 3:
            if self.sec_mode != MODE_XX or len(frame.payload) < 18:
                return
            attempt_id = frame.payload[2:18]
            if prov_epoch != compute_bootstrap_epoch(attempt_id):
                return
            if self._bootstrap_attempt_expired(attempt_id):
                self._abort_bootstrap_attempt(out)
                return
            if (
                self.bootstrap_mgr.current_attempt_id == attempt_id
                and self._processed_flight3_payload is not None
            ):
                # Identical processed continuation is a cheap no-op; a conflicting
                # duplicate cannot enter or abort the already advanced Noise state.
                return
            if self.bootstrap_mgr.current_attempt_id != attempt_id:
                return
            if self._bootstrap_attempt_local_initiated:
                return
            crypto_start_ns = self._start_bootstrap_crypto()
            if crypto_start_ns is None:
                return
            try:
                self.bootstrap_mgr.process_flight_3(frame.payload, self.now_ms)
            except (SecurityError, HandshakeError, AuthorizationError):
                budget_ok = self._finish_bootstrap_crypto(crypto_start_ns)
                if self.bootstrap_mgr.attempt_aborted or not budget_ok:
                    self._abort_bootstrap_attempt(out)
                return
            if not self._finish_bootstrap_crypto(crypto_start_ns):
                self._abort_bootstrap_attempt(out)
                return
            self._processed_flight3_payload = frame.payload
            self._register_pending_association(
                self.bootstrap_mgr.create_association(is_initiator=False, at_ms=self.now_ms)
            )

    def _handle_protected_frame(self, raw_frame: bytes, frame: CoreFrame, out: list[Any]) -> None:
        assoc = self._association_by_cid(frame.security.receive_cid)
        if assoc is None or assoc.status == "closed":
            return
        previous = self._rx_association
        previous_allow = self._allow_draining_tx
        self._rx_association = assoc
        self._allow_draining_tx = assoc.status == "draining"
        try:
            self._handle_selected_protected_frame(raw_frame, frame, out, assoc)
        finally:
            self._rx_association = previous
            self._allow_draining_tx = previous_allow

    def _handle_selected_protected_frame(
        self, raw_frame: bytes, frame: CoreFrame, out: list[Any], assoc: SecurityAssociation
    ) -> None:
        if (assoc.status != "active"
                and self._bootstrap_attempt_id is not None
                and self._bootstrap_attempt_expired(self._bootstrap_attempt_id)):
            # Attempt deadlines are absolute, so a late but otherwise valid
            # FINISH/READY cannot activate a candidate after its deadline.
            self._abort_bootstrap_attempt(out)
            return
        if assoc.status == "closed" or assoc.is_expired(self.now_ms) or assoc.drain_expired(self.now_ms):
            if assoc.status == "draining":
                self._expire_draining_association(assoc, out)
            elif assoc is self.pending_association:
                # Candidate lifetime and failed-AEAD budgets belong to the
                # in-progress handshake, not to the unrelated active SA.
                self._abort_bootstrap_attempt(out)
            else:
                self._expire_security_context(out)
            return
        if frame.security.cipher != self.sec_cipher:
            return
        if frame.security.receive_cid != assoc.local_rx_cid:
            return

        core_header = raw_frame[:raw_frame[1]]
        try:
            plaintext = assoc.decrypt_frame(
                core_header=core_header,
                ciphertext=frame.payload,
                tag=frame.trailer,
                pn=frame.security.packet_number,
                rx_cid=frame.security.receive_cid,
            )
        except SecurityError:
            if assoc.status == "closed":
                if assoc.local_rx_cid in self.draining_associations:
                    self._expire_draining_association(assoc, out)
                elif assoc is self.pending_association:
                    self._abort_bootstrap_attempt(out)
                else:
                    self._expire_security_context(out)
            return

        # Count only newly authenticated plaintext, including handshake controls.
        received_total = getattr(assoc, "total_plaintext_bytes_received", 0) + len(plaintext)
        if received_total > MAX_PLAINTEXT_BYTES:
            assoc.status = "closed"
            if assoc is self._active_association:
                self._expire_security_context(out)
            else:
                self._expire_draining_association(assoc, out)
            return
        assoc.total_plaintext_bytes_received = received_total

        if not self._protected_identity_matches(frame, assoc):
            return

        # Unknown critical extensions reject endpoint-local delivery after
        # authentication and identity binding, before candidate activation,
        # reassembly, retained-state admission, or application dispatch.
        if self._has_unknown_critical_extension(frame):
            return

        decrypted_frame = CoreFrame(
            message_type=frame.message_type,
            options=frame.options,
            sequence=frame.sequence,
            route=frame.route,
            fragment=frame.fragment,
            payload_descriptor=frame.payload_descriptor,
            integrity=frame.integrity,
            security=frame.security,
            extensions=frame.extensions,
            payload=plaintext,
            trailer=b"",
        )

        # Check for protected HELLO (FINISH / READY)
        if frame.message_type == 3:
            if plaintext == PAYLOAD_FINISH and self._valid_confirmation_frame(frame):  # b"\x04"
                if (
                    assoc is self.pending_association
                    and self.bootstrap_mgr is not None
                    and self.bootstrap_mgr.enrollment_committed
                    and self.pending_association is not None
                    and not self.pending_association.is_initiator
                ):
                    # Responder activates association!
                    self._activate_pending_association(self.pending_association)
                if self.association is not None:
                    # Send protected READY
                    ready_wire = self._build_protected_ready_frame()
                    self.cached_ready_wire = ready_wire
                    attempt_id = self._bootstrap_attempt_id
                    if attempt_id is not None:
                        if not self._enqueue_bootstrap_tx(ready_wire, attempt_id, out):
                            self.association.status = "closed"
                            self._expire_security_context(out)
                    else:
                        self._enqueue_tx(ready_wire, not_after_ms=None, service_id=0, out=out)
                return
            elif plaintext == PAYLOAD_READY and self._valid_confirmation_frame(frame):  # b"\x05"
                if (
                    assoc is self.pending_association
                    and self.bootstrap_mgr is not None
                    and self.bootstrap_mgr.enrollment_committed
                    and self.pending_association is not None
                    and self.pending_association.is_initiator
                ):
                    # Initiator activates association!
                    self._activate_pending_association(self.pending_association)
                    self.next_confirmation_retry_ms = None
                    self.cached_finish_wire = None
                    self._promote_waiting_requests(out)
                return
            return

        # Only an authorized application packet can prove readiness if READY
        # was lost. Reject unrecognized or unauthorized records while the
        # initiator association is still a candidate.
        if (
            assoc is self.pending_association
            and self.bootstrap_mgr is not None
            and self.bootstrap_mgr.enrollment_committed
            and self.pending_association is not None
            and self.pending_association.is_initiator
        ):
            if not self._candidate_application_is_authorized(decrypted_frame, self.pending_association):
                return
            self._activate_pending_association(self.pending_association)
            self.next_confirmation_retry_ms = None
            self.cached_finish_wire = None
            self._promote_waiting_requests(out)

        if self.association is None or self.association.status not in ("active", "draining"):
            return

        self._dispatch_core_frame(decrypted_frame, out)

    @staticmethod
    def _valid_confirmation_frame(frame: CoreFrame) -> bool:
        """Apply the exact SEC-1 S4 control-frame shape to FINISH and READY."""
        allowed_options = 0x01 | 0x04 | 0x40 | 0x80  # SEQ, ROUTE, SECURITY, EXT
        if (
            frame.sequence != 0
            or not (frame.options & 0x01)
            or not (frame.options & 0x40)
            or frame.options & ~allowed_options
            or frame.fragment is not None
            or frame.payload_descriptor is not None
        ):
            return False
        return all(ext.extension_id in (2, 3) for ext in frame.extensions)

    def _candidate_application_is_authorized(
        self, frame: CoreFrame, association: SecurityAssociation
    ) -> bool:
        """Check candidate traffic before it can activate an initiator (§S4)."""
        if frame.message_type not in (0, 5, 7) or frame.fragment is not None or frame.sequence is None:
            return False

        service_id = self.default_service
        explicit_service = False
        for ext in frame.extensions:
            if ext.extension_id == 4:
                service_id = decode_uleb(ext.value)[0]
                explicit_service = True
                break
        if service_id == 0 or (service_id == self.default_service and explicit_service):
            return False

        origin = frame.route.source_id if frame.route is not None else self.remote_node_id
        if frame.route is None:
            origin_ext = next((e for e in frame.extensions if e.extension_id == 3), None)
            if origin_ext is not None:
                origin, end = decode_uleb(origin_ext.value, 0)
                if end != len(origin_ext.value):
                    return False
        if origin != self.remote_node_id:
            return False

        service = next((s for s in self.manifest.values.get("services", []) if s.get("id") == service_id), None)
        if service is None:
            return False
        # SAMPLE-1 is a fixed profile encoding. A descriptor must not relabel
        # its request or telemetry payload before candidate readiness.
        if service_id in (1, 2) and frame.payload_descriptor is not None:
            return False
        acl = next((a for a in service.get("acl", []) if a.get("node") == origin), None)
        required_action = self._required_acl_action(frame, service_id)
        if acl is None or required_action is None or required_action not in acl.get("actions", []):
            return False

        # Candidate readiness is established only by an application operation
        # this endpoint can actually accept. SAMPLE-1 has a closed opcode set.
        if frame.message_type == 0:
            if not (frame.options & 2):
                return False
            request_limit = service.get("request_bytes", self.manifest.values["limits"]["message_bytes"])
            if len(frame.payload) > request_limit:
                return False
            if service_id == 1 and frame.payload not in (b"\x01", b"\x02"):
                return False
        elif frame.message_type == 5:
            if (service_id != 1 or self.sample_consumer is None or frame.options & 2
                    or len(frame.payload) != 16):
                return False
            try:
                Sample.decode_telemetry(frame.payload)
            except ValueError:
                return False
        elif len(frame.payload) > self.manifest.values["limits"]["message_bytes"]:
            return False

        if service.get("freshness") and frame.message_type in (0, 7):
            ext_fresh = next((e for e in frame.extensions if e.extension_id == 6), None)
            if ext_fresh is None or len(ext_fresh.value) != 16 or self.freshness_manager is None:
                return False
            sender_key = (self.namespace, origin, association.peer_epoch, frame.sequence)
            if sender_key not in self.delivery.accepted_messages and sender_key not in self.delivery.retained_results:
                immutable_binding = self._immutable_message_metadata(frame)
                binding_digest = hashlib.sha256(
                    repr((immutable_binding, hashlib.sha256(frame.payload).digest())).encode("utf-8")
                ).digest()
                if not self.freshness_manager.validate_command_token(
                    ext_fresh.value,
                    association.h,
                    origin,
                    sender_key,
                    self.now_ms,
                    service_id=service_id,
                    message_digest=binding_digest,
                ):
                    return False
        return True

    def _protected_identity_matches(self, frame: CoreFrame, assoc: SecurityAssociation) -> bool:
        """Bind authenticated visible identity and destination to this association."""
        expected_context = encode_uleb(self.namespace) + assoc.peer_epoch.to_bytes(8, "little")
        context = next((e for e in frame.extensions if e.extension_id == 2), None)
        origin_ext = next((e for e in frame.extensions if e.extension_id == 3), None)
        topology = self.manifest.values.get("binding", {}).get("topology")

        if frame.route is not None:
            if topology not in ("static-unicast", "relay-routed"):
                return False
            if (
                frame.route.mode != 1
                or frame.route.source_id != self.remote_node_id
                or frame.route.destination_id != self.local_node_id
                or context is None
                or context.value != expected_context
            ):
                return False
        else:
            if topology in ("static-unicast", "relay-routed"):
                return False
            if context is not None and context.value != expected_context:
                return False

        if origin_ext is not None:
            try:
                origin, end = decode_uleb(origin_ext.value, 0)
            except Exception:
                return False
            if end != len(origin_ext.value) or origin != self.remote_node_id:
                return False
        return True

    def _expire_security_context(self, out: list[Any], *, cancel_unadmitted: bool = False) -> None:
        """Stop protected work and retire all state tied to a lost/expired association."""
        for exc in list(self.delivery.active_outgoing.values()):
            may_have_reached_peer = (
                exc.possibly_transmitted
                or bool(exc.admitted_schedule_handles)
                or any(self.active_submissions.get(h, {}).get("admitted") for h in exc.active_submission_handles)
            )
            out.append(ApplicationEvent(
                kind="diagnostic" if may_have_reached_peer else "protocol_rejection",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=0 if may_have_reached_peer else 4,
                payload=b"unknown" if may_have_reached_peer else b"security_closed",
                at_ms=self.now_ms,
            ))
            self._retire_exchange_attempts(exc, out, cancel_unadmitted=cancel_unadmitted)
        for exc in self.delivery.queue:
            out.append(ApplicationEvent(
                kind="protocol_rejection",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=4,
                payload=b"security_closed",
                at_ms=self.now_ms,
            ))
        for handle, sub in self.active_submissions.items():
            if ((sub.get("admitted") or cancel_unadmitted)
                    and not sub.get("cancel_emitted")):
                sub["cancel_requested"] = True
                out.append(Cancel(handle=handle, generation=sub["generation"], at_ms=self.now_ms))
                sub["cancel_emitted"] = True
        self.active_submissions = {
            h: sub for h, sub in self.active_submissions.items()
            if sub.get("admitted") or (cancel_unadmitted and sub.get("cancel_requested"))
        }
        self.tx_queue.clear()
        self._retire_security_context()
        self._retire_delivery_state()
        self.reassembly.retire()

    def _process_core_bytes(self, raw_frame: bytes, out: list[Any]) -> None:
        try:
            frame = parse_frame(raw_frame, max_frame=self.forward_mtu)
        except Exception:
            return  # FrameError: reject frame

        # Dispatch protected frames (SECURITY=1)
        if frame.security is not None:
            self._handle_protected_frame(raw_frame, frame, out)
            return

        # Unknown critical extensions must not reach any endpoint-local path,
        # including test-only plaintext admission, bootstrap, or reassembly.
        if self._has_unknown_critical_extension(frame):
            return

        # Dispatch bootstrap HELLO (unprotected TYPE=3)
        if frame.message_type == 3:
            self._handle_bootstrap_hello(frame, out)
            return

        # Unprotected frame received while SEC-1 association is active:
        # Strictly reject plaintext downgrade (§S1, S10.03)!
        if self.sec_mode is not None and not self.test_only_disable_sec1:
            return

        self._dispatch_core_frame(frame, out)

    @staticmethod
    def _has_unknown_critical_extension(frame: CoreFrame) -> bool:
        known_extension_ids = {1, 2, 3, 4, 5, 6}
        return any(
            ext.critical and ext.extension_id not in known_extension_ids
            for ext in frame.extensions
        )

    def _dispatch_core_frame(self, frame: CoreFrame, out: list[Any]) -> None:
        # Resolve service ID
        service_id = self.default_service
        explicit_service = False
        for ext in frame.extensions:
            if ext.extension_id == 4:
                service_id = decode_uleb(ext.value)[0]
                explicit_service = True
                break

        # Check default-service canonical omission rule (§6.1)
        if service_id == self.default_service and explicit_service:
            # Explicit default-service ID is noncanonical: reject local delivery!
            return

        # Resolve sender full identity
        origin = self.remote_node_id
        if frame.route:
            origin = frame.route.source_id
        else:
            for ext in frame.extensions:
                if ext.extension_id == 3:
                    origin = decode_uleb(ext.value)[0]
                    break

        if self.association is not None and frame.security is not None:
            namespace = self.namespace
            epoch = self.association.peer_epoch
        else:
            namespace = self.namespace
            epoch = self.remote_epoch
            for ext in frame.extensions:
                if ext.extension_id == 2:
                    ns, at = decode_uleb(ext.value)
                    namespace = ns
                    epoch = int.from_bytes(ext.value[at : at + 8], "little")
                    break

        seq = frame.sequence if frame.sequence is not None else 0
        sender_key = (namespace, origin, epoch, seq)

        # Retained security-layer rejections own their identity before any
        # subsequently supplied opcode or FRESHNESS field can be reconsidered.
        if frame.message_type == 0 and self._replay_retained_rejection(
            sender_key, frame, service_id, out,
            geometry=(frame.fragment.chunk_size, frame.fragment.total_length)
            if frame.fragment is not None else None,
        ):
            return

        # Check ACL if SEC-1 association is active (§S2, S10.03)
        if self.association is not None and frame.security is not None:
            if service_id == 0:
                if any(e.extension_id == 6 for e in frame.extensions):
                    # Freshness control messages MUST NOT carry FRESHNESS themselves (§S7.1)
                    if frame.message_type == 0:
                        self._reject_sec1_request(sender_key, frame, 0, 7, out)
                    return
                if frame.message_type not in (0, 1, 2, 6):
                    return
            else:
                svc_cfg = next((s for s in self.manifest.values.get("services", []) if s.get("id") == service_id), None)
                if svc_cfg is None:
                    if frame.message_type == 0:
                        self._reject_sec1_request(sender_key, frame, service_id, 2, out)
                    return
                acl_entries = svc_cfg.get("acl", [])
                node_acl = next((a for a in acl_entries if a.get("node") == origin), None)
                if node_acl is None:
                    if frame.message_type == 0:
                        self._reject_sec1_request(sender_key, frame, service_id, 6, out)
                    return
                allowed_actions = node_acl.get("actions", [])
                required_action = self._required_acl_action(frame, service_id)
                if frame.message_type not in (6, 8) and (
                    required_action is None or required_action not in allowed_actions
                ):
                    # A malformed SAMPLE-1 REQ has no resolved opcode action.
                    # Defer only that case for an ACL principal allowed to make
                    # at least one SAMPLE-1 request; its size and payload checks
                    # below then select STATUS=3 or STATUS=7. Candidate
                    # authorization remains stricter and is checked separately.
                    malformed_sample1_req = (
                        frame.message_type == 0
                        and service_id == 1
                        and required_action is None
                        and bool({"read", "status"}.intersection(allowed_actions))
                    )
                    if not malformed_sample1_req:
                        if frame.message_type == 0:
                            self._reject_sec1_request(sender_key, frame, service_id, 6, out)
                        return

                # This profile fixes SAMPLE-1's representation in its service
                # contract and omits PAYLOAD_DESC. Do not guess a codec or
                # schema, and retain STATUS=2 for reliable requests.
                if service_id in (1, 2) and frame.payload_descriptor is not None:
                    if frame.message_type == 0:
                        self._reject_sec1_request(sender_key, frame, service_id, 2, out)
                    return

                if service_id == 1 and frame.message_type == 0:
                    sample1_actions = {"read", "status"}.intersection(allowed_actions)
                    opcode_action = {
                        1: "read",
                        2: "status",
                    }.get(frame.payload[0]) if frame.payload else None
                    if opcode_action is not None:
                        if opcode_action not in allowed_actions:
                            self._reject_sec1_request(sender_key, frame, service_id, 6, out)
                            return
                    elif not sample1_actions:
                        self._reject_sec1_request(sender_key, frame, service_id, 6, out)
                        return

                    request_length = (
                        frame.fragment.total_length if frame.fragment is not None else len(frame.payload)
                    )
                    request_limit = svc_cfg.get(
                        "request_bytes", self.manifest.values["limits"]["message_bytes"]
                    )
                    if request_length > request_limit:
                        self._reject_sec1_request(sender_key, frame, service_id, 3, out)
                        return
                    if (
                        not (frame.options & 2)
                        or request_length != 1
                        or len(frame.payload) != 1
                        or frame.payload[0] not in (1, 2)
                    ):
                        self._reject_sec1_request(sender_key, frame, service_id, 7, out)
                        return

                # Check Freshness token requirement (§S7)
                is_duplicate = (
                    sender_key in self.delivery.accepted_messages
                    or sender_key in self.delivery.retained_results
                )
                if svc_cfg.get("freshness") and frame.message_type in (0, 7) and not is_duplicate:
                    ext_fresh = next((e for e in frame.extensions if e.extension_id == 6), None)
                    if (not ext_fresh or len(ext_fresh.value) != 16
                            or self.freshness_manager is None):
                        self._reject_sec1_request(sender_key, frame, service_id, 7, out)
                        return
                    fragment_geometry = (
                        (frame.fragment.chunk_size, frame.fragment.total_length)
                        if frame.fragment is not None else None
                    )
                    immutable_binding = self._immutable_message_metadata(frame, fragment_geometry)
                    payload_digest = None if frame.fragment is not None else hashlib.sha256(frame.payload).digest()
                    binding_digest = hashlib.sha256(repr((immutable_binding, payload_digest)).encode("utf-8")).digest()
                    if not self.freshness_manager.validate_command_token(
                        ext_fresh.value,
                        self.association.h,
                        origin,
                        sender_key,
                        self.now_ms,
                        service_id=service_id,
                        message_digest=binding_digest,
                    ):
                        self._reject_sec1_request(sender_key, frame, service_id, 7, out)
                        return

        # Check fragmentation
        frag_geom = None
        if frame.fragment:
            frag_geom = (frame.fragment.chunk_size, frame.fragment.total_length)
            if sender_key in self.delivery.accepted_messages:
                rec = self.delivery.accepted_messages[sender_key]
                rec_is_frag = rec.immutable_metadata[0] if rec.immutable_metadata else False
                rec_geom = rec.immutable_metadata[1] if rec.immutable_metadata else None
                if not rec_is_frag or rec_geom != frag_geom:
                    return
            elif sender_key in self.delivery.rejections:
                rej = self.delivery.rejections[sender_key]
                rej_is_frag = rej.immutable_metadata[0] if rej.immutable_metadata else False
                rej_geom = rej.immutable_metadata[1] if rej.immutable_metadata else None
                if not rej_is_frag or rej_geom != frag_geom:
                    return

            try:
                res = self.reassembly.process_fragment(
                    namespace=namespace,
                    origin=origin,
                    epoch=epoch,
                    seq=seq,
                    fragment_index=frame.fragment.index,
                    chunk_size=frame.fragment.chunk_size,
                    total_length=frame.fragment.total_length,
                    message_type=frame.message_type,
                    ack_req=bool(frame.options & 2),
                    service_id=service_id,
                    slice_payload=frame.payload,
                    at_ms=self.now_ms,
                    immutable_metadata=(
                        (frame.route.mode, frame.route.source_id, frame.route.destination_id)
                        if frame.route else None,
                        frame.payload_descriptor,
                        frame.integrity,
                        tuple((e.extension_id, e.critical, e.unsafe, e.value) for e in frame.extensions),
                    ),
                )
            except (ReassemblyError, ConflictError, QuotaError):
                if self.association is not None and frame.security is not None and self.freshness_manager is not None:
                    self.freshness_manager.consume_identity(self.association.h, sender_key)
                return

            if getattr(res, "already_completed", False):
                # Trigger cached receipt/result behavior without reopening or re-executing
                if frame.message_type == 0:  # REQ
                    if sender_key in self.delivery.retained_results:
                        res_obj = self.delivery.retained_results[sender_key]
                        if res_obj.selective_state is not None:
                            # R4.5: a duplicate REQ repeats its receipt only; the
                            # existing selective result transfer owns its schedule.
                            rec = self.delivery.accepted_messages.get(sender_key)
                            if (rec is not None and rec.ack_frame_bytes
                                    and self.delivery.admit_receipt_replay(rec)):
                                ack = self._build_ack_frame(sender_key, service_id, own_seq=rec.ack_seq)
                                self._enqueue_tx(ack, not_after_ms=None, service_id=service_id, out=out)
                        elif self.delivery.admit_result_replay(res_obj, self.now_ms):
                            self._reprotect_retained_result(res_obj)
                            for rf in res_obj.result_frames:
                                self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
                    elif sender_key in self.delivery.accepted_messages:
                        rec = self.delivery.accepted_messages[sender_key]
                        if rec.ack_frame_bytes and self.delivery.admit_receipt_replay(rec):
                            ack = (
                                self._build_ack_frame(sender_key, service_id, own_seq=rec.ack_seq)
                                if self.association is not None
                                else rec.ack_frame_bytes
                            )
                            self._enqueue_tx(ack, not_after_ms=None, service_id=service_id, out=out)
                    elif sender_key in self.delivery.rejections:
                        rej = self.delivery.rejections[sender_key]
                        if rej.service_id != service_id:
                            return
                        offset = frame.fragment.index * frame.fragment.chunk_size
                        expected_len = min(frame.fragment.chunk_size, frame.fragment.total_length - offset)
                        if rej.payload and rej.payload[offset : offset + expected_len] != frame.payload:
                            return
                        if self.delivery.admit_rejection_replay(rej):
                            err = (
                                self._build_err_frame(
                                    sender_key, service_id, status=rej.status, own_seq=rej.err_seq
                                )
                                if self.association is not None
                                else rej.err_frame_bytes
                            )
                            self._enqueue_tx(err, not_after_ms=None, service_id=service_id, out=out)
                elif frame.message_type == 7:  # DATA
                    if sender_key in self.delivery.accepted_messages:
                        rec = self.delivery.accepted_messages[sender_key]
                        if rec.ack_frame_bytes and self.delivery.admit_receipt_replay(rec):
                            ack = (
                                self._build_ack_frame(sender_key, service_id, own_seq=rec.ack_seq)
                                if self.association is not None
                                else rec.ack_frame_bytes
                            )
                            self._enqueue_tx(ack, not_after_ms=None, service_id=service_id, out=out)
                elif frame.message_type in (1, 2) and frame.options & 2:
                    completed = self.reassembly.completed.get(sender_key)
                    if (not completed or not getattr(completed, "endpoint_accepted", False)
                            or completed.result_ack_replays >= self.delivery.max_bursts - 1):
                        return
                    completed.result_ack_replays += 1
                    result_ack = self._build_stable_result_ack_frame(
                        sender_key,
                        service_id,
                        request_key=self._extract_reply_to(frame),
                        completed=completed,
                    )
                    self._enqueue_tx(
                        result_ack,
                        not_after_ms=None,
                        service_id=service_id,
                        out=out,
                    )
                return

            complete, full_payload = res[0], res[1]
            if not complete or full_payload is None:
                if self._selective_frame_eligible(frame, service_id):
                    session = self.reassembly.active.get(sender_key)
                    timing = self.manifest.values["timing"]
                    if (session is not None
                            and session.selective_feedback_due_ms is not None
                            and self.now_ms > session.selective_feedback_due_ms
                            + timing["feedback_delay_ms"]):
                        session.selective_feedback_due_ms = None
                    if (session is not None and session.selective_feedback_due_ms is None
                            and session.selective_status_count < timing["max_status"]):
                        collection = (timing["burst_span_ms"] + timing["forward_delay_ms"]
                                      + timing["feedback_guard_ms"])
                        session.selective_feedback_due_ms = self.now_ms + collection
                return  # Assembly in progress

            # Reassembly complete! Reconstruct full unfragmented frame
            frame = CoreFrame(
                message_type=frame.message_type,
                options=frame.options & ~8,
                sequence=frame.sequence,
                route=frame.route,
                fragment=None,
                payload_descriptor=frame.payload_descriptor,
                integrity=frame.integrity,
                security=frame.security,
                extensions=frame.extensions,
                payload=full_payload,
            )
        else:
            if (
                sender_key in self.reassembly.active
                or sender_key in self.reassembly.completed
                or sender_key in self.reassembly.tombstones
            ):
                return  # Conflicting unfragmented use of fragmented identity
            frag_geom = None

        # Process message by type
        if frame.message_type == 6:  # ACK
            self._process_ack(frame, service_id, sender_key, out)
        elif frame.message_type == 8:  # FRAG_STATUS
            self._process_frag_status(frame, service_id, sender_key, out)
        elif frame.message_type in (1, 2):  # RSP or ERR
            accepted = self._process_response_or_err(frame, service_id, sender_key, out)
            if accepted and sender_key in self.reassembly.completed:
                self.reassembly.completed[sender_key].endpoint_accepted = True
        elif frame.message_type == 0:  # REQ
            self._process_req(frame, service_id, sender_key, out, geometry=frag_geom)
        elif frame.message_type == 5:  # TELEM
            self._process_telem(frame, service_id, out)
        elif frame.message_type == 7:  # DATA
            self._process_data(frame, service_id, sender_key, out, geometry=frag_geom)

    def _selective_frame_eligible(self, frame: CoreFrame, service_id: int) -> bool:
        if (not self._selective_enabled(service_id) or service_id == 0
                or self.association is None or frame.security is None
                or frame.fragment is None or not (frame.options & 2)
                or frame.message_type not in (0, 1, 2, 4, 7)):
            return False
        if frame.message_type == 2:
            status_ext = next((ext for ext in frame.extensions if ext.extension_id == 5), None)
            if status_ext is None:
                return False
            try:
                status, end = decode_uleb(status_ext.value)
            except FrameError:
                return False
            if end != len(status_ext.value) or status < 64:
                return False
        count = (frame.fragment.total_length + frame.fragment.chunk_size - 1) // frame.fragment.chunk_size
        return 2 <= count <= 32

    def _selective_transfer_for_sequence(
        self, sequence: int, association_h: bytes
    ) -> tuple[str, Any] | None:
        for exchange in self.delivery.active_outgoing.values():
            if (exchange.seq == sequence and exchange.association_h == association_h
                    and exchange.selective_state is not None):
                return "exchange", exchange
        for result in self.delivery.retained_results.values():
            if (result.result_seq == sequence and result.association_h == association_h
                    and result.selective_state is not None):
                return "result", result
        data_transfer = self.outgoing_data.get((association_h, sequence))
        if data_transfer is not None:
            return "data", data_transfer
        return None

    def _build_fragment_status(
        self, target_key: tuple[int, int, int, int], service_id: int, missing_mask: int
    ) -> bytes | None:
        if (self.association is None or self.association.status not in ("active", "draining")
                or (self.association.status == "draining" and not self._allow_draining_tx)
                or service_id == 0 or not self._selective_enabled(service_id)):
            return None
        route, context = self._routed_fields()
        exts = [Extension(1, True, False, encode_uleb(target_key[3]))]
        if context is not None:
            exts.append(context)
        if service_id != self.default_service:
            exts.append(Extension(4, True, False, encode_uleb(service_id)))
        exts.sort(key=lambda item: item.extension_id)
        frame = CoreFrame(
            message_type=8,
            options=1 | 0x80 | (4 if route else 0),
            sequence=self._alloc_seq(),
            route=route,
            extensions=tuple(exts),
            payload=b"",
        )
        wire = self._encrypt_and_encode(frame, plaintext=missing_mask.to_bytes(4, "little"))
        if len(wire) > self.manifest.values["binding"]["return_mtu"]:
            return None
        return wire

    def _emit_due_fragment_statuses(self, out: list[Any]) -> None:
        if self.association is None or self.association.status != "active":
            return
        timing = self.manifest.values["timing"]
        feedback_limit = timing.get("feedback_buffers", 1)
        pending = sum(bool(item.get("is_frag_status")) for item in self.tx_queue)
        pending += sum(bool(item.get("is_frag_status")) for item in self.active_submissions.values())
        for key, session in list(self.reassembly.active.items()):
            due = session.selective_feedback_due_ms
            if due is None or self.now_ms < due:
                continue
            if (self.now_ms >= session.expires_at_ms or session.service_id == 0
                    or session.selective_status_count >= timing["max_status"]):
                session.selective_feedback_due_ms = None
                continue
            if self.now_ms > due + timing["feedback_delay_ms"]:
                session.selective_feedback_due_ms = None
                continue
            if pending >= feedback_limit or len(self.active_submissions) >= self.adapter_slots:
                continue
            missing = ((1 << session.derived_count) - 1)
            for index in session.received_indices:
                missing &= ~(1 << index)
            if missing == 0 or missing == (1 << session.derived_count) - 1:
                continue
            assoc = next((item for item in self._all_associations()
                          if item.peer_epoch == key[2] and item.status in ("active", "draining")), None)
            if assoc is None:
                session.selective_feedback_due_ms = None
                continue
            with self._use_association(assoc, allow_draining=assoc.status == "draining"):
                status = self._build_fragment_status(key, session.service_id, missing)
            if status is None:
                session.selective_feedback_due_ms = None
                continue
            self._enqueue_tx(
                status,
                not_after_ms=None,
                service_id=session.service_id,
                is_frag_status=True,
                out=out,
            )
            session.selective_feedback_due_ms = None
            session.selective_status_count += 1
            pending += 1

    def _advance_selective_transfers(self, out: list[Any]) -> None:
        owners: list[tuple[str, Any]] = []
        owners.extend(("exchange", item) for item in self.delivery.active_outgoing.values()
                      if item.selective_state is not None)
        owners.extend(("result", item) for item in self.delivery.retained_results.values()
                      if item.selective_state is not None)
        owners.extend(("data", item) for item in self.outgoing_data.values())
        for kind, owner in owners:
            self._drive_selective_transfer(kind, owner, out)

    def _drive_selective_transfer(self, kind: str, owner: Any, out: list[Any]) -> None:
        state: SelectiveTransfer | None = owner.selective_state
        if state is None or state.terminal:
            return
        action = state.take_due_action(self.now_ms)
        if action is None:
            return
        sequence = owner.seq if kind in ("exchange", "data") else owner.result_seq
        transfer_assoc = self._association_by_hash(owner.association_h)
        if transfer_assoc is None or transfer_assoc.status not in ("active", "draining"):
            state.terminate()
            return
        allow_drain = transfer_assoc.status == "draining"
        if action.kind == "stop":
            self._retire_selective_attempts(sequence, out, association_h=owner.association_h)
            if kind == "exchange":
                owner.state = "failed"
                self.delivery.active_outgoing.pop(owner.exchange_id, None)
                self.delivery._release_gate(owner)
                if owner.service_id == 1 and self.sample_consumer and owner.request_payload == b"\x01":
                    if self.sample_consumer.designated_request_seq == owner.seq:
                        self.sample_consumer.designated_request_seq = None
                uncertain = owner.possibly_transmitted or bool(owner.admitted_schedule_handles)
                out.append(ApplicationEvent(
                    kind="diagnostic" if uncertain else "protocol_rejection",
                    service_id=owner.service_id,
                    exchange_id=owner.exchange_id,
                    status=0 if uncertain else 4,
                    payload=b"unknown" if uncertain else b"timeout",
                    at_ms=self.now_ms,
                ))
            elif kind == "result":
                owner.attempts_left = 0
            else:
                self.outgoing_data.pop((owner.association_h, sequence), None)
                out.append(ApplicationEvent(
                    kind="diagnostic",
                    service_id=owner.service_id,
                    exchange_id=0,
                    status=0,
                    payload=b"unknown" if owner.possibly_transmitted else b"timeout",
                    at_ms=self.now_ms,
                ))
            return

        if kind == "exchange":
            with self._use_association(transfer_assoc, allow_draining=allow_drain):
                frames = self._build_req_frames(
                    owner.service_id,
                    owner.seq,
                    owner.request_payload,
                    ack_req=owner.ack_req,
                    freshness_token=owner.freshness_token,
                    selected_indices=action.indices,
                )
            exchange_id = owner.exchange_id
            service_id = owner.service_id
            not_after = owner.not_after_ms
        elif kind == "result":
            target = (owner.req_namespace, owner.req_origin, owner.req_epoch, owner.req_seq)
            if owner.is_app_err:
                state.terminate()
                owner.attempts_left = 0
                return
            with self._use_association(transfer_assoc, allow_draining=allow_drain):
                frames, _ = self._build_rsp_frames(
                    target,
                    owner.service_id,
                    owner.result_payload or b"",
                    own_seq=owner.result_seq,
                    selected_indices=action.indices,
                )
            exchange_id = None
            service_id = owner.service_id
            not_after = None
        else:
            with self._use_association(transfer_assoc, allow_draining=allow_drain):
                frames = self._build_data_frames(
                    owner.service_id,
                    owner.seq,
                    owner.payload,
                    ack_req=owner.ack_req,
                    freshness_token=owner.freshness_token,
                    selected_indices=action.indices,
                )
            exchange_id = None
            service_id = owner.service_id
            not_after = None
        if len(frames) != state.frames_remaining:
            state.terminate()
            if kind == "exchange":
                self._expire_outgoing_exchange(owner, out)
            elif kind == "result":
                owner.attempts_left = 0
            else:
                self.outgoing_data.pop((owner.association_h, sequence), None)
            return
        for frame_bytes in frames:
            self._enqueue_tx(
                frame_bytes,
                not_after_ms=not_after,
                service_id=service_id,
                exchange_id=exchange_id,
                recovery_seq=sequence,
                out=out,
            )

    def _retire_selective_attempts(
        self, sequence: int, out: list[Any], *, association_h: bytes
    ) -> None:
        kept = []
        for item in self.tx_queue:
            if (item.get("recovery_seq") == sequence
                    and item.get("association_h", b"") == association_h):
                exchange = self.delivery.active_outgoing.get(item.get("exchange_id"))
                if exchange is not None:
                    exchange.queued_schedule_frames = max(0, exchange.queued_schedule_frames - 1)
            else:
                kept.append(item)
        self.tx_queue = kept
        for handle, item in self.active_submissions.items():
            if (item.get("recovery_seq") != sequence
                    or item.get("association_h", b"") != association_h
                    or item.get("cancel_requested")):
                continue
            item["cancel_requested"] = True
            if item.get("admitted"):
                out.append(Cancel(handle=handle, generation=item["generation"], at_ms=self.now_ms))

    def _settle_selective_frame(
        self, sequence: int | None, association_h: bytes, out: list[Any]
    ) -> None:
        if sequence is None:
            return
        matched = self._selective_transfer_for_sequence(sequence, association_h)
        if matched is None:
            return
        kind, owner = matched
        state: SelectiveTransfer = owner.selective_state
        if state.settle_frame(self.now_ms):
            self._drive_selective_transfer(kind, owner, out)

    def _process_frag_status(self, frame: CoreFrame, service_id: int, sender_key: tuple, out: list[Any]) -> None:
        """Authenticate first, then bind feedback to one live same-service transfer."""
        assoc = self.association
        if (frame.security is None or assoc is None
                or assoc.status not in ("active", "draining") or service_id == 0
                or not self._selective_enabled(service_id)):
            return
        topology = self.manifest.values.get("binding", {}).get("topology")
        routed = topology in ("static-unicast", "relay-routed")
        required_options = 1 | 0x40 | 0x80 | (4 if routed else 0)
        if frame.options != required_options or frame.fragment is not None or frame.payload_descriptor is not None:
            return
        ext_ids = {ext.extension_id for ext in frame.extensions}
        expected_ext_ids = {1}
        if routed:
            expected_ext_ids.add(2)
        if service_id != self.default_service:
            expected_ext_ids.add(4)
        if not expected_ext_ids.issubset(ext_ids):
            return
        # TYPE 8 forbids other known semantic extensions, but the main extension
        # rules still permit an endpoint to ignore unknown noncritical values.
        if any(
            ext.extension_id not in expected_ext_ids
            and (ext.extension_id in (3, 5, 6) or ext.critical)
            for ext in frame.extensions
        ):
            return
        target_key = self._extract_reply_to(frame)
        if target_key is None or target_key[:3] != (self.namespace, self.local_node_id, self.local_epoch):
            return
        matched = self._selective_transfer_for_sequence(target_key[3], assoc.h)
        if matched is None:
            return
        kind, owner = matched
        if owner.association_h != assoc.h:
            return
        state: SelectiveTransfer = owner.selective_state
        if kind == "exchange":
            expected = (owner.namespace, owner.origin, owner.epoch, owner.seq)
            peer = owner.destination
            if owner.service_id != service_id or owner.state != "awaiting_receipt":
                return
        elif kind == "result":
            expected = (owner.result_namespace, owner.result_origin, owner.result_epoch, owner.result_seq)
            peer = owner.req_origin
            if owner.service_id != service_id or owner.acknowledged:
                return
        else:
            expected = (owner.namespace, owner.origin, owner.epoch, owner.seq)
            peer = owner.destination
            if owner.service_id != service_id or state.terminal:
                return
        if target_key != expected or sender_key[1] != peer or len(frame.payload) != 4:
            return
        missing_mask = int.from_bytes(frame.payload, "little")
        if not state.accept_status(frame.sequence, missing_mask, self.now_ms):
            return
        self._drive_selective_transfer(kind, owner, out)

    def _process_ack(self, frame: CoreFrame, service_id: int, sender_key: tuple, out: list[Any]) -> None:
        ref_key = self._extract_reply_to(frame)
        if not ref_key:
            return
        ref_ns, ref_orig, ref_ep, ref_seq = ref_key
        responder = sender_key[1]

        assoc = self.association
        association_h = assoc.h if assoc is not None else b""

        # Match the logical reference and its owning association before mutating
        # delivery state. The same logical SEQ may be live while an older SA drains.
        exc = next((item for item in self.delivery.active_outgoing.values()
                    if (item.namespace, item.origin, item.epoch, item.seq)
                    == (ref_ns, ref_orig, ref_ep, ref_seq)
                    and item.destination == responder
                    and item.service_id == service_id
                    and item.association_h == association_h), None)
        if exc:
            exc.received_ack = True
            if exc.state == "awaiting_receipt":
                exc.state = "awaiting_result"
            if exc.selective_state is not None:
                exc.selective_state.terminate()
                self._retire_selective_attempts(exc.seq, out, association_h=exc.association_h)
            out.append(ApplicationEvent(
                kind="request_accepted",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=0,
                payload=b"",
                at_ms=self.now_ms,
            ))

        # Check matching result: must match full result identity (namespace, origin, epoch, sequence),
        # expected requester, and service. Colliding sequence from other identity cannot acknowledge result.
        result = next((item for item in self.delivery.retained_results.values()
                       if (item.result_namespace, item.result_origin,
                           item.result_epoch, item.result_seq)
                       == (ref_ns, ref_orig, ref_ep, ref_seq)
                       and item.req_origin == responder
                       and item.service_id == service_id
                       and item.association_h == association_h), None)
        if result is not None:
            result.acknowledged = True
            self.delivery.release_result_gate(
                (result.req_namespace, result.req_origin, result.req_epoch, result.req_seq)
            )
        if result is not None and result.selective_state is not None:
            result.selective_state.terminate()
            self._retire_selective_attempts(
                result.result_seq, out, association_h=result.association_h
            )
        data_transfer = self.outgoing_data.get((association_h, ref_seq))
        if data_transfer is not None and (
            data_transfer.namespace == ref_ns
            and data_transfer.origin == ref_orig
            and data_transfer.epoch == ref_ep
            and data_transfer.destination == responder
            and data_transfer.service_id == service_id
        ):
            data_transfer.selective_state.terminate()
            self._retire_selective_attempts(
                data_transfer.seq, out, association_h=data_transfer.association_h
            )
            self.outgoing_data.pop((data_transfer.association_h, data_transfer.seq), None)
        self._promote_waiting_requests(out)

    def _process_response_or_err(self, frame: CoreFrame, service_id: int, sender_key: tuple, out: list[Any]) -> bool:
        ref_key = self._extract_reply_to(frame)
        if not ref_key:
            return
        ref_ns, ref_orig, ref_ep, ref_seq = ref_key
        responder = sender_key[1]

        status = 0
        for ext in frame.extensions:
            if ext.extension_id == 5:
                status = decode_uleb(ext.value)[0]
                break

        has_ack_req = bool(frame.options & 2)

        # Validate message_type and status combinations before completion
        if frame.message_type == 2:  # ERR
            if 1 <= status <= 7:
                # Protocol rejection ERR MUST NOT have ACK_REQ
                if has_ack_req:
                    return
                exc = self.delivery.match_request_for_result(
                    ref_ns, ref_orig, ref_ep, ref_seq, responder=responder, service_id=service_id
                )
                if exc:
                    self._complete_outgoing_exchange(exc, out)
                    self._promote_waiting_requests(out)
                    out.append(ApplicationEvent(
                        kind="protocol_rejection",
                        service_id=exc.service_id,
                        exchange_id=exc.exchange_id,
                        status=status,
                        payload=frame.payload,
                        at_ms=self.now_ms,
                    ))
                return
            elif status >= 64:
                # Application-result ERR requires ACK_REQ
                if not has_ack_req:
                    return
            else:
                # ERR status 0 or 8..63 is invalid and cannot complete an operation
                return
        elif frame.message_type == 1:  # RSP
            # RSP must have status 0 and requires ACK_REQ
            if status != 0 or not has_ack_req:
                return
        else:
            return

        # Terminal RSP or application-result ERR (STATUS >= 64)
        exc = self.delivery.match_request_for_result(
            ref_ns, ref_orig, ref_ep, ref_seq, responder=responder, service_id=service_id
        )
        if exc:
            if exc.service_id == 0:
                if frame.message_type != 1 or status != 0 or len(frame.payload) != 21 or frame.payload[0] != 0x11:
                    return
                requested = int.from_bytes(exc.request_payload[1:5], "little") if len(exc.request_payload) == 5 else 0
                granted = int.from_bytes(frame.payload[17:21], "little")
                maximum = self.manifest.values.get("freshness", {}).get("lease_ms", 0)
                if not (1 <= granted <= min(requested, maximum)):
                    return
            # Validate SAMPLE-1 terminal response shape, opcode, message type, and correlated request
            if service_id == 1 and self.sample_consumer:
                req_opcode = exc.request_payload[0] if exc.request_payload else 0
                valid_sample1 = False
                if req_opcode == 1:  # Correlated READ request
                    if frame.message_type == 1 and status == 0 and len(frame.payload) == 17 and frame.payload[0] == 1:
                        try:
                            Sample.decode_read_result(frame.payload)
                            valid_sample1 = True
                        except ValueError:
                            valid_sample1 = False
                    elif frame.message_type == 2 and status == 64 and len(frame.payload) == 0:
                        valid_sample1 = True
                elif req_opcode == 2:  # Correlated STATUS request
                    if frame.message_type == 1 and status == 0 and len(frame.payload) == 2 and frame.payload[0] == 2 and frame.payload[1] in (0, 1):
                        valid_sample1 = True

                if not valid_sample1:
                    # Invalid response shape: leave request state eligible for timeout/retry policy,
                    # and must NOT mutate the sample cache or complete exchange
                    return

                assoc_id = 1
                init_gen = self.sample_consumer.init_generation
                if frame.message_type == 2 and status == 64:
                    self.sample_consumer.handle_no_sample(
                        ref_seq, association_id=assoc_id, generation=init_gen
                    )
                elif frame.message_type == 1:
                    self.sample_consumer.handle_read_result(
                        ref_seq, frame.payload, association_id=assoc_id, generation=init_gen, now_ms=self.now_ms
                    )

            if exc.service_id == 0 and frame.message_type == 1 and status == 0 and len(frame.payload) == 21 and frame.payload[0] == 0x11:
                self.active_freshness_token = frame.payload[1:17]

            self._complete_outgoing_exchange(exc, out)
            self._promote_waiting_requests(out)
            out.append(ApplicationEvent(
                kind="request_result",
                service_id=exc.service_id,
                exchange_id=exc.exchange_id,
                status=status,
                payload=frame.payload,
                at_ms=self.now_ms,
            ))

            # Send ACK for the result referencing the result's identity
            if frame.options & 2:  # ACK_REQ
                ack_bytes = self._build_stable_result_ack_frame(
                    sender_key,
                    service_id,
                    request_key=ref_key,
                )
                self._enqueue_tx(ack_bytes, not_after_ms=None, service_id=service_id, out=out)
            return True
        else:
            # Check late-result tombstones
            tombstone = self.delivery.caller_tombstones.get((ref_ns, ref_orig, ref_ep, ref_seq))
            if tombstone and tombstone.expires_at_ms > self.now_ms:
                valid_late_context = (
                    tombstone.responder == responder and tombstone.service_id == service_id
                )
                if service_id == 1:
                    request = tombstone.request_payload
                    if request == b"\x01":
                        valid_late_context = valid_late_context and (
                            (frame.message_type == 1 and status == 0 and self._valid_sample_read(frame.payload))
                            or (frame.message_type == 2 and status == 64 and not frame.payload)
                        )
                    elif request == b"\x02":
                        valid_late_context = valid_late_context and frame.message_type == 1 and status == 0 and len(frame.payload) == 2 and frame.payload in (b"\x02\x00", b"\x02\x01")
                    else:
                        valid_late_context = False
                elif service_id == 2:
                    max_result = self.manifest.values["services"][1]["result_bytes"]
                    valid_late_context = valid_late_context and frame.message_type == 1 and status == 0 and len(frame.payload) <= max_result
                if valid_late_context and frame.options & 2:
                    ack_bytes = self._build_stable_result_ack_frame(
                        sender_key,
                        service_id,
                        request_key=(ref_ns, ref_orig, ref_ep, ref_seq),
                    )
                    self._enqueue_tx(ack_bytes, not_after_ms=None, service_id=service_id, out=out)
                    return True
        return False

    @staticmethod
    def _valid_sample_read(payload: bytes) -> bool:
        try:
            Sample.decode_read_result(payload)
            return True
        except ValueError:
            return False

    def _promote_waiting_requests(self, out: list[Any]) -> None:
        admissible = self.delivery.pop_next_admissible()
        while admissible:
            for frame_bytes in admissible.frames:
                self._enqueue_tx(
                    frame_bytes,
                    not_after_ms=admissible.not_after_ms,
                    service_id=admissible.service_id,
                    exchange_id=admissible.exchange_id,
                    out=out,
                )
            admissible = self.delivery.pop_next_admissible()

    @staticmethod
    def _immutable_message_metadata(frame: CoreFrame, geometry: tuple[int, int] | None = None) -> tuple:
        route = None if frame.route is None else (frame.route.mode, frame.route.source_id, frame.route.destination_id)
        if geometry is None and frame.fragment is not None:
            geometry = (frame.fragment.chunk_size, frame.fragment.total_length)
        sec_meta = None if frame.security is None else (frame.security.cipher, frame.security.receive_cid)
        return (
            geometry is not None,
            geometry,
            frame.options & ~8,
            route,
            frame.payload_descriptor,
            frame.integrity,
            sec_meta,
            tuple((e.extension_id, e.critical, e.unsafe, e.value) for e in frame.extensions),
        )

    def _retain_rejection(self, sender_key: tuple, frame: CoreFrame, service_id: int, status: int, err_frame: bytes, geometry: tuple[int, int] | None = None) -> None:
        err_seq = 0
        try:
            parsed_error = parse_frame(err_frame, max_frame=self.forward_mtu)
            err_seq = parsed_error.sequence or 0
        except FrameError:
            pass
        self.delivery.rejections[sender_key] = RejectionRecord(
            status=status,
            service_id=service_id,
            err_frame_bytes=err_frame,
            created_at_ms=self.now_ms,
            expires_at_ms=self.now_ms + self.delivery.rejection_ms,
            payload=frame.payload,
            immutable_metadata=self._immutable_message_metadata(frame, geometry),
            err_seq=err_seq,
        )
        if frame.security is not None and self.freshness_manager is not None:
            token_ext = next((e for e in frame.extensions if e.extension_id == 6), None)
            if token_ext is not None and len(token_ext.value) == 16:
                self.freshness_manager.consume_token(token_ext.value)

    def _replay_retained_rejection(
        self,
        sender_key: tuple,
        frame: CoreFrame,
        service_id: int,
        out: list[Any],
        geometry: tuple[int, int] | None = None,
    ) -> bool:
        rejection = self.delivery.rejections.get(sender_key)
        if rejection is None:
            return False
        payload_matches = rejection.payload == frame.payload
        if geometry is not None and len(rejection.payload) == geometry[1]:
            offset = frame.fragment.index * frame.fragment.chunk_size
            expected_len = min(frame.fragment.chunk_size, geometry[1] - offset)
            payload_matches = rejection.payload[offset : offset + expected_len] == frame.payload
        if (rejection.service_id != service_id
                or not payload_matches
                or rejection.immutable_metadata != self._immutable_message_metadata(frame, geometry)):
            return True  # Conflicting metadata keeps the retained decision immutable.
        if self.delivery.admit_rejection_replay(rejection):
            err_frame = (
                self._build_err_frame(
                    sender_key,
                    service_id,
                    status=rejection.status,
                    payload=b"",
                    is_reliable=False,
                    own_seq=rejection.err_seq,
                )
                if self.association is not None else rejection.err_frame_bytes
            )
            self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
        return True

    def _reject_sec1_request(
        self,
        sender_key: tuple,
        frame: CoreFrame,
        service_id: int,
        status: int,
        out: list[Any],
    ) -> None:
        if (sender_key in self.delivery.accepted_messages
                or sender_key in self.delivery.retained_results
                or not self.delivery.admit_history()
                or not self.delivery.admit_result(sender_key)):
            return
        err_frame = self._build_err_frame(
            sender_key, service_id, status=status, payload=b"", is_reliable=False
        )
        self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
        geometry = (
            (frame.fragment.chunk_size, frame.fragment.total_length)
            if frame.fragment is not None else None
        )
        self._retain_rejection(sender_key, frame, service_id, status, err_frame, geometry=geometry)

    @staticmethod
    def _required_acl_action(frame: CoreFrame, service_id: int) -> str | None:
        if frame.message_type == 0:  # REQ
            if service_id == 1:
                if frame.payload == b"\x01":
                    return "read"
                if frame.payload == b"\x02":
                    return "status"
                return None
            return "data"
        if frame.message_type == 7:  # DATA
            return "data"
        if frame.message_type == 5:  # TELEM
            return "produce"
        if frame.message_type in (1, 2):  # RSP / ERR
            return "result"
        # ACK is authorized by its authenticated association and a matching
        # pending request/result reference in _process_ack.
        return None

    def _process_req(self, frame: CoreFrame, service_id: int, sender_key: tuple, out: list[Any], geometry: tuple[int, int] | None = None) -> None:
        # A retained rejection owns its identity until expiry. Exact duplicates replay
        # the original decision within its existing burst budget; conflicts are dropped.
        if sender_key in self.delivery.rejections:
            rej = self.delivery.rejections[sender_key]
            if (rej.service_id != service_id or rej.payload != frame.payload
                    or rej.immutable_metadata != self._immutable_message_metadata(frame, geometry)):
                return
            if self.delivery.admit_rejection_replay(rej):
                if self.association is not None:
                    err_frame = self._build_err_frame(
                        sender_key, service_id, status=rej.status, payload=b"", is_reliable=False, own_seq=rej.err_seq
                    )
                else:
                    err_frame = rej.err_frame_bytes
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            return

        # Accepted identity lookup precedes size/ACK policy so changed duplicates
        # cannot replace the retained acceptance with a new rejection.
        if sender_key in self.delivery.accepted_messages:
            rec = self.delivery.accepted_messages[sender_key]
            if (rec.service_id != service_id or rec.message_type != 0
                    or rec.immutable_metadata != self._immutable_message_metadata(frame, geometry)
                    or (frame.security is None and rec.payload != frame.payload)):
                return
            if sender_key in self.delivery.retained_results:
                res = self.delivery.retained_results[sender_key]
                rec = self.delivery.accepted_messages.get(sender_key)
                if res.selective_state is not None:
                    if rec is not None and rec.ack_frame_bytes and self.delivery.admit_receipt_replay(rec):
                        fresh_ack = self._build_ack_frame(sender_key, service_id, own_seq=rec.ack_seq)
                        self._enqueue_tx(fresh_ack, not_after_ms=None, service_id=service_id, out=out)
                elif res.acknowledged:
                    # A duplicate after result release still receives its
                    # receipt ACK, without reissuing the result or token.
                    if rec is not None and rec.ack_frame_bytes and self.delivery.admit_receipt_replay(rec):
                        fresh_ack = self._build_ack_frame(sender_key, service_id, own_seq=rec.ack_seq)
                        self._enqueue_tx(fresh_ack, not_after_ms=None, service_id=service_id, out=out)
                elif self.delivery.admit_result_replay(res, self.now_ms):
                    self._reprotect_retained_result(res)
                    for rf in res.result_frames:
                        self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
            elif rec.ack_frame_bytes and self.delivery.admit_receipt_replay(rec):
                if self.association is not None:
                    fresh_ack = self._build_ack_frame(sender_key, service_id, own_seq=rec.ack_seq)
                    self._enqueue_tx(fresh_ack, not_after_ms=None, service_id=service_id, out=out)
                else:
                    self._enqueue_tx(rec.ack_frame_bytes, not_after_ms=None, service_id=service_id, out=out)
            return

        # Check supported service before execution
        supported_services = {1, 2}
        if self.association is not None:
            supported_services.add(0)
        if self.test_services:
            supported_services.update(self.test_services.keys())
        for svc in self.manifest.values.get("services", []):
            supported_services.add(svc.get("id", svc.get("service_id")))

        if not self.delivery.admit_history() or not self.delivery.admit_result(sender_key):
            return

        if service_id not in supported_services:
            # STATUS 2: Unsupported service / schema / profile
            err_frame = self._build_err_frame(sender_key, service_id, status=2, payload=b"", is_reliable=False)
            self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            self._retain_rejection(sender_key, frame, service_id, 2, err_frame, geometry=geometry)
            return

        # Size limit check
        if service_id == 0:
            max_req_len = 5
        else:
            max_req_len = None
            for svc in self.manifest.values.get("services", []):
                if svc.get("id", svc.get("service_id")) == service_id:
                    max_req_len = svc.get("request_bytes")
                    break
            if max_req_len is None:
                max_req_len = self.manifest.values.get("limits", {}).get("message_bytes", 1048576)
        if len(frame.payload) > max_req_len:
            # STATUS 3: message exceeds configured size
            err_frame = self._build_err_frame(sender_key, service_id, status=3, payload=b"", is_reliable=False)
            self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            self._retain_rejection(sender_key, frame, service_id, 3, err_frame, geometry=geometry)
            return

        if service_id == 1 and frame.payload_descriptor is not None:
            # SAMPLE-1 fixes its representation in the selected profile and
            # does not accept PAYLOAD_DESC or infer an alternate schema.
            err_frame = self._build_err_frame(sender_key, service_id, status=2, payload=b"", is_reliable=False)
            self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            self._retain_rejection(sender_key, frame, service_id, 2, err_frame, geometry=geometry)
            return

        # Check missing ACK_REQ
        if not (frame.options & 2):
            # STATUS 7: invalid application request shape
            err_frame = self._build_err_frame(sender_key, service_id, status=7, payload=b"", is_reliable=False)
            self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            self._retain_rejection(sender_key, frame, service_id, 7, err_frame, geometry=geometry)
            return

        # Check deduplication and conflicting metadata
        if sender_key in self.delivery.rejections:
            rej = self.delivery.rejections[sender_key]
            if rej.service_id != service_id or rej.immutable_metadata != self._immutable_message_metadata(frame, geometry):
                return  # Conflicting metadata: drop
            # Repeat retained rejection without renewing retention
            if self.delivery.admit_rejection_replay(rej):
                if self.association is not None:
                    err_frame = self._build_err_frame(
                        sender_key, service_id, status=rej.status, payload=b"", is_reliable=False, own_seq=rej.err_seq
                    )
                else:
                    err_frame = rej.err_frame_bytes
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            return

        if sender_key in self.delivery.retained_results:
            res = self.delivery.retained_results[sender_key]
            if res.immutable_metadata != self._immutable_message_metadata(frame, geometry):
                return
            if self.delivery.admit_result_replay(res, self.now_ms):
                self._reprotect_retained_result(res)
                for rf in res.result_frames:
                    self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
            return

        # Verify enabled service handler before acceptance or execution
        if service_id == 0:
            pass  # Built-in SEC-1 control handler enabled
        elif service_id == 1:
            if not self.sample_producer:
                # Producer role not active on consumer: STATUS=6 (policy/authorization denied)
                err_frame = self._build_err_frame(sender_key, service_id, status=6, payload=b"", is_reliable=False)
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
                self._retain_rejection(sender_key, frame, service_id, 6, err_frame, geometry=geometry)
                return
        elif service_id == 2:
            pass  # Built-in OPAQUE-1 handler enabled
        elif self.test_services and isinstance(self.test_services, dict) and callable(self.test_services.get(service_id)):
            pass  # Injected test handler enabled
        else:
            # STATUS 2: Unsupported service / schema / profile without enabled handler
            err_frame = self._build_err_frame(sender_key, service_id, status=2, payload=b"", is_reliable=False)
            self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            self._retain_rejection(sender_key, frame, service_id, 2, err_frame, geometry=geometry)
            return

        # Validate Service 0 before reserving the single-result gate. Malformed
        # controls must not leave a gate held until timeout.
        grant_request: int | None = None
        if service_id == 0:
            if len(frame.payload) != 5:
                rejection_status = 7
            elif frame.payload[0] != 0x10:
                rejection_status = 1
            else:
                requested_lifetime = int.from_bytes(frame.payload[1:5], "little")
                rejection_status = 0 if 1 <= requested_lifetime <= 60000 else 7
                if rejection_status == 0:
                    grant_request = requested_lifetime
            if rejection_status:
                err_frame = self._build_err_frame(sender_key, 0, status=rejection_status, payload=b"", is_reliable=False)
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=0, out=out)
                self._retain_rejection(sender_key, frame, 0, rejection_status, err_frame, geometry=geometry)
                return

            freshness_cfg = self.manifest.values.get("freshness", {})
            if self.freshness_manager is None or freshness_cfg.get("lease_ms", 0) <= 0:
                err_frame = self._build_err_frame(sender_key, 0, status=2, payload=b"", is_reliable=False)
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=0, out=out)
                self._retain_rejection(sender_key, frame, 0, 2, err_frame, geometry=geometry)
                return
            if self.remote_node_id not in freshness_cfg.get("grant_nodes", []):
                err_frame = self._build_err_frame(sender_key, 0, status=6, payload=b"", is_reliable=False)
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=0, out=out)
                self._retain_rejection(sender_key, frame, 0, 6, err_frame, geometry=geometry)
                return

        # Execute request
        if service_id == 1 and (len(frame.payload) != 1 or frame.payload[0] not in (1, 2)):
            err_frame = self._build_err_frame(sender_key, service_id, status=7, payload=b"", is_reliable=False)
            self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            self._retain_rejection(sender_key, frame, service_id, 7, err_frame, geometry=geometry)
            return
        if not self.delivery.reserve_result_gate(self.remote_node_id, service_id, sender_key):
            return
        exchange_id = self._alloc_exchange_id()

        if service_id == 0:
            req_lifetime = grant_request
            freshness_cfg = self.manifest.values["freshness"]
            try:
                grant = self.freshness_manager.issue_grant(
                    self.association.h,
                    sender_key[1],
                    req_lifetime,
                    self.now_ms,
                    max_policy_ms=freshness_cfg["lease_ms"],
                    max_tokens_per_association=freshness_cfg["tokens_per_association"],
                    max_tokens_per_principal=freshness_cfg["tokens_per_principal"],
                    max_requests_per_pair=freshness_cfg["grant_requests_per_pair"],
                    token_record_ms=freshness_cfg["token_record_ms"],
                )
            except FreshnessError:
                self.delivery.release_result_gate(sender_key)
                return
            if grant is None:
                self.delivery.release_result_gate(sender_key)
                err_frame = self._build_err_frame(sender_key, 0, status=4, payload=b"", is_reliable=False)
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=0, out=out)
                self._retain_rejection(sender_key, frame, 0, 4, err_frame, geometry=geometry)
                return
            else:
                token, granted_ms = grant
                result_payload = b"\x11" + token + granted_ms.to_bytes(4, "little")
                result_status = 0
                is_app_err = False
                rsp_frames, result_seq = self._build_rsp_frames(sender_key, 0, result_payload)
            for rf in rsp_frames:
                self._enqueue_tx(rf, not_after_ms=None, service_id=0, out=out)
            self.delivery.retained_results[sender_key] = RetainedResult(
                service_id=0,
                req_namespace=sender_key[0],
                req_origin=sender_key[1],
                req_epoch=sender_key[2],
                req_seq=sender_key[3],
                result_seq=result_seq,
                result_frames=tuple(rsp_frames),
                result_frame_bytes=rsp_frames[0],
                result_payload=result_payload,
                is_app_err=is_app_err,
                status=result_status,
                created_at_ms=self.now_ms,
                expires_at_ms=self.now_ms + freshness_cfg["grant_result_ms"],
                result_namespace=self.namespace,
                result_origin=self.local_node_id,
                result_epoch=self.local_epoch,
                next_retry_ms=self.now_ms + self.delivery.response_timeout_ms,
                attempts_left=max(0, self.delivery.max_bursts - 1),
                gate_destination=self.remote_node_id,
                immutable_metadata=self._immutable_message_metadata(frame, geometry),
                association_h=self.association.h if self.association is not None else b"",
            )
        elif service_id == 1:
            # SAMPLE-1 request validation
            if len(frame.payload) != 1 or frame.payload[0] not in (1, 2):
                # STATUS 7
                err_frame = self._build_err_frame(sender_key, service_id, status=7, payload=b"", is_reliable=False)
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
                self._retain_rejection(sender_key, frame, service_id, 7, err_frame, geometry=geometry)
                return

            if frame.payload[0] == 1:  # READ
                status, result_payload = self.sample_producer.handle_read()
                if status == 0:
                    rsp_frames, result_seq = self._build_rsp_frames(sender_key, service_id, result_payload)
                    for rf in rsp_frames:
                        self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
                    self.delivery.retained_results[sender_key] = RetainedResult(
                        service_id=service_id,
                        req_namespace=sender_key[0],
                        req_origin=sender_key[1],
                        req_epoch=sender_key[2],
                        req_seq=sender_key[3],
                        result_seq=result_seq,
                        result_frames=tuple(rsp_frames),
                        result_frame_bytes=rsp_frames[0],
                        result_payload=result_payload,
                        is_app_err=False,
                        status=0,
                        created_at_ms=self.now_ms,
                        expires_at_ms=self.now_ms + self.delivery.result_cache_ms,
                        result_namespace=self.namespace,
                        result_origin=self.local_node_id,
                        result_epoch=self.local_epoch,
                        next_retry_ms=self.now_ms + self.delivery.response_timeout_ms,
                        attempts_left=max(0, self.delivery.max_bursts - 1),
                        gate_destination=self.remote_node_id,
                        immutable_metadata=self._immutable_message_metadata(frame, geometry),
                        association_h=self.association.h if self.association is not None else b"",
                    )
                else:  # NO_SAMPLE: status 64
                    err_frame, result_seq = self._build_err_frame_reliable(sender_key, service_id, status=64, payload=b"")
                    self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
                    self.delivery.retained_results[sender_key] = RetainedResult(
                        service_id=service_id,
                        req_namespace=sender_key[0],
                        req_origin=sender_key[1],
                        req_epoch=sender_key[2],
                        req_seq=sender_key[3],
                        result_seq=result_seq,
                        result_frames=(err_frame,),
                        result_frame_bytes=err_frame,
                        result_payload=b"",
                        is_app_err=True,
                        status=64,
                        created_at_ms=self.now_ms,
                        expires_at_ms=self.now_ms + self.delivery.result_cache_ms,
                        result_namespace=self.namespace,
                        result_origin=self.local_node_id,
                        result_epoch=self.local_epoch,
                        next_retry_ms=self.now_ms + self.delivery.response_timeout_ms,
                        attempts_left=max(0, self.delivery.max_bursts - 1),
                        gate_destination=self.remote_node_id,
                        immutable_metadata=self._immutable_message_metadata(frame, geometry),
                        association_h=self.association.h if self.association is not None else b"",
                    )
            elif frame.payload[0] == 2:  # STATUS
                status, result_payload = self.sample_producer.handle_status()
                rsp_frames, result_seq = self._build_rsp_frames(sender_key, service_id, result_payload)
                for rf in rsp_frames:
                    self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
                self.delivery.retained_results[sender_key] = RetainedResult(
                    service_id=service_id,
                    req_namespace=sender_key[0],
                    req_origin=sender_key[1],
                    req_epoch=sender_key[2],
                    req_seq=sender_key[3],
                    result_seq=result_seq,
                    result_frames=tuple(rsp_frames),
                    result_frame_bytes=rsp_frames[0],
                    result_payload=result_payload,
                    is_app_err=False,
                    status=0,
                    created_at_ms=self.now_ms,
                    expires_at_ms=self.now_ms + self.delivery.result_cache_ms,
                    result_namespace=self.namespace,
                    result_origin=self.local_node_id,
                    result_epoch=self.local_epoch,
                    next_retry_ms=self.now_ms + self.delivery.response_timeout_ms,
                    attempts_left=max(0, self.delivery.max_bursts - 1),
                    gate_destination=self.remote_node_id,
                    immutable_metadata=self._immutable_message_metadata(frame, geometry),
                    association_h=self.association.h if self.association is not None else b"",
                )
        elif service_id == 2:
            # OPAQUE-1 idempotent workload
            max_res = self.manifest.values["services"][1]["result_bytes"]
            res_len = len(frame.payload) if len(frame.payload) < max_res else max_res
            result_payload = bytes((i % 256) ^ 0xA5 for i in range(res_len))
            rsp_frames, result_seq = self._build_rsp_frames(sender_key, service_id, result_payload)
            retained = RetainedResult(
                service_id=service_id,
                req_namespace=sender_key[0],
                req_origin=sender_key[1],
                req_epoch=sender_key[2],
                req_seq=sender_key[3],
                result_seq=result_seq,
                result_frames=tuple(rsp_frames),
                result_frame_bytes=rsp_frames[0],
                result_payload=result_payload,
                is_app_err=False,
                status=0,
                created_at_ms=self.now_ms,
                expires_at_ms=self.now_ms + self.delivery.result_cache_ms,
                result_namespace=self.namespace,
                result_origin=self.local_node_id,
                result_epoch=self.local_epoch,
                next_retry_ms=self.now_ms + self.delivery.response_timeout_ms,
                attempts_left=max(0, self.delivery.max_bursts - 1),
                gate_destination=self.remote_node_id,
                immutable_metadata=self._immutable_message_metadata(frame, geometry),
                association_h=self.association.h if self.association is not None else b"",
                selective_state=(self._new_selective_transfer(len(rsp_frames))
                                 if self._selective_enabled(service_id) and len(rsp_frames) > 1
                                 else None),
            )
            self.delivery.retained_results[sender_key] = retained
            for rf in rsp_frames:
                self._enqueue_tx(
                    rf,
                    not_after_ms=None,
                    service_id=service_id,
                    recovery_seq=result_seq if retained.selective_state is not None else None,
                    out=out,
                )
        elif self.test_services and isinstance(self.test_services, dict) and callable(self.test_services.get(service_id)):
            res = self.test_services[service_id](frame.payload)
            if isinstance(res, tuple):
                res_status, res_payload = res
            else:
                res_status, res_payload = 0, res
            if res_status == 0:
                rsp_frames, result_seq = self._build_rsp_frames(sender_key, service_id, res_payload)
                for rf in rsp_frames:
                    self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
                self.delivery.retained_results[sender_key] = RetainedResult(
                    service_id=service_id,
                    req_namespace=sender_key[0],
                    req_origin=sender_key[1],
                    req_epoch=sender_key[2],
                    req_seq=sender_key[3],
                    result_seq=result_seq,
                    result_frames=tuple(rsp_frames),
                    result_frame_bytes=rsp_frames[0],
                    result_payload=res_payload,
                    is_app_err=False,
                    status=0,
                    created_at_ms=self.now_ms,
                    expires_at_ms=self.now_ms + self.delivery.result_cache_ms,
                    result_namespace=self.namespace,
                    result_origin=self.local_node_id,
                    result_epoch=self.local_epoch,
                    next_retry_ms=self.now_ms + self.delivery.response_timeout_ms,
                    attempts_left=max(0, self.delivery.max_bursts - 1),
                    gate_destination=self.remote_node_id,
                    immutable_metadata=self._immutable_message_metadata(frame, geometry),
                    association_h=self.association.h if self.association is not None else b"",
                )
            else:
                err_frame, result_seq = self._build_err_frame_reliable(sender_key, service_id, status=res_status, payload=res_payload)
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
                self.delivery.retained_results[sender_key] = RetainedResult(
                    service_id=service_id,
                    req_namespace=sender_key[0],
                    req_origin=sender_key[1],
                    req_epoch=sender_key[2],
                    req_seq=sender_key[3],
                    result_seq=result_seq,
                    result_frames=(err_frame,),
                    result_frame_bytes=err_frame,
                    result_payload=res_payload,
                    is_app_err=True,
                    status=res_status,
                    created_at_ms=self.now_ms,
                    expires_at_ms=self.now_ms + self.delivery.result_cache_ms,
                    result_namespace=self.namespace,
                    result_origin=self.local_node_id,
                    result_epoch=self.local_epoch,
                    next_retry_ms=self.now_ms + self.delivery.response_timeout_ms,
                    attempts_left=max(0, self.delivery.max_bursts - 1),
                    gate_destination=self.remote_node_id,
                    immutable_metadata=self._immutable_message_metadata(frame, geometry),
                    association_h=self.association.h if self.association is not None else b"",
                )

        # Build cached receipt ACK distinct from terminal result frames
        receipt_ack_bytes = self._build_ack_frame(sender_key, service_id)
        ack_seq = decode_uleb(receipt_ack_bytes, 3)[0] if len(receipt_ack_bytes) > 3 else 0

        # Preserve request acceptance record across dedup horizon even after result release
        self.delivery.accepted_messages[sender_key] = AcceptedRecord(
            message_type=0,
            service_id=service_id,
            ack_seq=ack_seq,
            ack_frame_bytes=receipt_ack_bytes,
            created_at_ms=self.now_ms,
            expires_at_ms=self.now_ms + self.delivery.dedup_ms,
            payload=frame.payload,
            immutable_metadata=self._immutable_message_metadata(frame, geometry),
        )

        if self.association is not None:
            ext_fresh = next((e for e in frame.extensions if e.extension_id == 6), None)
            if ext_fresh and len(ext_fresh.value) == 16:
                self.freshness_manager.consume_token(ext_fresh.value)

        out.append(ApplicationEvent(
            kind="request_accepted",
            service_id=service_id,
            exchange_id=exchange_id,
            status=0,
            payload=frame.payload,
            at_ms=self.now_ms,
        ))

    def _process_telem(self, frame: CoreFrame, service_id: int, out: list[Any]) -> None:
        if service_id == 1 and self.sample_consumer:
            try:
                self.sample_consumer.handle_telemetry(frame.payload)
            except ValueError:
                # Malformed SAMPLE-1 telemetry is dropped at the application
                # boundary; it cannot escape Receive as an endpoint exception.
                return

    def _process_data(self, frame: CoreFrame, service_id: int, sender_key: tuple, out: list[Any], geometry: tuple[int, int] | None = None) -> None:
        # Check if rejected
        if sender_key in self.delivery.rejections:
            rej = self.delivery.rejections[sender_key]
            if (rej.service_id != service_id or rej.payload != frame.payload
                    or rej.immutable_metadata != self._immutable_message_metadata(frame, geometry)):
                return  # Conflicting metadata
            if self.delivery.admit_rejection_replay(rej):
                if self.association is not None:
                    err_frame = self._build_err_frame(
                        sender_key, service_id, status=rej.status, payload=b"", is_reliable=False, own_seq=rej.err_seq
                    )
                else:
                    err_frame = rej.err_frame_bytes
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            return

        # Check message type conflict with retained result
        if sender_key in self.delivery.retained_results:
            return

        # Deduplication check: accepted DATA identities never re-dispatch or re-run service effects within horizon
        if sender_key in self.delivery.accepted_messages:
            rec = self.delivery.accepted_messages[sender_key]
            if (rec.service_id != service_id or rec.message_type != 7
                    or rec.immutable_metadata != self._immutable_message_metadata(frame, geometry)
                    or (frame.security is None and rec.payload != frame.payload)):
                return  # Conflicting immutable metadata cannot become a new acceptance
            # Matching duplicate: replay cached ACK without renewing absolute retention
            if rec.ack_frame_bytes:
                if not self.delivery.admit_receipt_replay(rec):
                    return
                if self.association is not None:
                    fresh_ack = self._build_ack_frame(sender_key, service_id, own_seq=rec.ack_seq)
                    self._enqueue_tx(fresh_ack, not_after_ms=None, service_id=service_id, out=out)
                else:
                    self._enqueue_tx(rec.ack_frame_bytes, not_after_ms=None, service_id=service_id, out=out)
            return

        if not self.delivery.admit_history():
            return

        ack_bytes = b""
        ack_seq = 0
        if frame.options & 2:  # ACK_REQ
            ack_bytes = self._build_ack_frame(sender_key, service_id)
            self._enqueue_tx(ack_bytes, not_after_ms=None, service_id=service_id, out=out)
            ack_seq = decode_uleb(ack_bytes, 3)[0] if len(ack_bytes) > 3 else 0

        self.delivery.accepted_messages[sender_key] = AcceptedRecord(
            message_type=7,
            service_id=service_id,
            ack_seq=ack_seq,
            ack_frame_bytes=ack_bytes,
            created_at_ms=self.now_ms,
            expires_at_ms=self.now_ms + self.delivery.dedup_ms,
            payload=frame.payload,
            immutable_metadata=self._immutable_message_metadata(frame, geometry),
        )

        if self.association is not None and self.freshness_manager is not None:
            self.freshness_manager.consume_identity(self.association.h, sender_key)

        out.append(ApplicationEvent(
            kind="request_accepted",
            service_id=service_id,
            exchange_id=self._alloc_exchange_id(),
            status=0,
            payload=frame.payload,
            at_ms=self.now_ms,
        ))

    def _handle_application_request(self, req: ApplicationRequest, out: list[Any]) -> None:
        exchange_id = req.exchange_id if req.exchange_id != 0 else self._alloc_exchange_id()

        if not self.is_open:
            out.append(ApplicationEvent(
                kind="protocol_rejection",
                service_id=req.service_id,
                exchange_id=exchange_id,
                status=4,
                payload=b"disconnected",
                at_ms=self.now_ms,
            ))
            return

        if self.sec_mode is not None and not self.test_only_disable_sec1:
            assoc = self.association
            if assoc is not None and assoc.is_expired(self.now_ms):
                self._expire_security_context(out)
                assoc = None
            if assoc is None or assoc.status != "active":
                out.append(ApplicationEvent(
                    kind="protocol_rejection",
                    service_id=req.service_id,
                    exchange_id=exchange_id,
                    status=4,
                    payload=b"security_not_active",
                    at_ms=self.now_ms,
                ))
                return

        # Check if already expired before admission
        if req.not_after_ms is not None and self.now_ms >= req.not_after_ms:
            out.append(ApplicationEvent(
                kind="protocol_rejection",
                service_id=req.service_id,
                exchange_id=exchange_id,
                status=4,
                payload=b"expired",
                at_ms=self.now_ms,
            ))
            return

        freshness_token = None
        if self.association is not None and req.service_id != 0:
            svc_cfg = next((s for s in self.manifest.values.get("services", []) if s.get("id") == req.service_id), None)
            if svc_cfg and svc_cfg.get("freshness"):
                freshness_token = self.active_freshness_token
                if freshness_token is None:
                    out.append(ApplicationEvent(
                        kind="protocol_rejection",
                        service_id=req.service_id,
                        exchange_id=exchange_id,
                        status=4,
                        payload=b"freshness_token_required",
                        at_ms=self.now_ms,
                    ))
                    return

        seq = self._alloc_seq()

        # Build request frames (single or fragmented)
        frames = self._build_req_frames(
            service_id=req.service_id,
            seq=seq,
            payload=req.payload,
            ack_req=req.ack_req,
            freshness_token=freshness_token,
        )

        # Single OutgoingExchange for all slices of the message
        exc = OutgoingExchange(
            exchange_id=exchange_id,
            service_id=req.service_id,
            destination=self.remote_node_id,
            seq=seq,
            namespace=self.namespace,
            origin=self.local_node_id,
            epoch=self.local_epoch,
            frames=tuple(frames),
            ack_req=req.ack_req,
            not_after_ms=req.not_after_ms,
            created_at_ms=self.now_ms,
            response_timeout_ms=self.manifest.values["timing"]["response_timeout_ms"],
            result_deadline_ms=self.manifest.values["timing"]["result_deadline_ms"],
            max_attempts=self.manifest.values["timing"]["max_bursts"],
            request_payload=req.payload,
            freshness_token=freshness_token,
            association_h=self.association.h if self.association is not None else b"",
        )
        if (req.ack_req and self._selective_enabled(req.service_id)
                and len(frames) > 1):
            exc.selective_state = self._new_selective_transfer(len(frames))

        # If consumer designated READ, record seq
        if req.service_id == 1 and self.sample_consumer and req.payload == b"\x01":
            self.sample_consumer.designate_read(seq, at_ms=self.now_ms)

        admission = self.delivery.enqueue_outgoing(exc)
        if admission:
            if freshness_token is not None and self.active_freshness_token == freshness_token:
                self.active_freshness_token = None
            for frame_bytes in frames:
                self._enqueue_tx(
                    frame_bytes,
                    not_after_ms=req.not_after_ms,
                    service_id=req.service_id,
                    exchange_id=exchange_id,
                    recovery_seq=seq if exc.selective_state is not None else None,
                    out=out,
                )
        elif admission != "queue_full" and freshness_token is not None and self.active_freshness_token == freshness_token:
            # A queued reliable exchange owns the token across admission delay and retries.
            self.active_freshness_token = None
        elif admission == "queue_full":
            out.append(ApplicationEvent(
                kind="protocol_rejection",
                service_id=req.service_id,
                exchange_id=exchange_id,
                status=4,
                payload=b"queue_full",
                at_ms=self.now_ms,
            ))

    def _handle_publish_sample(self, event: PublishSample, out: list[Any]) -> None:
        if not self.sample_producer:
            return
        if self.sec_mode is not None and not self.test_only_disable_sec1:
            assoc = self.association
            if assoc is not None and assoc.is_expired(self.now_ms):
                self._expire_security_context(out)
                # PublishSample is best effort; no insecure or candidate-state frame is emitted.
                self.sample_dropped_count += 1
                self.counters["dropped_samples"] += 1
                return
            if assoc is None or assoc.status != "active":
                self.sample_dropped_count += 1
                self.counters["dropped_samples"] += 1
                return
        if self.sample_producer._sample_index >= 0xFFFFFFFF and self.is_open:
            # Retire the association before advancing the producer epoch.
            self._handle_disconnect(Disconnect(link=self.link or 0, at_ms=self.now_ms), out)
        sample = self.sample_producer.publish(event.value)
        if not self.is_open:
            return
        # Construct TELEM frame (16 bytes payload)
        payload = sample.encode_telemetry()
        if self.association is not None:
            seq = self._alloc_seq()
            route, context = self._routed_fields()
            frame = CoreFrame(
                message_type=5,
                options=1 | (4 if route else 0) | (0x80 if context else 0),
                sequence=seq,
                route=route,
                extensions=(context,) if context else (),
                payload=b"",
            )
            frame_bytes = self._encrypt_and_encode(frame, plaintext=payload)
        else:
            frame = CoreFrame(message_type=5, options=0, payload=payload)
            frame_bytes = encode_frame(frame, max_frame=self.forward_mtu)
        self._enqueue_tx(frame_bytes, not_after_ms=None, service_id=1, is_sample_telemetry=True, out=out)

    def _enqueue_tx(
        self,
        raw_bytes: bytes,
        *,
        not_after_ms: Optional[int],
        service_id: int = 1,
        exchange_id: Optional[int] = None,
        is_sample_telemetry: bool = False,
        bootstrap_attempt_id: bytes | None = None,
        recovery_seq: int | None = None,
        is_frag_status: bool = False,
        out: list[Any],
    ) -> None:
        association_h = b""
        try:
            protected = parse_frame(raw_bytes, max_frame=self.forward_mtu)
            if protected.security is not None:
                selected = next((item for item in self._all_associations()
                                 if item.peer_rx_cid == protected.security.receive_cid), None)
                association_h = selected.h if selected is not None else b""
        except Exception:
            pass
        if recovery_seq is None and exchange_id is not None:
            exchange = self.delivery.active_outgoing.get(exchange_id)
            if exchange is not None and exchange.selective_state is not None:
                recovery_seq = exchange.seq
        if recovery_seq is None and not is_frag_status:
            try:
                core = parse_frame(raw_bytes, max_frame=self.forward_mtu)
            except Exception:
                core = None
            if core is not None and core.message_type in (1, 2) and core.fragment is not None:
                result = next((item for item in self.delivery.retained_results.values()
                               if item.result_seq == core.sequence and item.service_id == service_id), None)
                if result is not None and self._selective_enabled(service_id):
                    if result.selective_state is None and len(result.result_frames) > 1:
                        result.selective_state = self._new_selective_transfer(len(result.result_frames))
                    if result.selective_state is not None:
                        recovery_seq = result.result_seq

        # Wrap into Stream R envelope if needed
        if self.binding_kind == "stream-r":
            if raw_bytes == b"\x00":
                wire_bytes = b"\x00"
            else:
                wire_bytes = encode_stream_r(raw_bytes, max_core=self.forward_mtu, max_encoded=self.encoded_mtu)
        else:
            wire_bytes = raw_bytes

        # Check deadline before submitting
        if not_after_ms is not None and self.now_ms >= not_after_ms:
            exc = self.delivery.active_outgoing.get(exchange_id) if exchange_id is not None else None
            if exc:
                self._expire_outgoing_exchange(exc, out)
            else:
                out.append(ApplicationEvent(
                    kind="diagnostic",
                    service_id=service_id,
                    exchange_id=exchange_id or 0,
                    status=0,
                    payload=b"local_expiry",
                    at_ms=self.now_ms,
                ))
            return

        if is_sample_telemetry:
            for item in self.tx_queue:
                if item.get("is_sample_telemetry"):
                    item["wire_bytes"] = wire_bytes
                    item["not_after_ms"] = not_after_ms
                    item["service_id"] = service_id
                    item["exchange_id"] = exchange_id
                    self.sample_coalesced_count += 1
                    self.counters["coalesced_samples"] += 1
                    out.append(ApplicationEvent(
                        kind="diagnostic",
                        service_id=1,
                        exchange_id=0,
                        status=0,
                        payload=b"sample_coalesced",
                        at_ms=self.now_ms,
                    ))
                    return
            if len(self.active_submissions) >= self.adapter_slots:
                if len(self.tx_queue) >= self.max_queued_frames:
                    self.sample_dropped_count += 1
                    self.counters["dropped_samples"] += 1
                    out.append(ApplicationEvent(
                        kind="diagnostic",
                        service_id=1,
                        exchange_id=0,
                        status=0,
                        payload=b"sample_dropped",
                        at_ms=self.now_ms,
                    ))
                    return
                self.tx_queue.append({
                    "wire_bytes": wire_bytes,
                    "not_after_ms": not_after_ms,
                    "service_id": service_id,
                    "exchange_id": exchange_id,
                    "is_sample_telemetry": True,
                    "bootstrap_attempt_id": bootstrap_attempt_id,
                    "recovery_seq": recovery_seq,
                    "is_frag_status": is_frag_status,
                    "association_h": association_h,
                })
                return
            self._submit_wire(
                wire_bytes, not_after_ms, service_id, exchange_id, out,
                bootstrap_attempt_id=bootstrap_attempt_id,
                recovery_seq=recovery_seq,
                is_frag_status=is_frag_status,
                association_h=association_h,
            )
            return

        if len(self.active_submissions) >= self.adapter_slots:
            if len(self.tx_queue) >= self.max_queued_frames:
                raise RuntimeError("manifest-backed pending transmission capacity exhausted")
            self.tx_queue.append({
                "wire_bytes": wire_bytes,
                "not_after_ms": not_after_ms,
                "service_id": service_id,
                "exchange_id": exchange_id,
                "bootstrap_attempt_id": bootstrap_attempt_id,
                "recovery_seq": recovery_seq,
                "is_frag_status": is_frag_status,
                "association_h": association_h,
            })
            if exchange_id is not None and exchange_id in self.delivery.active_outgoing:
                self.delivery.active_outgoing[exchange_id].queued_schedule_frames += 1
            return
        self._submit_wire(
            wire_bytes, not_after_ms, service_id, exchange_id, out,
            bootstrap_attempt_id=bootstrap_attempt_id,
            recovery_seq=recovery_seq,
            is_frag_status=is_frag_status,
            association_h=association_h,
        )

    def _submit_wire(
        self,
        wire_bytes,
        not_after_ms,
        service_id,
        exchange_id,
        out,
        *,
        bootstrap_attempt_id: bytes | None = None,
        recovery_seq: int | None = None,
        is_frag_status: bool = False,
        association_h: bytes = b"",
    ):
        if not self.is_open:
            return
        if not_after_ms is not None and self.now_ms >= not_after_ms:
            exc = self.delivery.active_outgoing.get(exchange_id) if exchange_id is not None else None
            if exc:
                self._expire_outgoing_exchange(exc, out)
            else:
                out.append(ApplicationEvent(
                    kind="diagnostic", service_id=service_id, exchange_id=exchange_id or 0,
                    status=0, payload=b"local_expiry", at_ms=self.now_ms,
                ))
            return
        handle = self._alloc_handle()
        item = {
            "handle": handle,
            "generation": self.generation,
            "bytes": wire_bytes,
            "not_after_ms": not_after_ms,
            "at_ms": self.now_ms,
            "service_id": service_id,
            "exchange_id": exchange_id,
            "bootstrap_attempt_id": bootstrap_attempt_id,
            "recovery_seq": recovery_seq,
            "is_frag_status": is_frag_status,
            "association_h": association_h,
            "admitted": False,
            "cancel_requested": False,
            "cancel_emitted": False,
        }
        self.active_submissions[handle] = item
        if exchange_id is not None and exchange_id in self.delivery.active_outgoing:
            exc = self.delivery.active_outgoing[exchange_id]
            exc.active_submission_handles.append(handle)
            exc.pending_schedule_handles.add(handle)
        out.append(TxSubmit(
            handle=handle,
            generation=self.generation,
            bytes=wire_bytes,
            not_after_ms=not_after_ms,
            at_ms=self.now_ms,
        ))

    def _drain_tx_queue(self, out: list[Any]) -> None:
        while self.is_open and self.tx_queue and len(self.active_submissions) < self.adapter_slots:
            item = self.tx_queue.pop(0)
            if (item.get("bootstrap_attempt_id") is not None
                    and item.get("bootstrap_attempt_id") != self._bootstrap_attempt_id):
                continue
            exc = self.delivery.active_outgoing.get(item.get("exchange_id")) if item.get("exchange_id") is not None else None
            if item.get("exchange_id") is not None and exc is None:
                continue
            if exc:
                exc.queued_schedule_frames = max(0, exc.queued_schedule_frames - 1)
            if item["not_after_ms"] is not None and self.now_ms >= item["not_after_ms"]:
                bootstrap_attempt_id = item.get("bootstrap_attempt_id")
                if bootstrap_attempt_id is not None and bootstrap_attempt_id == self._bootstrap_attempt_id:
                    self._abort_bootstrap_attempt(out)
                    continue
                if exc:
                    self._expire_outgoing_exchange(exc, out)
                else:
                    out.append(ApplicationEvent(
                        kind="diagnostic",
                        service_id=item["service_id"],
                        exchange_id=item.get("exchange_id") or 0,
                        status=0,
                        payload=b"local_expiry",
                        at_ms=self.now_ms,
                    ))
                continue
            self._submit_wire(
                item["wire_bytes"], item["not_after_ms"], item["service_id"], item["exchange_id"], out,
                bootstrap_attempt_id=item.get("bootstrap_attempt_id"),
                recovery_seq=item.get("recovery_seq"),
                is_frag_status=item.get("is_frag_status", False),
                association_h=item.get("association_h", b""),
            )

    def _extract_reply_to(self, frame: CoreFrame) -> Optional[tuple[int, int, int, int]]:
        for ext in frame.extensions:
            if ext.extension_id == 1:
                if frame.security is not None:
                    # Protected compact format: single ULEB32 seq resolved via receiver identity (§S4, S10.16)
                    seq, at = decode_uleb(ext.value, 0)
                    if at != len(ext.value):
                        return None  # Extraneous bytes rejected!
                    return self.namespace, self.local_node_id, self.local_epoch, seq
                else:
                    # SECURITY=0 full reply to: namespace, origin, epoch(8 bytes LE), seq
                    ns, at = decode_uleb(ext.value, 0)
                    orig, at = decode_uleb(ext.value, at)
                    if len(ext.value) - at < 8:
                        return None
                    epoch = int.from_bytes(ext.value[at : at + 8], "little")
                    at += 8
                    seq, at_end = decode_uleb(ext.value, at)
                    if at_end != len(ext.value):
                        return None
                    return ns, orig, epoch, seq
        return None

    def _build_ack_frame(
        self,
        target_key: tuple[int, int, int, int],
        service_id: int,
        own_seq: int | None = None,
    ) -> bytes:
        tgt_ns, tgt_orig, tgt_ep, tgt_seq = target_key
        if own_seq is None:
            own_seq = self._alloc_seq()

        if self.association is not None:
            reply_to_bytes = encode_uleb(tgt_seq)
        else:
            reply_to_bytes = bytearray()
            reply_to_bytes.extend(encode_uleb(tgt_ns))
            reply_to_bytes.extend(encode_uleb(tgt_orig))
            reply_to_bytes.extend(tgt_ep.to_bytes(8, "little"))
            reply_to_bytes.extend(encode_uleb(tgt_seq))
            reply_to_bytes = bytes(reply_to_bytes)

        exts = [Extension(extension_id=1, critical=True, unsafe=False, value=reply_to_bytes)]
        route, context = self._routed_fields()
        if context is not None:
            exts.append(context)
        if service_id != self.default_service or service_id == 0:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))
        exts.sort(key=lambda e: e.extension_id)

        frame = CoreFrame(
            message_type=6,  # ACK
            options=1 | 0x80 | (4 if route else 0),  # SEQ | EXT | optional ROUTE
            sequence=own_seq,
            route=route,
            extensions=tuple(exts),
            payload=b"",
        )
        if self.association is not None:
            return self._encrypt_and_encode(frame, plaintext=b"")
        return encode_frame(frame, max_frame=self.forward_mtu)

    def _build_stable_result_ack_frame(
        self,
        result_key: tuple[int, int, int, int],
        service_id: int,
        *,
        request_key: tuple[int, int, int, int] | None,
        completed: Any | None = None,
    ) -> bytes:
        tombstone = self.delivery.caller_tombstones.get(request_key) if request_key is not None else None
        own_seq = tombstone.result_ack_seq if tombstone is not None else None
        if own_seq is None and completed is not None:
            own_seq = completed.result_ack_seq
        ack = self._build_ack_frame(result_key, service_id, own_seq=own_seq)
        if own_seq is None:
            own_seq = parse_frame(ack, max_frame=self.forward_mtu).sequence
        if tombstone is not None and tombstone.result_ack_seq is None:
            tombstone.result_ack_seq = own_seq
        if completed is not None and completed.result_ack_seq is None:
            completed.result_ack_seq = own_seq
        return ack

    def _build_rsp_frames(
        self,
        target_key: tuple[int, int, int, int],
        service_id: int,
        payload: bytes,
        own_seq: int | None = None,
        selected_indices: tuple[int, ...] | None = None,
    ) -> tuple[list[bytes], int]:
        tgt_ns, tgt_orig, tgt_ep, tgt_seq = target_key
        if own_seq is None:
            own_seq = self._alloc_seq()

        if self.association is not None:
            reply_to_bytes = encode_uleb(tgt_seq)
        else:
            reply_to_bytes = bytearray()
            reply_to_bytes.extend(encode_uleb(tgt_ns))
            reply_to_bytes.extend(encode_uleb(tgt_orig))
            reply_to_bytes.extend(tgt_ep.to_bytes(8, "little"))
            reply_to_bytes.extend(encode_uleb(tgt_seq))
            reply_to_bytes = bytes(reply_to_bytes)

        exts = [Extension(extension_id=1, critical=True, unsafe=False, value=reply_to_bytes)]
        route, context = self._routed_fields()
        if context is not None:
            exts.append(context)
        if service_id != self.default_service or service_id == 0:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))
        exts.sort(key=lambda e: e.extension_id)

        base_options = 0x83  # SEQ | ACK_REQ | EXT
        chunk_bytes = self.manifest.values["limits"]["chunk_bytes"]

        if len(payload) > chunk_bytes:
            total_len = len(payload)
            num_frags = (total_len + chunk_bytes - 1) // chunk_bytes
            frames = []
            for idx in range(num_frags):
                if selected_indices is not None and idx not in selected_indices:
                    continue
                slice_bytes = payload[idx * chunk_bytes : (idx + 1) * chunk_bytes]
                frame = CoreFrame(
                    message_type=1,  # RSP
                    options=base_options | 8 | (4 if route else 0),  # FRAG / optional ROUTE
                    sequence=own_seq,
                    route=route,
                    fragment=Fragment(index=idx, chunk_size=chunk_bytes, total_length=total_len),
                    extensions=tuple(exts),
                    payload=slice_bytes if self.association is None else b"",
                )
                if self.association is not None:
                    frames.append(self._encrypt_and_encode(frame, plaintext=slice_bytes))
                else:
                    frames.append(encode_frame(frame, max_frame=self.forward_mtu))
            return frames, own_seq
        else:
            frame = CoreFrame(
                message_type=1,  # RSP
                options=base_options | (4 if route else 0),
                sequence=own_seq,
                route=route,
                extensions=tuple(exts),
                payload=payload if self.association is None else b"",
            )
            if self.association is not None:
                return [self._encrypt_and_encode(frame, plaintext=payload)], own_seq
            return [encode_frame(frame, max_frame=self.forward_mtu)], own_seq

    def _queue_data_transfer(
        self,
        service_id: int,
        payload: bytes,
        *,
        ack_req: bool,
        out: list[Any],
    ) -> int:
        """Queue one locally originated DATA transfer through SELECTIVE-32 recovery."""
        assoc = self.association
        if assoc is None or assoc.status != "active":
            raise SecurityError("protected DATA requires an active association")
        if isinstance(service_id, bool) or not isinstance(service_id, int) or service_id == 0:
            raise ValueError("DATA service_id must be a nonzero integer")
        if not isinstance(payload, bytes):
            raise TypeError("DATA payload must be bytes")
        if len(payload) > self.manifest.values["limits"]["message_bytes"]:
            raise ValueError("DATA payload exceeds the manifest message limit")
        service = next((item for item in self.manifest.values.get("services", [])
                        if item.get("id") == service_id), None)
        acl = next((item for item in service.get("acl", [])
                    if item.get("node") == self.remote_node_id), None) if service else None
        if service is None or acl is None or "data" not in acl.get("actions", []):
            raise AuthorizationError("peer is not authorized for DATA on this service")
        freshness_token = None
        if self.association is not None and service.get("freshness"):
            freshness_token = self.active_freshness_token
            if freshness_token is None:
                raise SecurityError("freshness token required for DATA")
            if not isinstance(freshness_token, bytes) or len(freshness_token) != 16:
                raise SecurityError("freshness token must be exactly 16 bytes")
        sender_slots = self.delivery.sender_slots
        active_slots = (len(self.delivery.active_outgoing) + len(self.delivery.queue)
                        + len(self.outgoing_data))
        if sender_slots is not None and active_slots >= sender_slots:
            raise ValueError("manifest sender slots are exhausted")

        chunk = self.manifest.values["limits"]["chunk_bytes"]
        count = max(1, (len(payload) + chunk - 1) // chunk)
        if count > self.manifest.values["limits"]["fragments"]:
            raise ValueError("DATA payload exceeds the manifest fragment limit")
        seq = self._alloc_seq()
        frames = self._build_data_frames(
            service_id,
            seq,
            payload,
            ack_req=ack_req,
            freshness_token=freshness_token,
        )
        state = (
            self._new_selective_transfer(len(frames))
            if ack_req and self._selective_enabled(service_id) and len(frames) > 1
            else None
        )
        if state is not None:
            self.outgoing_data[(assoc.h, seq)] = _OutgoingDataTransfer(
                service_id=service_id,
                seq=seq,
                namespace=self.namespace,
                origin=self.local_node_id,
                epoch=assoc.local_epoch,
                destination=self.remote_node_id,
                payload=bytes(payload),
                ack_req=ack_req,
                selective_state=state,
                freshness_token=freshness_token,
                association_h=assoc.h,
            )
        if freshness_token is not None and self.active_freshness_token == freshness_token:
            self.active_freshness_token = None
        for frame in frames:
            self._enqueue_tx(
                frame,
                not_after_ms=None,
                service_id=service_id,
                recovery_seq=seq if state is not None else None,
                out=out,
            )
        return seq

    def _build_data_frames(
        self,
        service_id: int,
        seq: int,
        payload: bytes,
        *,
        ack_req: bool = True,
        freshness_token: bytes | None = None,
        selected_indices: tuple[int, ...] | None = None,
    ) -> list[bytes]:
        """Build DATA logical transfers for independent peer recovery scenarios."""
        exts: list[Extension] = []
        route, context = self._routed_fields()
        if context is not None:
            exts.append(context)
        if service_id != self.default_service or service_id == 0:
            exts.append(Extension(4, True, False, encode_uleb(service_id)))
        svc_cfg = next((item for item in self.manifest.values.get("services", [])
                        if item.get("id") == service_id), None)
        if (self.association is not None and svc_cfg and svc_cfg.get("freshness")
                and freshness_token is not None):
            if not isinstance(freshness_token, bytes) or len(freshness_token) != 16:
                raise ValueError("S7 freshness tokens must be exactly 16 bytes")
            exts.append(Extension(6, True, False, freshness_token))
        exts.sort(key=lambda e: e.extension_id)
        options = 1 | (2 if ack_req else 0) | (0x80 if exts else 0) | (4 if route else 0)
        chunk = self.manifest.values["limits"]["chunk_bytes"]
        if len(payload) > chunk:
            count = (len(payload) + chunk - 1) // chunk
            frames = []
            for index in range(count):
                if selected_indices is not None and index not in selected_indices:
                    continue
                part = payload[index * chunk : (index + 1) * chunk]
                frame = CoreFrame(
                    7, options | 8, seq, route=route,
                    fragment=Fragment(index, chunk, len(payload)),
                    extensions=tuple(exts), payload=part if self.association is None else b"",
                )
                frames.append(self._encrypt_and_encode(frame, plaintext=part)
                              if self.association is not None
                              else encode_frame(frame, max_frame=self.forward_mtu))
            return frames
        frame = CoreFrame(
            7, options, seq, route=route, extensions=tuple(exts),
            payload=payload if self.association is None else b"",
        )
        return [self._encrypt_and_encode(frame, plaintext=payload)
                if self.association is not None
                else encode_frame(frame, max_frame=self.forward_mtu)]

    def _build_err_frame(
        self,
        target_key: tuple[int, int, int, int],
        service_id: int,
        status: int,
        payload: bytes = b"",
        is_reliable: bool = False,
        own_seq: int | None = None,
    ) -> bytes:
        tgt_ns, tgt_orig, tgt_ep, tgt_seq = target_key
        if own_seq is None:
            own_seq = self._alloc_seq()

        if self.association is not None:
            reply_to_bytes = encode_uleb(tgt_seq)
        else:
            reply_to_bytes = bytearray()
            reply_to_bytes.extend(encode_uleb(tgt_ns))
            reply_to_bytes.extend(encode_uleb(tgt_orig))
            reply_to_bytes.extend(tgt_ep.to_bytes(8, "little"))
            reply_to_bytes.extend(encode_uleb(tgt_seq))
            reply_to_bytes = bytes(reply_to_bytes)

        exts = [
            Extension(extension_id=1, critical=True, unsafe=False, value=reply_to_bytes),
            Extension(extension_id=5, critical=True, unsafe=False, value=encode_uleb(status)),
        ]
        route, context = self._routed_fields()
        if context is not None:
            exts.append(context)
        if service_id != self.default_service or service_id == 0:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))
        exts.sort(key=lambda e: e.extension_id)

        options = 0x81 | (2 if is_reliable else 0)
        frame = CoreFrame(
            message_type=2,  # ERR
            options=options | (4 if route else 0),
            sequence=own_seq,
            route=route,
            extensions=tuple(exts),
            payload=payload if self.association is None else b"",
        )
        if self.association is not None:
            return self._encrypt_and_encode(frame, plaintext=payload)
        return encode_frame(frame, max_frame=self.forward_mtu)

    def _build_err_frame_reliable(
        self,
        target_key: tuple[int, int, int, int],
        service_id: int,
        status: int,
        payload: bytes = b"",
        own_seq: int | None = None,
    ) -> tuple[bytes, int]:
        tgt_ns, tgt_orig, tgt_ep, tgt_seq = target_key
        if own_seq is None:
            own_seq = self._alloc_seq()

        if self.association is not None:
            reply_to_bytes = encode_uleb(tgt_seq)
        else:
            reply_to_bytes = bytearray()
            reply_to_bytes.extend(encode_uleb(tgt_ns))
            reply_to_bytes.extend(encode_uleb(tgt_orig))
            reply_to_bytes.extend(tgt_ep.to_bytes(8, "little"))
            reply_to_bytes.extend(encode_uleb(tgt_seq))
            reply_to_bytes = bytes(reply_to_bytes)

        exts = [
            Extension(extension_id=1, critical=True, unsafe=False, value=reply_to_bytes),
            Extension(extension_id=5, critical=True, unsafe=False, value=encode_uleb(status)),
        ]
        route, context = self._routed_fields()
        if context is not None:
            exts.append(context)
        if service_id != self.default_service or service_id == 0:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))
        exts.sort(key=lambda e: e.extension_id)

        frame = CoreFrame(
            message_type=2,  # ERR
            options=0x83 | (4 if route else 0),  # SEQ | ACK_REQ | EXT | optional ROUTE
            sequence=own_seq,
            route=route,
            extensions=tuple(exts),
            payload=payload if self.association is None else b"",
        )
        if self.association is not None:
            return self._encrypt_and_encode(frame, plaintext=payload), own_seq
        return encode_frame(frame, max_frame=self.forward_mtu), own_seq

    def _reprotect_retained_result(self, res: RetainedResult) -> None:
        """Re-encrypt a retained logical result with a fresh PN and stable identity."""
        assoc = self._association_by_hash(res.association_h)
        if assoc is None or assoc.status not in ("active", "draining"):
            return
        if res.result_payload is None:
            res.result_frames = ()
            return
        target = (res.req_namespace, res.req_origin, res.req_epoch, res.req_seq)
        with self._use_association(assoc, allow_draining=assoc.status == "draining"):
            if res.is_app_err:
                err, _ = self._build_err_frame_reliable(
                    target,
                    res.service_id,
                    res.status,
                    payload=res.result_payload,
                    own_seq=res.result_seq,
                )
                res.result_frames = (err,)
            else:
                frames, _ = self._build_rsp_frames(
                    target,
                    res.service_id,
                    res.result_payload,
                    own_seq=res.result_seq,
                )
                res.result_frames = tuple(frames)

    def _build_req_frames(
        self,
        service_id: int,
        seq: int,
        payload: bytes,
        ack_req: bool = True,
        freshness_token: bytes | None = None,
        selected_indices: tuple[int, ...] | None = None,
    ) -> list[bytes]:
        exts = []
        route, context = self._routed_fields()
        if context is not None:
            exts.append(context)
        if service_id != self.default_service or service_id == 0:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))

        if self.association is not None and service_id != 0:
            svc_cfg = next((s for s in self.manifest.values.get("services", []) if s.get("id") == service_id), None)
            if svc_cfg and svc_cfg.get("freshness") and freshness_token is not None:
                exts.append(Extension(extension_id=6, critical=True, unsafe=False, value=freshness_token))

        exts.sort(key=lambda e: e.extension_id)

        base_options = 1 | (2 if ack_req else 0) | (0x80 if exts else 0) | (4 if route else 0)
        chunk_bytes = self.manifest.values["limits"]["chunk_bytes"]

        if len(payload) > chunk_bytes:
            # Fragmented message
            total_len = len(payload)
            num_frags = (total_len + chunk_bytes - 1) // chunk_bytes
            frames = []
            for idx in range(num_frags):
                if selected_indices is not None and idx not in selected_indices:
                    continue
                slice_bytes = payload[idx * chunk_bytes : (idx + 1) * chunk_bytes]
                frame = CoreFrame(
                    message_type=0,  # REQ
                    options=base_options | 8,  # FRAG
                    sequence=seq,
                    route=route,
                    fragment=Fragment(index=idx, chunk_size=chunk_bytes, total_length=total_len),
                    extensions=tuple(exts),
                    payload=slice_bytes if self.association is None else b"",
                )
                if self.association is not None:
                    frames.append(self._encrypt_and_encode(frame, plaintext=slice_bytes))
                else:
                    frames.append(encode_frame(frame, max_frame=self.forward_mtu))
            return frames
        else:
            frame = CoreFrame(
                message_type=0,  # REQ
                options=base_options,
                sequence=seq,
                route=route,
                extensions=tuple(exts),
                payload=payload if self.association is None else b"",
            )
            if self.association is not None:
                return [self._encrypt_and_encode(frame, plaintext=payload)]
            return [encode_frame(frame, max_frame=self.forward_mtu)]
