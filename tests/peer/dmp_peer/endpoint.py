"""DMP-PEER-TEST/1 endpoint implementation (dev/P20_Independent_Peer_Brief.md)."""

from __future__ import annotations

import struct
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
from .frame import CoreFrame, Extension, Fragment, decode_uleb, encode_frame, encode_uleb, parse_frame
from .manifest import Manifest, ManifestError, identify_frozen_manifest
from .reassembly import ConflictError, QuotaError, ReassemblyError, ReassemblyManager
from .sample1 import Sample, SampleConsumer, SampleEpochStore, SampleProducer
from .stream_r import StreamRDecoder, encode_stream_r


class PeerEndpoint:
    """Independent DMP v2 peer exposing the DMP-PEER-TEST/1 API."""

    def __init__(
        self,
        manifest_bytes: bytes,
        test_credentials: Any,
        entropy_source: Callable[[int], bytes],
        test_services: Any,
    ) -> None:
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
            app_queue_slots=limits["application_queue_slots"],
            sender_slots=resource_slots.get("sender"),
            result_slots=resource_slots.get("result"),
            history_slots=resource_slots.get("history"),
            correlation_slots=resource_slots.get("correlation"),
        )
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

    def _alloc_handle(self) -> int:
        handle = self.next_handle
        self.next_handle = (self.next_handle + 1) & 0xFFFFFFFF
        if self.next_handle == 0:
            self.next_handle = 1
        return handle

    def _alloc_seq(self) -> int:
        seq = self.next_seq
        self.next_seq = (self.next_seq + 1) & 0xFFFFFFFF
        if self.next_seq == 0:
            self.next_seq = 1
        return seq

    def _alloc_exchange_id(self) -> int:
        eid = self.next_exchange_id
        self.next_exchange_id += 1
        return eid

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
            if isinstance(input_event, TxTerminal) and not sub.get("admitted"):
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
            # Candidate timeout from timing.feedback_delay_ms or 500ms
            cand_timeout = self.manifest.values["timing"].get("feedback_delay_ms", 500)
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

        sub["admit_resolved"] = True
        if event.accepted:
            sub["admitted"] = True
            if exc:
                exc.admitted_schedule_handles.add(event.handle)
            if sub.get("cancel_requested"):
                out.append(Cancel(handle=event.handle, generation=event.generation, at_ms=self.now_ms))
        else:
            # Rejected by adapter: caller retains ownership; no subsequent terminal event
            del self.active_submissions[event.handle]
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
            self._drain_tx_queue(out)

    def _handle_tx_terminal(self, event: TxTerminal, out: list[Any]) -> None:
        sub = self.active_submissions.get(event.handle)
        if not sub or sub["generation"] != event.generation:
            # Stale completion: must not free current slot!
            return

        del self.active_submissions[event.handle]

        exc_id = sub.get("exchange_id")
        exc = self.delivery.active_outgoing.get(exc_id) if exc_id else None

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
        elif event.outcome in ("expired_unsent", "cancelled_unsent", "failed_unsent"):
            if exc:
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

        self._drain_tx_queue(out)

    def _retire_exchange_attempts(self, exc: OutgoingExchange, out: list[Any], trigger_handle: int | None = None) -> None:
        kept = []
        for item in self.tx_queue:
            if item.get("exchange_id") == exc.exchange_id:
                exc.queued_schedule_frames = max(0, exc.queued_schedule_frames - 1)
            else:
                kept.append(item)
        self.tx_queue = kept
        for handle in exc.active_submission_handles:
            sub = self.active_submissions.get(handle)
            if handle != trigger_handle and sub and not sub.get("cancel_requested"):
                sub["cancel_requested"] = True
                if sub.get("admitted"):
                    out.append(Cancel(handle=handle, generation=sub["generation"], at_ms=self.now_ms))

    def _expire_outgoing_exchange(self, exc: OutgoingExchange, out: list[Any]) -> None:
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

    def _handle_restart(self, event: Restart, out: list[Any]) -> None:
        # Restart uses injected deterministic entropy; fails closed when absent or reused
        if not event.entropy or len(event.entropy) < 8:
            raise EventValidationError("Restart requires at least 8 bytes of entropy")
        if event.entropy in self.used_entropy:
            raise EventValidationError("Restart entropy has already been used")
        self.used_entropy.add(event.entropy)

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
        if self.stream_r_decoder:
            stream_events = self.stream_r_decoder.advance(self.now_ms)
            for se in stream_events:
                if se.kind == "frame" and se.frame:
                    self._process_core_bytes(se.frame, out)

        # Advance reassembly
        self.reassembly.advance(self.now_ms)
        if self.sample_consumer:
            self.sample_consumer.advance(self.now_ms)

        # Advance delivery: returns due retries and expired exchanges (removed from active list)
        due_reqs, due_results, expired_excs = self.delivery.advance(self.now_ms)

        for exc in due_reqs:
            # Check deadline before retransmitting
            if exc.not_after_ms is not None and self.now_ms >= exc.not_after_ms:
                self._expire_outgoing_exchange(exc, out)
            else:
                for f_bytes in exc.frames:
                    self._enqueue_tx(f_bytes, not_after_ms=exc.not_after_ms, service_id=exc.service_id, exchange_id=exc.exchange_id, out=out)

        # Retransmit all frames of retained results
        for res in due_results:
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

    def _process_core_bytes(self, raw_frame: bytes, out: list[Any]) -> None:
        try:
            frame = parse_frame(raw_frame, max_frame=self.forward_mtu)
        except Exception:
            return  # FrameError: reject frame

        # Reject protected frames: SEC-1 belongs to P21C (test-only provisional)
        if frame.security is not None:
            return

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
                return

            if getattr(res, "already_completed", False):
                # Trigger cached receipt/result behavior without reopening or re-executing
                if frame.message_type == 0:  # REQ
                    if sender_key in self.delivery.retained_results:
                        res_obj = self.delivery.retained_results[sender_key]
                        if self.delivery.admit_result_replay(res_obj, self.now_ms):
                            for rf in res_obj.result_frames:
                                self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
                    elif sender_key in self.delivery.accepted_messages:
                        rec = self.delivery.accepted_messages[sender_key]
                        if rec.ack_frame_bytes:
                            self._enqueue_tx(rec.ack_frame_bytes, not_after_ms=None, service_id=service_id, out=out)
                    elif sender_key in self.delivery.rejections:
                        rej = self.delivery.rejections[sender_key]
                        if rej.service_id != service_id:
                            return
                        offset = frame.fragment.index * frame.fragment.chunk_size
                        expected_len = min(frame.fragment.chunk_size, frame.fragment.total_length - offset)
                        if rej.payload and rej.payload[offset : offset + expected_len] != frame.payload:
                            return
                        if self.delivery.admit_rejection_replay(rej):
                            self._enqueue_tx(rej.err_frame_bytes, not_after_ms=None, service_id=service_id, out=out)
                elif frame.message_type == 7:  # DATA
                    if sender_key in self.delivery.accepted_messages:
                        rec = self.delivery.accepted_messages[sender_key]
                        if rec.ack_frame_bytes:
                            self._enqueue_tx(rec.ack_frame_bytes, not_after_ms=None, service_id=service_id, out=out)
                elif frame.message_type in (1, 2) and frame.options & 2:
                    completed = self.reassembly.completed.get(sender_key)
                    if (not completed or not getattr(completed, "endpoint_accepted", False)
                            or completed.result_ack_replays >= self.delivery.max_bursts - 1):
                        return
                    completed.result_ack_replays += 1
                    self._enqueue_tx(
                        self._build_ack_frame(sender_key, service_id),
                        not_after_ms=None,
                        service_id=service_id,
                        out=out,
                    )
                return

            complete, full_payload = res[0], res[1]
            if not complete or full_payload is None:
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

    def _process_ack(self, frame: CoreFrame, service_id: int, sender_key: tuple, out: list[Any]) -> None:
        ref_key = self._extract_reply_to(frame)
        if not ref_key:
            return
        ref_ns, ref_orig, ref_ep, ref_seq = ref_key
        responder = sender_key[1]

        # Check matching request: must match logical ref, expected peer, and service
        exc = self.delivery.record_ack_received(
            ref_ns, ref_orig, ref_ep, ref_seq, responder=responder, service_id=service_id
        )
        if exc:
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
        self.delivery.record_result_ack_received(
            ref_ns, ref_orig, ref_ep, ref_seq, responder=responder, service_id=service_id
        )
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
                ack_bytes = self._build_ack_frame(sender_key, service_id)
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
                    ack_bytes = self._build_ack_frame(sender_key, service_id)
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
        return (
            geometry is not None,
            geometry,
            frame.options & ~8,
            route,
            frame.payload_descriptor,
            frame.integrity,
            frame.security,
            tuple((e.extension_id, e.critical, e.unsafe, e.value) for e in frame.extensions),
        )

    def _retain_rejection(self, sender_key: tuple, frame: CoreFrame, service_id: int, status: int, err_frame: bytes, geometry: tuple[int, int] | None = None) -> None:
        self.delivery.rejections[sender_key] = RejectionRecord(
            status=status,
            service_id=service_id,
            err_frame_bytes=err_frame,
            created_at_ms=self.now_ms,
            expires_at_ms=self.now_ms + self.delivery.rejection_ms,
            payload=frame.payload,
            immutable_metadata=self._immutable_message_metadata(frame, geometry),
        )

    def _process_req(self, frame: CoreFrame, service_id: int, sender_key: tuple, out: list[Any], geometry: tuple[int, int] | None = None) -> None:
        # A retained rejection owns its identity until expiry. Exact duplicates replay
        # the original decision within its existing burst budget; conflicts are dropped.
        if sender_key in self.delivery.rejections:
            rej = self.delivery.rejections[sender_key]
            if (rej.service_id != service_id or rej.payload != frame.payload
                    or rej.immutable_metadata != self._immutable_message_metadata(frame, geometry)):
                return
            if self.delivery.admit_rejection_replay(rej):
                self._enqueue_tx(rej.err_frame_bytes, not_after_ms=None, service_id=service_id, out=out)
            return

        # Accepted identity lookup precedes size/ACK policy so changed duplicates
        # cannot replace the retained acceptance with a new rejection.
        if sender_key in self.delivery.accepted_messages:
            rec = self.delivery.accepted_messages[sender_key]
            if rec.service_id != service_id or rec.message_type != 0 or rec.payload != frame.payload or rec.immutable_metadata != self._immutable_message_metadata(frame, geometry):
                return
            if sender_key in self.delivery.retained_results:
                res = self.delivery.retained_results[sender_key]
                if self.delivery.admit_result_replay(res, self.now_ms):
                    for rf in res.result_frames:
                        self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
            elif rec.ack_frame_bytes and rec.replay_bursts < self.delivery.max_bursts - 1:
                rec.replay_bursts += 1
                self._enqueue_tx(rec.ack_frame_bytes, not_after_ms=None, service_id=service_id, out=out)
            return

        # Check supported service before execution
        supported_services = {1, 2}
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
                err_frame = self._build_err_frame(sender_key, service_id, status=rej.status, payload=b"", is_reliable=False)
                self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            return

        if sender_key in self.delivery.retained_results:
            res = self.delivery.retained_results[sender_key]
            if self.delivery.admit_result_replay(res, self.now_ms):
                for rf in res.result_frames:
                    self._enqueue_tx(rf, not_after_ms=None, service_id=service_id, out=out)
            return

        # Verify enabled service handler before acceptance or execution
        if service_id == 1:
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

        # Execute request
        if service_id == 1 and (len(frame.payload) != 1 or frame.payload[0] not in (1, 2)):
            err_frame = self._build_err_frame(sender_key, service_id, status=7, payload=b"", is_reliable=False)
            self._enqueue_tx(err_frame, not_after_ms=None, service_id=service_id, out=out)
            self._retain_rejection(sender_key, frame, service_id, 7, err_frame, geometry=geometry)
            return
        if not self.delivery.reserve_result_gate(self.remote_node_id, service_id, sender_key):
            return
        exchange_id = self._alloc_exchange_id()

        if service_id == 1:
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
                )
        elif service_id == 2:
            # OPAQUE-1 idempotent workload
            max_res = self.manifest.values["services"][1]["result_bytes"]
            res_len = len(frame.payload) if len(frame.payload) < max_res else max_res
            result_payload = bytes((i % 256) ^ 0xA5 for i in range(res_len))
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
            self.sample_consumer.handle_telemetry(frame.payload)

    def _process_data(self, frame: CoreFrame, service_id: int, sender_key: tuple, out: list[Any], geometry: tuple[int, int] | None = None) -> None:
        # Check if rejected
        if sender_key in self.delivery.rejections:
            rej = self.delivery.rejections[sender_key]
            if rej.service_id != service_id or rej.immutable_metadata != self._immutable_message_metadata(frame, geometry):
                return  # Conflicting metadata
            if self.delivery.admit_rejection_replay(rej):
                self._enqueue_tx(rej.err_frame_bytes, not_after_ms=None, service_id=service_id, out=out)
            return

        # Check message type conflict with retained result
        if sender_key in self.delivery.retained_results:
            return

        # Deduplication check: accepted DATA identities never re-dispatch or re-run service effects within horizon
        if sender_key in self.delivery.accepted_messages:
            rec = self.delivery.accepted_messages[sender_key]
            if rec.service_id != service_id or rec.message_type != 7 or rec.payload != frame.payload or rec.immutable_metadata != self._immutable_message_metadata(frame, geometry):
                return  # Conflicting metadata or payload cannot become a new acceptance
            # Matching duplicate: replay cached ACK without renewing absolute retention
            if rec.ack_frame_bytes:
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

        seq = self._alloc_seq()

        # Build request frames (single or fragmented)
        frames = self._build_req_frames(service_id=req.service_id, seq=seq, payload=req.payload, ack_req=req.ack_req)

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
        )

        # If consumer designated READ, record seq
        if req.service_id == 1 and self.sample_consumer and req.payload == b"\x01":
            self.sample_consumer.designate_read(seq, at_ms=self.now_ms)

        admission = self.delivery.enqueue_outgoing(exc)
        if admission:
            for frame_bytes in frames:
                self._enqueue_tx(frame_bytes, not_after_ms=req.not_after_ms, service_id=req.service_id, exchange_id=exchange_id, out=out)
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
        if self.sample_producer._sample_index >= 0xFFFFFFFF and self.is_open:
            # Retire the association before advancing the producer epoch.
            self._handle_disconnect(Disconnect(link=self.link or 0, at_ms=self.now_ms), out)
        sample = self.sample_producer.publish(event.value)
        if not self.is_open:
            return
        # Construct TELEM frame (16 bytes payload)
        payload = sample.encode_telemetry()
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
        out: list[Any],
    ) -> None:
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
                })
                return
            self._submit_wire(wire_bytes, not_after_ms, service_id, exchange_id, out)
            return

        if len(self.active_submissions) >= self.adapter_slots:
            if len(self.tx_queue) >= self.max_queued_frames:
                raise RuntimeError("manifest-backed pending transmission capacity exhausted")
            self.tx_queue.append({
                "wire_bytes": wire_bytes,
                "not_after_ms": not_after_ms,
                "service_id": service_id,
                "exchange_id": exchange_id,
            })
            if exchange_id is not None and exchange_id in self.delivery.active_outgoing:
                self.delivery.active_outgoing[exchange_id].queued_schedule_frames += 1
            return
        self._submit_wire(wire_bytes, not_after_ms, service_id, exchange_id, out)

    def _submit_wire(self, wire_bytes, not_after_ms, service_id, exchange_id, out):
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
            "admitted": False,
            "cancel_requested": False,
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
            exc = self.delivery.active_outgoing.get(item.get("exchange_id")) if item.get("exchange_id") is not None else None
            if item.get("exchange_id") is not None and exc is None:
                continue
            if exc:
                exc.queued_schedule_frames = max(0, exc.queued_schedule_frames - 1)
            if item["not_after_ms"] is not None and self.now_ms >= item["not_after_ms"]:
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
                item["wire_bytes"], item["not_after_ms"], item["service_id"], item["exchange_id"], out
            )

    def _extract_reply_to(self, frame: CoreFrame) -> Optional[tuple[int, int, int, int]]:
        for ext in frame.extensions:
            if ext.extension_id == 1:
                # SECURITY=0 full reply to: namespace, origin, epoch(8 bytes LE), seq
                ns, at = decode_uleb(ext.value, 0)
                orig, at = decode_uleb(ext.value, at)
                if len(ext.value) - at < 8:
                    return None
                epoch = int.from_bytes(ext.value[at : at + 8], "little")
                at += 8
                seq, _ = decode_uleb(ext.value, at)
                return ns, orig, epoch, seq
        return None

    def _build_ack_frame(self, target_key: tuple[int, int, int, int], service_id: int) -> bytes:
        tgt_ns, tgt_orig, tgt_ep, tgt_seq = target_key
        own_seq = self._alloc_seq()

        reply_to_bytes = bytearray()
        reply_to_bytes.extend(encode_uleb(tgt_ns))
        reply_to_bytes.extend(encode_uleb(tgt_orig))
        reply_to_bytes.extend(tgt_ep.to_bytes(8, "little"))
        reply_to_bytes.extend(encode_uleb(tgt_seq))

        exts = [Extension(extension_id=1, critical=True, unsafe=False, value=bytes(reply_to_bytes))]
        if service_id != self.default_service:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))
            exts.sort(key=lambda e: e.extension_id)

        frame = CoreFrame(
            message_type=6,  # ACK
            options=0x81,  # SEQ | EXT
            sequence=own_seq,
            extensions=tuple(exts),
            payload=b"",
        )
        return encode_frame(frame, max_frame=self.forward_mtu)

    def _build_rsp_frames(self, target_key: tuple[int, int, int, int], service_id: int, payload: bytes) -> tuple[list[bytes], int]:
        tgt_ns, tgt_orig, tgt_ep, tgt_seq = target_key
        own_seq = self._alloc_seq()

        reply_to_bytes = bytearray()
        reply_to_bytes.extend(encode_uleb(tgt_ns))
        reply_to_bytes.extend(encode_uleb(tgt_orig))
        reply_to_bytes.extend(tgt_ep.to_bytes(8, "little"))
        reply_to_bytes.extend(encode_uleb(tgt_seq))

        exts = [Extension(extension_id=1, critical=True, unsafe=False, value=bytes(reply_to_bytes))]
        if service_id != self.default_service:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))
        exts.sort(key=lambda e: e.extension_id)

        base_options = 0x83  # SEQ | ACK_REQ | EXT
        chunk_bytes = self.manifest.values["limits"]["chunk_bytes"]

        if len(payload) > chunk_bytes:
            total_len = len(payload)
            num_frags = (total_len + chunk_bytes - 1) // chunk_bytes
            frames = []
            for idx in range(num_frags):
                slice_bytes = payload[idx * chunk_bytes : (idx + 1) * chunk_bytes]
                frame = CoreFrame(
                    message_type=1,  # RSP
                    options=base_options | 8,  # FRAG
                    sequence=own_seq,
                    fragment=Fragment(index=idx, chunk_size=chunk_bytes, total_length=total_len),
                    extensions=tuple(exts),
                    payload=slice_bytes,
                )
                frames.append(encode_frame(frame, max_frame=self.forward_mtu))
            return frames, own_seq
        else:
            frame = CoreFrame(
                message_type=1,  # RSP
                options=base_options,
                sequence=own_seq,
                extensions=tuple(exts),
                payload=payload,
            )
            return [encode_frame(frame, max_frame=self.forward_mtu)], own_seq

    def _build_err_frame(self, target_key: tuple[int, int, int, int], service_id: int, status: int, payload: bytes = b"", is_reliable: bool = False) -> bytes:
        tgt_ns, tgt_orig, tgt_ep, tgt_seq = target_key
        own_seq = self._alloc_seq()

        reply_to_bytes = bytearray()
        reply_to_bytes.extend(encode_uleb(tgt_ns))
        reply_to_bytes.extend(encode_uleb(tgt_orig))
        reply_to_bytes.extend(tgt_ep.to_bytes(8, "little"))
        reply_to_bytes.extend(encode_uleb(tgt_seq))

        exts = [
            Extension(extension_id=1, critical=True, unsafe=False, value=bytes(reply_to_bytes)),
            Extension(extension_id=5, critical=True, unsafe=False, value=encode_uleb(status)),
        ]
        if service_id != self.default_service:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))
        exts.sort(key=lambda e: e.extension_id)

        options = 0x81 | (2 if is_reliable else 0)
        frame = CoreFrame(
            message_type=2,  # ERR
            options=options,
            sequence=own_seq,
            extensions=tuple(exts),
            payload=payload,
        )
        return encode_frame(frame, max_frame=self.forward_mtu)

    def _build_err_frame_reliable(self, target_key: tuple[int, int, int, int], service_id: int, status: int, payload: bytes = b"") -> tuple[bytes, int]:
        tgt_ns, tgt_orig, tgt_ep, tgt_seq = target_key
        own_seq = self._alloc_seq()

        reply_to_bytes = bytearray()
        reply_to_bytes.extend(encode_uleb(tgt_ns))
        reply_to_bytes.extend(encode_uleb(tgt_orig))
        reply_to_bytes.extend(tgt_ep.to_bytes(8, "little"))
        reply_to_bytes.extend(encode_uleb(tgt_seq))

        exts = [
            Extension(extension_id=1, critical=True, unsafe=False, value=bytes(reply_to_bytes)),
            Extension(extension_id=5, critical=True, unsafe=False, value=encode_uleb(status)),
        ]
        if service_id != self.default_service:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))
        exts.sort(key=lambda e: e.extension_id)

        frame = CoreFrame(
            message_type=2,  # ERR
            options=0x83,  # SEQ | ACK_REQ | EXT
            sequence=own_seq,
            extensions=tuple(exts),
            payload=payload,
        )
        return encode_frame(frame, max_frame=self.forward_mtu), own_seq

    def _build_req_frames(self, service_id: int, seq: int, payload: bytes, ack_req: bool = True) -> list[bytes]:
        exts = []
        if service_id != self.default_service:
            exts.append(Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(service_id)))

        base_options = 1 | (2 if ack_req else 0) | (0x80 if exts else 0)
        chunk_bytes = self.manifest.values["limits"]["chunk_bytes"]

        if len(payload) > chunk_bytes:
            # Fragmented message
            total_len = len(payload)
            num_frags = (total_len + chunk_bytes - 1) // chunk_bytes
            frames = []
            for idx in range(num_frags):
                slice_bytes = payload[idx * chunk_bytes : (idx + 1) * chunk_bytes]
                frame = CoreFrame(
                    message_type=0,  # REQ
                    options=base_options | 8,  # FRAG
                    sequence=seq,
                    fragment=Fragment(index=idx, chunk_size=chunk_bytes, total_length=total_len),
                    extensions=tuple(exts),
                    payload=slice_bytes,
                )
                frames.append(encode_frame(frame, max_frame=self.forward_mtu))
            return frames
        else:
            frame = CoreFrame(
                message_type=0,  # REQ
                options=base_options,
                sequence=seq,
                extensions=tuple(exts),
                payload=payload,
            )
            return [encode_frame(frame, max_frame=self.forward_mtu)]
