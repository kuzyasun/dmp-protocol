from __future__ import annotations

import unittest
import os
import subprocess
from unittest.mock import patch
from pathlib import Path

from dmp_peer.events import Advance, ApplicationEvent, ApplicationRequest, Open, PublishSample, Receive, TxAdmit, TxSubmit, TxTerminal
from dmp_peer.endpoint import PeerEndpoint, SecurityError
from dmp_peer.frame import CoreFrame, Extension, Route, decode_uleb, encode_frame, encode_uleb, parse_frame
from dmp_peer.stream_r import StreamRDecoder
from dmp_peer.sample1 import Sample


ROOT = Path(__file__).parents[3]


def _context(namespace: int, epoch: int) -> bytes:
    return encode_uleb(namespace) + epoch.to_bytes(8, "little")


class NoneEndpointTests(unittest.TestCase):
    def setUp(self):
        self.clock = 0

    def next_time(self):
        self.clock += 1
        return self.clock

    def _pair(self, manifest_name):
        manifest = (ROOT / "profiles" / "deployments" / manifest_name).read_bytes()
        producer = PeerEndpoint(
            manifest,
            {"node_id": 10, "epoch": 10, "remote_epoch": 20, "sample_epoch": 3},
            lambda size: b"\x11" * size,
            {},
        )
        consumer = PeerEndpoint(
            manifest,
            {"node_id": 20, "epoch": 20, "remote_epoch": 10},
            lambda size: b"\x22" * size,
            {},
        )
        producer_open = producer.handle(Open(0, "strict_latest_start", self.next_time()))
        consumer_open = consumer.handle(Open(0, "strict_latest_start", self.next_time()))
        # DIRECT-1 emits Stream R synchronization delimiters; RADIO-1 is packet based.
        producer_sync = self._settle(producer, producer_open)
        consumer_sync = self._settle(consumer, consumer_open)
        for wire in producer_sync:
            consumer.handle(Receive(0, wire, self.next_time()))
        for wire in consumer_sync:
            producer.handle(Receive(0, wire, self.next_time()))
        return producer, consumer

    def _settle(self, endpoint, events):
        wires = [event.bytes for event in events if isinstance(event, TxSubmit)]
        while endpoint.active_submissions:
            for handle, submission in list(endpoint.active_submissions.items()):
                if not submission.get("admitted"):
                    admitted = endpoint.handle(TxAdmit(
                        handle, submission["generation"], True, None, self.next_time()
                    ))
                    wires.extend(event.bytes for event in admitted if isinstance(event, TxSubmit))
                terminal = endpoint.handle(TxTerminal(
                    handle, submission["generation"], "transmitted", self.next_time()
                ))
                wires.extend(event.bytes for event in terminal if isinstance(event, TxSubmit))
        return wires

    def _send(self, source, destination, events):
        received = []
        for wire in self._settle(source, events):
            received.extend(destination.handle(Receive(0, wire, self.next_time())))
        return received

    def _request(self, consumer, producer, payload, exchange_id):
        req = consumer.handle(ApplicationRequest(
            service_id=1, payload=payload, exchange_id=exchange_id, at_ms=self.next_time()
        ))
        producer_events = self._send(consumer, producer, req)
        consumer_events = self._send(producer, consumer, producer_events)
        self._send(consumer, producer, consumer_events)
        return [event for event in consumer_events if isinstance(event, ApplicationEvent)]

    def endpoint(self, entropy=lambda size: b"\x2a" * size):
        return PeerEndpoint(
            (ROOT / "profiles" / "deployments" / "direct-none.json").read_bytes(),
            {"node_id": 10, "epoch": 7, "remote_epoch": 9},
            entropy,
            {},
        )

    def _shared_c_driver(self):
        executable = os.environ.get("DMP_P23_SAMPLE1_NONE_DRIVER")
        if not executable:
            self.skipTest("shared production C SAMPLE-1 driver is not configured")
        process = subprocess.Popen(
            [executable, "s3-driver"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        initial = []
        frames = []
        while True:
            line = process.stdout.readline()
            if not line:
                self.fail("shared C producer exited during initialization")
            if line.strip() == ".":
                break
            line = line.strip()
            if line.startswith("F "):
                _, slot, encoded = line.split(" ", 2)
                frames.append((int(slot), bytes.fromhex(encoded)))
            else:
                initial.append(line)
        self.assertEqual(initial, ["READY"])
        return process, frames

    def _driver_call(self, process, command):
        self.assertIsNotNone(process.stdin)
        self.assertIsNotNone(process.stdout)
        process.stdin.write(command + "\n")
        process.stdin.flush()
        frames = []
        state = None
        while True:
            line = process.stdout.readline()
            if not line:
                diagnostics = process.stderr.read() if process.stderr else ""
                self.fail(f"shared C producer exited in {command!r}: {diagnostics}")
            line = line.rstrip("\r\n")
            if line == ".":
                return frames, state
            if line.startswith("F "):
                _, slot, encoded = line.split(" ", 2)
                frames.append((int(slot), bytes.fromhex(encoded)))
            elif line.startswith("S "):
                state = int(line[2:])
            elif line.startswith("ERR"):
                self.fail(f"shared C producer rejected {command!r}: {line}")
            else:
                self.fail(f"unexpected shared C producer output: {line!r}")

    def _shared_consumer(self, manifest, node_id, entropy_byte, now):
        peer = PeerEndpoint(
            manifest,
            {"node_id": node_id, "epoch": 20, "remote_epoch": 11},
            lambda size: bytes((entropy_byte,)) * size,
            {},
        )
        events = peer.handle(Open(0, "strict_latest_start", now))
        return peer, events

    def _reply_identity(self, wire):
        parsed = parse_frame(wire)
        extension = next(item for item in parsed.extensions
                         if item.extension_id == 1)
        namespace, offset = decode_uleb(extension.value)
        origin, offset = decode_uleb(extension.value, offset)
        epoch = int.from_bytes(extension.value[offset:offset + 8], "little")
        offset += 8
        sequence, offset = decode_uleb(extension.value, offset)
        self.assertEqual(offset, len(extension.value))
        return namespace, origin, epoch, sequence

    def test_none_output_has_core_crc_and_bad_crc_is_rejected(self):
        endpoint = self.endpoint()
        frame = CoreFrame(message_type=4, sequence=3)
        encoded = endpoint._encode_endpoint_frame(frame)
        self.assertEqual(1, parse_frame(encoded).integrity)
        damaged = encoded[:-1] + bytes([encoded[-1] ^ 1])
        with self.assertRaises(ValueError):
            parse_frame(damaged)

    def test_incoming_epoch_never_rebinds_context(self):
        endpoint = self.endpoint()
        frame = CoreFrame(
            message_type=4,
            sequence=5,
            integrity=1,
            extensions=(
                Extension(2, True, True, _context(1, 10)),
                Extension(3, True, True, encode_uleb(20)),
            ),
        )
        endpoint._process_core_bytes(encode_frame(frame), [])
        self.assertEqual(9, endpoint.remote_epoch)
        endpoint.replace_none_peer_context(20, 10)
        self.assertEqual(10, endpoint.remote_epoch)

    def test_direct_none_frames_require_context_and_origin(self):
        endpoint = self.endpoint()
        cases = (
            ("missing context", (Extension(3, True, True, encode_uleb(20)),)),
            ("missing origin", (Extension(2, True, True, _context(1, 9)),)),
        )
        for label, extensions in cases:
            with self.subTest(label=label), patch.object(endpoint, "_dispatch_core_frame") as dispatch:
                frame = CoreFrame(message_type=4, options=0x81, sequence=1, extensions=extensions)
                endpoint._process_core_bytes(endpoint._encode_endpoint_frame(frame), [])
                dispatch.assert_not_called()

    def test_routed_none_frames_require_context_and_fixed_route_mapping(self):
        manifest = (ROOT / "profiles" / "deployments" / "radio-none.json").read_bytes()
        endpoint = PeerEndpoint(
            manifest,
            {"node_id": 10, "epoch": 10, "remote_epoch": 20},
            lambda size: b"\x11" * size,
            {},
        )
        context = Extension(2, True, True, _context(1, 20))
        cases = (
            ("missing context", Route(ttl=1, mode=1, source_id=20, destination_id=10), ()),
            ("wrong source", Route(ttl=1, mode=1, source_id=30, destination_id=10), (context,)),
            ("wrong destination", Route(ttl=1, mode=1, source_id=20, destination_id=30), (context,)),
        )
        for label, route, extensions in cases:
            with self.subTest(label=label), patch.object(endpoint, "_dispatch_core_frame") as dispatch:
                frame = CoreFrame(message_type=4, options=0x85, sequence=1, route=route, extensions=extensions)
                endpoint._process_core_bytes(endpoint._encode_endpoint_frame(frame), [])
                dispatch.assert_not_called()

    def test_sample1_none_direct_status_read_telemetry_and_no_rollback(self):
        producer, consumer = self._pair("direct-none.json")

        # STATUS works before synchronization and reports no current sample.
        status = self._request(consumer, producer, b"\x02", 101)
        self.assertEqual([(event.kind, event.status, event.payload) for event in status],
                         [("request_result", 0, b"\x02\x00")])

        # Unsynchronized telemetry is ignored. The designated READ supplies the
        # current sample and establishes the SAMPLE-1 consumer epoch.
        self._send(producer, consumer, producer.handle(PublishSample(100, self.next_time())))
        ready = self._request(consumer, producer, b"\x02", 104)
        self.assertEqual([(event.kind, event.status, event.payload) for event in ready],
                         [("request_result", 0, b"\x02\x01")])
        self.assertFalse(consumer.sample_consumer.is_live)
        read = self._request(consumer, producer, b"\x01", 102)
        self.assertEqual(len(read), 1)
        self.assertEqual(read[0].kind, "request_result")
        self.assertEqual(Sample.decode_read_result(read[0].payload), Sample(3, 1, 100))
        self.assertTrue(consumer.sample_consumer.is_live)

        # A later TELEM advances the cache. A correctly correlated but older
        # READ snapshot cannot roll the live value back.
        self._send(producer, consumer, producer.handle(PublishSample(200, self.next_time())))
        self.assertEqual(consumer.sample_consumer.cached_sample, Sample(3, 2, 200))
        producer.sample_producer._current_sample = Sample(3, 1, 100)
        stale_result = self._request(consumer, producer, b"\x01", 103)
        self.assertTrue(any(event.kind == "request_result" for event in stale_result))
        self.assertEqual(consumer.sample_consumer.cached_sample, Sample(3, 2, 200))

        # Application replacement is explicit; a frame carrying the retired
        # peer epoch is rejected and cannot change the cache.
        stale = next(iter(self._settle(producer, producer.handle(PublishSample(300, self.next_time())))))
        replacement = PeerEndpoint(
            (ROOT / "profiles" / "deployments" / "direct-none.json").read_bytes(),
            {"node_id": 20, "epoch": 21, "remote_epoch": 10},
            lambda size: b"\x33" * size,
            {},
        )
        self._settle(replacement, replacement.handle(Open(0, "strict_latest_start", self.next_time())))
        replacement.handle(Receive(0, b"\x00", self.next_time()))
        replacement.replace_none_peer_context(10, 11)
        replacement.handle(Receive(0, stale, self.next_time()))
        self.assertEqual(replacement.remote_epoch, 11)
        self.assertIsNone(replacement.sample_consumer.cached_sample)

    def test_sample1_none_direct_no_sample_is_terminal_status_64(self):
        producer, consumer = self._pair("direct-none.json")
        result = self._request(consumer, producer, b"\x01", 201)
        self.assertEqual([(event.kind, event.status, event.payload) for event in result],
                         [("request_result", 64, b"")])
        self.assertFalse(consumer.sample_consumer.is_live)
        self.assertEqual(consumer.sample_consumer.state, "unsynchronized")

    def test_sample1_none_radio_status_read_telemetry_and_no_rollback(self):
        producer, consumer = self._pair("radio-none.json")
        status = self._request(consumer, producer, b"\x02", 301)
        self.assertEqual([(event.kind, event.status, event.payload) for event in status],
                         [("request_result", 0, b"\x02\x00")])
        self._send(producer, consumer, producer.handle(PublishSample(100, self.next_time())))
        ready = self._request(consumer, producer, b"\x02", 304)
        self.assertEqual([(event.kind, event.status, event.payload) for event in ready],
                         [("request_result", 0, b"\x02\x01")])
        self.assertFalse(consumer.sample_consumer.is_live)
        read = self._request(consumer, producer, b"\x01", 302)
        self.assertEqual(len(read), 1)
        self.assertEqual(Sample.decode_read_result(read[0].payload), Sample(3, 1, 100))
        self.assertTrue(consumer.sample_consumer.is_live)

        self._send(producer, consumer, producer.handle(PublishSample(200, self.next_time())))
        self.assertEqual(consumer.sample_consumer.cached_sample, Sample(3, 2, 200))
        producer.sample_producer._current_sample = Sample(3, 1, 100)
        stale_result = self._request(consumer, producer, b"\x01", 303)
        self.assertTrue(any(event.kind == "request_result" for event in stale_result))
        self.assertEqual(consumer.sample_consumer.cached_sample, Sample(3, 2, 200))

        stale = next(iter(self._settle(producer, producer.handle(PublishSample(300, self.next_time())))))
        replacement = PeerEndpoint(
            (ROOT / "profiles" / "deployments" / "radio-none.json").read_bytes(),
            {"node_id": 20, "epoch": 21, "remote_epoch": 10},
            lambda size: b"\x33" * size,
            {},
        )
        replacement.handle(Open(0, "strict_latest_start", self.next_time()))
        replacement.replace_none_peer_context(10, 11)
        replacement.handle(Receive(0, stale, self.next_time()))
        self.assertEqual(replacement.remote_epoch, 11)
        self.assertIsNone(replacement.sample_consumer.cached_sample)

    def test_sample1_none_radio_no_sample_is_terminal_status_64(self):
        producer, consumer = self._pair("radio-none.json")
        result = self._request(consumer, producer, b"\x01", 401)
        self.assertEqual([(event.kind, event.status, event.payload) for event in result],
                         [("request_result", 64, b"")])
        self.assertFalse(consumer.sample_consumer.is_live)
        self.assertEqual(consumer.sample_consumer.state, "unsynchronized")

    def test_sample1_none_independent_consumers_share_production_history(self):
        # Two independent P21 consumers exchange real Stream R frames with one
        # shared production C endpoint and result/history table.
        manifest = (ROOT / "profiles" / "deployments"
                    / "test-direct-none-five-peers.json").read_bytes()
        driver, initial_sync = self._shared_c_driver()
        peers = {}
        slots = {20: 0, 30: 1}
        peer_by_slot = {}

        def deliver_to_consumer(peer, wire):
            return peer.handle(Receive(0, wire, self.next_time()))

        def route_consumer_events(peer, slot, events):
            returned = []
            for wire in self._settle(peer, events):
                frames, _ = self._driver_call(driver, f"RX {slot} {wire.hex()}")
                for route, frame in frames:
                    recipient = peer_by_slot.get(route)
                    if recipient is not None:
                        returned.extend(deliver_to_consumer(recipient, frame))
            return returned

        try:
            opened = []
            for node_id, entropy_byte in ((20, 0x31), (30, 0x32)):
                peer, open_events = self._shared_consumer(
                    manifest, node_id, entropy_byte, self.next_time()
                )
                peers[node_id] = peer
                peer_by_slot[slots[node_id]] = peer
                opened.append((peer, slots[node_id], open_events))
            for slot, wire in initial_sync:
                recipient = peer_by_slot.get(slot)
                if recipient is not None:
                    recipient.handle(Receive(0, wire, self.next_time()))
            # Complete Stream R synchronization against the common C endpoint
            # before any application traffic. The production stream endpoint
            # may emit delimiters for multiple configured peers at once.
            sync_frames = []
            for peer, slot, events in opened:
                for wire in self._settle(peer, events):
                    frames, _ = self._driver_call(
                        driver, f"RX {slot} {wire.hex()}"
                    )
                    sync_frames.extend(frames)
            for route, wire in sync_frames:
                recipient = peer_by_slot.get(route)
                if recipient is not None:
                    recipient.handle(Receive(0, wire, self.next_time()))
            self.assertTrue(all(peer.stream_r_decoder._synced
                                for peer in peers.values()))

            # Each SAMPLE-1 consumer explicitly synchronizes its epoch with a
            # STATUS result before it accepts subsequent telemetry.
            for node_id in (20, 30):
                peer = peers[node_id]
                status_events = route_consumer_events(
                    peer, slots[node_id], peer.handle(ApplicationRequest(
                        service_id=1, payload=b"\x02", exchange_id=700 + node_id,
                        at_ms=self.next_time(),
                    ))
                )
                self.assertTrue(any(
                    isinstance(event, ApplicationEvent) and
                    event.kind == "request_result" and
                    event.payload in (b"\x02\x00", b"\x02\x01")
                    for event in status_events
                ), repr(status_events))
                status_acks = [event for event in status_events
                               if isinstance(event, TxSubmit)]
                if status_acks:
                    route_consumer_events(peer, slots[node_id], status_acks)

            publish_frames, _ = self._driver_call(driver, "PUB 110")
            self.assertGreaterEqual(len(publish_frames), 2,
                                    f"C producer telemetry frames: {publish_frames!r}")
            publish_types = []
            node_by_slot = {slot: node_id for node_id, slot in slots.items()}
            for slot, wire in publish_frames:
                core = next(
                    event.frame for event in StreamRDecoder(
                        max_encoded=263, max_core=256,
                        candidate_timeout_ms=12000, await_sync=False,
                    ).feed(wire, at_ms=self.next_time())
                    if event.kind == "frame"
                )
                parsed_core = parse_frame(core)
                context_ext = next(e for e in parsed_core.extensions
                                   if e.extension_id == 2)
                ns, offset = decode_uleb(context_ext.value)
                origin_ext = next(e for e in parsed_core.extensions
                                  if e.extension_id == 3)
                origin = decode_uleb(origin_ext.value)[0]
                policy_match = peers[20 if slot == 0 else 30]._none_inbound_identity_matches(parsed_core)
                publish_types.append((slot, parsed_core.message_type, ns,
                                      int.from_bytes(context_ext.value[offset:], "little"),
                                      origin, parsed_core.sequence,
                                      parsed_core.integrity, parsed_core.payload.hex(),
                                      policy_match))
                recipient_id = node_by_slot.get(slot)
                if recipient_id is not None:
                    peers[recipient_id].handle(Receive(0, wire, self.next_time()))
            targeted_publications = {
                slot: metadata for slot, *metadata in publish_types
                if slot in slots.values()
            }
            self.assertEqual(set(targeted_publications), {0, 1})
            for metadata in targeted_publications.values():
                self.assertEqual(metadata[:4], [5, 1, 11, 10])
                self.assertEqual(metadata[5], 1)
                self.assertTrue(metadata[7])
            consumer_a = peers[20]
            request_events_a = consumer_a.handle(ApplicationRequest(
                service_id=1, payload=b"\x01", exchange_id=707,
                at_ms=self.next_time(),
            ))
            request_wires_a = self._settle(consumer_a, request_events_a)
            self.assertEqual(len(request_wires_a), 1)
            request_core_a = next(
                event.frame for event in StreamRDecoder(
                    max_encoded=263, max_core=256, candidate_timeout_ms=12000,
                    await_sync=False,
                ).feed(request_wires_a[0], at_ms=self.next_time())
                if event.kind == "frame"
            )
            request_seq_a = parse_frame(request_core_a).sequence
            frames_a, _ = self._driver_call(
                driver, f"RX 0 {request_wires_a[0].hex()}"
            )
            result_a_wire = None
            result_a_events = []
            for slot, wire in frames_a:
                self.assertEqual(slot, 0)
                core = next(
                    event.frame for event in StreamRDecoder(
                        max_encoded=263, max_core=256,
                        candidate_timeout_ms=12000, await_sync=False,
                    ).feed(wire, at_ms=self.next_time())
                    if event.kind == "frame"
                )
                if parse_frame(core).message_type == 1:
                    result_a_wire = wire
                result_a_events.extend(consumer_a.handle(
                    Receive(0, wire, self.next_time())
                ))
            self.assertIsNotNone(result_a_wire)
            delivered_a = [event for event in result_a_events
                           if isinstance(event, ApplicationEvent)]
            self.assertEqual([(event.kind, event.exchange_id, event.status,
                              event.payload) for event in delivered_a],
                             [("request_result", 707, 0,
                               Sample(3, 1, 110).encode_read_result())])
            self.assertEqual(self._reply_identity(
                next(event.frame for event in StreamRDecoder(
                    max_encoded=263, max_core=256, candidate_timeout_ms=12000,
                    await_sync=False,
                ).feed(result_a_wire, at_ms=self.next_time())
                     if event.kind == "frame")
            ), (1, 20, 20, request_seq_a))
            # Leave the generated result ACK active but unsent: C still retains
            # this accepted A result while other consumers proceed.
            self.assertTrue(any(isinstance(event, TxSubmit)
                                for event in result_a_events))

            # B also synchronizes by a real READ and ACKs it before the next
            # publication, leaving only A's result retained in shared C state.
            consumer_b = peers[30]
            initial_b_events = route_consumer_events(
                consumer_b, slots[30], consumer_b.handle(ApplicationRequest(
                    service_id=1, payload=b"\x01", exchange_id=706,
                    at_ms=self.next_time(),
                ))
            )
            self.assertTrue(any(
                isinstance(event, ApplicationEvent) and
                event.kind == "request_result" and event.payload ==
                Sample(3, 1, 110).encode_read_result()
                for event in initial_b_events
            ))
            initial_b_acks = [event for event in initial_b_events
                              if isinstance(event, TxSubmit)]
            for wire in self._settle(consumer_b, initial_b_acks):
                self._driver_call(driver, f"RX 1 {wire.hex()}")
            self.assertEqual(consumer_b.sample_consumer.cached_sample,
                             Sample(3, 1, 110))
            state_frames, retained_before = self._driver_call(driver, "STATE")
            self.assertEqual(state_frames, [])
            self.assertGreaterEqual(retained_before, 1)

            # A new publication and B's READ happen while A's unacknowledged
            # result remains live in the same C endpoint history table.
            publish_frames, _ = self._driver_call(driver, "PUB 220")
            for slot, wire in publish_frames:
                recipient_id = node_by_slot.get(slot)
                if recipient_id is not None:
                    peers[recipient_id].handle(Receive(0, wire, self.next_time()))
            self.assertEqual(consumer_a.sample_consumer.cached_sample,
                             Sample(3, 2, 220))
            self.assertEqual(peers[30].sample_consumer.cached_sample,
                             Sample(3, 2, 220))
            request_events_b = consumer_b.handle(ApplicationRequest(
                service_id=1, payload=b"\x01", exchange_id=708,
                at_ms=self.next_time(),
            ))
            request_wires_b = self._settle(consumer_b, request_events_b)
            self.assertEqual(len(request_wires_b), 1)
            request_core_b = next(
                event.frame for event in StreamRDecoder(
                    max_encoded=263, max_core=256, candidate_timeout_ms=12000,
                    await_sync=False,
                ).feed(request_wires_b[0], at_ms=self.next_time())
                if event.kind == "frame"
            )
            request_seq_b = parse_frame(request_core_b).sequence
            frames_b, _ = self._driver_call(
                driver, f"RX 1 {request_wires_b[0].hex()}"
            )
            result_b_wire = next(
                wire for slot, wire in frames_b
                if slot == 1 and any(
                    event.kind == "frame" and parse_frame(event.frame).message_type == 1
                    for event in StreamRDecoder(
                        max_encoded=263, max_core=256,
                        candidate_timeout_ms=12000, await_sync=False,
                    ).feed(wire, at_ms=self.next_time())
                )
            )
            # The older A result has a valid producer context but a different
            # full REPLY_TO. It must not complete B's active exchange.
            wrong_events = consumer_b.handle(Receive(
                0, result_a_wire, self.next_time()
            ))
            self.assertFalse(any(isinstance(event, ApplicationEvent) and
                                 event.kind == "request_result"
                                 for event in wrong_events))
            self.assertTrue(consumer_b.sample_consumer.is_live)

            # Replaying A's duplicate while B remains active cannot roll A's
            # newer telemetry state back to its older READ snapshot.
            duplicate_events = consumer_a.handle(Receive(
                0, result_a_wire, self.next_time()
            ))
            self.assertFalse(any(isinstance(event, ApplicationEvent) and
                                 event.kind == "request_result"
                                 for event in duplicate_events))
            self.assertEqual(consumer_a.sample_consumer.cached_sample,
                             Sample(3, 2, 220))
            state_frames, retained_during_b = self._driver_call(driver, "STATE")
            self.assertEqual(state_frames, [])
            self.assertGreaterEqual(retained_during_b, 1)

            result_b_events = consumer_b.handle(Receive(
                0, result_b_wire, self.next_time()
            ))
            delivered_b = [event for event in result_b_events
                           if isinstance(event, ApplicationEvent)]
            self.assertEqual([(event.kind, event.exchange_id, event.status,
                              event.payload) for event in delivered_b],
                             [("request_result", 708, 0,
                               Sample(3, 2, 220).encode_read_result())])
            self.assertEqual(self._reply_identity(
                next(event.frame for event in StreamRDecoder(
                    max_encoded=263, max_core=256, candidate_timeout_ms=12000,
                    await_sync=False,
                ).feed(result_b_wire, at_ms=self.next_time())
                     if event.kind == "frame")
            ), (1, 30, 20, request_seq_b))
            self.assertEqual(consumer_b.sample_consumer.cached_sample,
                             Sample(3, 2, 220))
            ack_events = [event for event in result_b_events
                          if isinstance(event, TxSubmit)]
            ack_wires = self._settle(consumer_b, ack_events)
            for wire in ack_wires:
                self._driver_call(driver, f"RX 1 {wire.hex()}")
            state_frames, retained_after_b_ack = self._driver_call(driver, "STATE")
            self.assertEqual(state_frames, [])
            self.assertEqual(retained_after_b_ack, 1)
        finally:
            if driver.stdin:
                driver.stdin.close()
            try:
                driver.wait(timeout=3)
            except subprocess.TimeoutExpired:
                driver.kill()
                driver.wait(timeout=3)
            if driver.stderr:
                diagnostics = driver.stderr.read()
                if driver.returncode not in (0, None):
                    self.fail(f"shared C producer failed: {diagnostics}")
                driver.stderr.close()
            if driver.stdout:
                driver.stdout.close()

    def test_none_initialization_requires_fresh_nonzero_random_epoch(self):
        raw = (ROOT / "profiles" / "deployments" / "direct-none.json").read_bytes()
        credentials = {"node_id": 10, "remote_epoch": 9}
        with self.assertRaisesRegex(ValueError, "exactly 8 bytes"):
            PeerEndpoint(raw, credentials, lambda _size: b"bad", {})
        with self.assertRaisesRegex(ValueError, "nonzero uint64"):
            PeerEndpoint(raw, credentials, lambda size: bytes(size), {})
        peer = PeerEndpoint(raw, credentials, lambda size: b"\x2a" * size, {})
        self.assertEqual(int.from_bytes(b"\x2a" * 8, "little"), peer.local_epoch)

    def test_context_replacement_waits_for_retained_work(self):
        endpoint = self.endpoint()
        endpoint.delivery.accepted_messages[(1, 20, 9, 1)] = object()
        with self.assertRaisesRegex(SecurityError, "accepted work"):
            endpoint.replace_none_peer_context(20, 10)
        self.assertEqual(9, endpoint.remote_epoch)

    def test_context_replacement_waits_for_queued_and_borrowed_transmissions(self):
        endpoint = PeerEndpoint(
            (ROOT / "profiles" / "deployments" / "radio-none.json").read_bytes(),
            {"node_id": 10, "epoch": 10, "remote_epoch": 20},
            lambda size: b"\x11" * size,
            {},
        )
        endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=1))
        endpoint.adapter_slots = 1
        output = []
        wire = endpoint._encode_endpoint_frame(CoreFrame(message_type=4, sequence=1))
        endpoint._enqueue_tx(wire, not_after_ms=None, service_id=2, out=output)
        first = next(event for event in output if isinstance(event, TxSubmit))
        queued_wire = endpoint._encode_endpoint_frame(CoreFrame(message_type=4, sequence=2))
        endpoint._enqueue_tx(queued_wire, not_after_ms=None, service_id=2, out=[])
        self.assertEqual(1, len(endpoint.tx_queue))
        with self.assertRaisesRegex(SecurityError, "transmissions"):
            endpoint.replace_none_peer_context(20, 10)

        endpoint.handle(TxAdmit(
            handle=first.handle, generation=first.generation,
            accepted=True, reason=None, at_ms=2,
        ))
        endpoint.handle(TxTerminal(
            handle=first.handle, generation=first.generation,
            outcome="transmitted", at_ms=3,
        ))
        second = next(iter(endpoint.active_submissions.values()))
        with self.assertRaisesRegex(SecurityError, "transmissions"):
            endpoint.replace_none_peer_context(20, 10)

        endpoint.handle(TxAdmit(
            handle=second["handle"], generation=second["generation"],
            accepted=False, reason="disconnected", at_ms=4,
        ))
        self.assertFalse(endpoint.active_submissions)
        self.assertFalse(endpoint.tx_queue)
        old_generation = endpoint.generation
        endpoint.replace_none_peer_context(20, 10)
        self.assertEqual(10, endpoint.remote_epoch)
        self.assertEqual((old_generation + 1) & 0xFFFFFFFF, endpoint.generation)

    @staticmethod
    def settle(endpoint, events, at_ms):
        wires = [event.bytes for event in events if isinstance(event, TxSubmit)]
        while endpoint.active_submissions:
            for handle, submission in list(endpoint.active_submissions.items()):
                if not submission.get("admitted"):
                    endpoint.handle(TxAdmit(
                        handle=handle,
                        generation=submission["generation"],
                        accepted=True,
                        reason=None,
                        at_ms=at_ms,
                    ))
                terminal = endpoint.handle(TxTerminal(
                    handle=handle,
                    generation=submission["generation"],
                    outcome="transmitted",
                    at_ms=at_ms,
                ))
                wires.extend(event.bytes for event in terminal if isinstance(event, TxSubmit))
        return wires

    def test_radio_none_selective_feedback_repairs_only_missing_fragments(self):
        manifest = (ROOT / "profiles" / "deployments" / "radio-none.json").read_bytes()
        initiator = PeerEndpoint(
            manifest,
            {"node_id": 20, "epoch": 20, "remote_epoch": 10},
            lambda size: b"\x21" * size,
            {},
        )
        responder = PeerEndpoint(
            manifest,
            {"node_id": 10, "epoch": 10, "remote_epoch": 20},
            lambda size: b"\x11" * size,
            {},
        )
        initiator.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        responder.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        request = self.settle(
            initiator,
            initiator.handle(ApplicationRequest(
                service_id=2, payload=bytes(range(256)), ack_req=True, at_ms=230
            )),
            231,
        )
        self.assertEqual(len(request), 8)
        self.assertTrue(all(parse_frame(wire).integrity == 1 for wire in request))
        partial = [wire for wire in request if parse_frame(wire).fragment.index not in (2, 6)]
        for offset, wire in enumerate(partial):
            responder.handle(Receive(link=0, bytes=wire, at_ms=300 + offset))
        key = (1, 20, 20, parse_frame(request[0]).sequence)
        assembly = responder.reassembly.active[key]
        feedback_at = assembly.selective_feedback_due_ms
        self.assertIsNotNone(feedback_at)
        status = self.settle(
            responder,
            responder.handle(Advance(now_ms=feedback_at)),
            feedback_at + 1,
        )
        self.assertEqual(len(status), 1)
        status_frame = parse_frame(status[0])
        self.assertEqual(status_frame.message_type, 8)
        self.assertIsNone(status_frame.security)
        self.assertEqual(1, status_frame.integrity)
        self.assertEqual(b"\x44\x00\x00\x00", status_frame.payload)
        transfer = next(iter(initiator.delivery.active_outgoing.values()))
        initiator.handle(Receive(link=0, bytes=status[0], at_ms=feedback_at + 2))
        repair_at = transfer.selective_state.started_at_ms + 4352
        repairs = self.settle(
            initiator,
            initiator.handle(Advance(now_ms=repair_at)),
            repair_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in repairs], [2, 6])
        self.assertTrue(all(parse_frame(wire).integrity == 1 for wire in repairs))
        self.assertTrue(all(parse_frame(wire).security is None for wire in repairs))


if __name__ == "__main__":
    unittest.main()
