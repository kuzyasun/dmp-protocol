"""P23 negative SEC-1 interoperability checks through the real C endpoint."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))

import test_p23_c_endpoint_interop as interop  # noqa: E402
from dmp_peer.events import Disconnect, PublishSample, Receive  # noqa: E402
from dmp_peer.frame import CoreFrame, Security, encode_frame, encode_uleb, parse_frame  # noqa: E402
from dmp_peer.stream_r import encode_stream_r  # noqa: E402


_DIRECT_MANIFESTS = ("direct-nnpsk0.json", "direct-xx.json")
_MAX_CORE = 256
_MAX_ENCODED = 263


def _core_from_wire(wire: bytes, clock: interop._Clock) -> bytes:
    decoder = interop.StreamRDecoder(
        max_encoded=_MAX_ENCODED,
        max_core=_MAX_CORE,
        candidate_timeout_ms=26,
        await_sync=False,
    )
    frames = [
        event.frame
        for event in decoder.feed(wire, at_ms=clock.next())
        if event.kind == "frame"
    ]
    if len(frames) != 1 or frames[0] is None:
        raise AssertionError("peer did not emit exactly one structurally valid Stream R frame")
    return frames[0]


def _wire_with_bad_high_pn(wire: bytes, clock: interop._Clock, packet_number: int) -> bytes:
    """Retain a genuine peer ciphertext/tag while changing its authenticated PN."""
    core = _core_from_wire(wire, clock)
    frame = parse_frame(core, max_frame=_MAX_CORE)
    if frame.security is None:
        raise AssertionError("peer frame is not SEC-1 protected")
    high_pn_frame = CoreFrame(
        message_type=frame.message_type,
        options=frame.options,
        sequence=frame.sequence,
        route=frame.route,
        fragment=frame.fragment,
        payload_descriptor=frame.payload_descriptor,
        integrity=frame.integrity,
        security=Security(
            cipher=frame.security.cipher,
            receive_cid=frame.security.receive_cid,
            packet_number=packet_number,
        ),
        extensions=frame.extensions,
        payload=frame.payload,
        trailer=frame.trailer,
    )
    mutated = encode_frame(high_pn_frame, max_frame=_MAX_CORE)
    reparsed = parse_frame(mutated, max_frame=_MAX_CORE)
    if reparsed.security is None or reparsed.security.packet_number != packet_number:
        raise AssertionError("mutated frame did not retain its canonical high PN")
    return encode_stream_r(mutated, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED)


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23SecurityNegativeInterop(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = os.environ["DMP_P23_ENDPOINT_SEC_EXE"]

    def open_pair(
        self, manifest_name: str, seed: int
    ) -> tuple[interop._CProcess, interop.PeerEndpoint, interop._Clock]:
        endpoint, peer, clock = interop.TestP23CPrimaryInterop.open_pair(
            self, b"\x35" * 32, seed, manifest_name=manifest_name
        )
        self.assertTrue(endpoint.last_state.handshake_active)
        self.assertTrue(endpoint.last_state.bound)
        self.assertEqual(peer.association.status, "active")
        return endpoint, peer, clock

    def test_active_nnpsk0_and_xx_reject_plaintext_application_frames_both_ways(self) -> None:
        for index, manifest_name in enumerate(_DIRECT_MANIFESTS):
            with self.subTest(profile=manifest_name):
                endpoint, peer, clock = self.open_pair(manifest_name, 0x51 + index * 0x20)
                baseline = endpoint.last_state
                plain_request = encode_frame(
                    CoreFrame(message_type=0, options=2, sequence=0x5100, payload=b"\x01"),
                    max_frame=_MAX_CORE,
                )
                plain_wire = encode_stream_r(
                    plain_request, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED
                )

                peer_events = peer.handle(
                    Receive(link=0, bytes=plain_wire, at_ms=clock.next())
                )
                self.assertFalse(peer_events)
                self.assertEqual(peer.association.status, "active")

                rejected = endpoint.receive(plain_wire, clock.next())
                self.assertNotEqual(rejected.rx_status, 0)
                self.assertFalse(rejected.pending)
                self.assertEqual(rejected.accepts, baseline.accepts)
                self.assertEqual(rejected.telemetry, baseline.telemetry)
                self.assertEqual(rejected.request, baseline.request)
                self.assertTrue(rejected.handshake_active)
                self.assertTrue(rejected.bound)
                self.assertEqual(peer.association.status, "active")

    def test_invalid_tag_high_pn_does_not_block_genuine_lower_pn_telemetry(self) -> None:
        for index, manifest_name in enumerate(_DIRECT_MANIFESTS):
            with self.subTest(profile=manifest_name):
                endpoint, peer, clock = self.open_pair(manifest_name, 0x71 + index * 0x20)
                event = peer.handle(PublishSample(value=4321, at_ms=clock.next()))
                valid_wires, _ = interop._settle(peer, event, clock)
                self.assertEqual(len(valid_wires), 1)
                valid_core = _core_from_wire(valid_wires[0], clock)
                valid_frame = parse_frame(valid_core, max_frame=_MAX_CORE)
                self.assertIsNotNone(valid_frame.security)
                assert valid_frame.security is not None
                self.assertLess(valid_frame.security.packet_number, 1000)

                bad_wire = _wire_with_bad_high_pn(valid_wires[0], clock, 1000)
                bad_core = _core_from_wire(bad_wire, clock)
                bad_frame = parse_frame(bad_core, max_frame=_MAX_CORE)
                self.assertEqual(bad_frame.security.packet_number, 1000)
                self.assertTrue(bad_frame.payload == valid_frame.payload)
                self.assertTrue(bad_frame.trailer != b"\x00" * 16)

                baseline_telemetry = endpoint.last_state.telemetry
                rejected = endpoint.receive(bad_wire, clock.next())
                self.assertNotEqual(rejected.rx_status, 0)
                self.assertEqual(rejected.telemetry, baseline_telemetry)
                self.assertFalse(rejected.pending)
                self.assertTrue(rejected.handshake_active)
                self.assertTrue(rejected.bound)

                accepted = endpoint.receive(valid_wires[0], clock.next())
                self.assertEqual(accepted.rx_status, 0)
                self.assertEqual(accepted.telemetry, baseline_telemetry + 1)
                self.assertTrue(accepted.handshake_active)
                self.assertTrue(accepted.bound)

    def test_wrong_service_protected_rsp_does_not_complete_live_request(self) -> None:
        endpoint, peer, clock = self.open_pair("direct-nnpsk0.json", 0xA1)
        sample_events = peer.handle(PublishSample(value=6789, at_ms=clock.next()))
        interop._settle(peer, sample_events, clock)

        request = endpoint.submit_req(1, b"\x01", clock.next())
        self.assertEqual(request.status, 0)
        peer_wires: list[bytes] = []
        for wire in request.frames:
            events = peer.handle(Receive(link=0, bytes=wire, at_ms=clock.next()))
            emitted, _ = interop._settle(peer, events, clock)
            peer_wires.extend(emitted)

        correct_rsp_wires = []
        for wire in peer_wires:
            frame = parse_frame(_core_from_wire(wire, clock), max_frame=_MAX_CORE)
            if frame.message_type == 1 and frame.security is not None:
                correct_rsp_wires.append(wire)
        self.assertEqual(len(correct_rsp_wires), 1)
        self.assertTrue(peer.delivery.retained_results)
        retained = next(iter(peer.delivery.retained_results.values()))
        request_key = (
            retained.req_namespace,
            retained.req_origin,
            retained.req_epoch,
            retained.req_seq,
        )

        # Produce an authentic RSP for this live request, but bind it to service
        # 2 rather than service 1. The independent peer encrypts it with its
        # actual active association and consumes a fresh send PN.
        wrong_core_frames, _ = peer._build_rsp_frames(
            request_key, 2, b"wrong-service"
        )
        self.assertEqual(len(wrong_core_frames), 1)
        wrong_frame = parse_frame(wrong_core_frames[0], max_frame=_MAX_CORE)
        self.assertEqual(wrong_frame.message_type, 1)
        self.assertIsNotNone(wrong_frame.security)
        wrong_wire = encode_stream_r(
            wrong_core_frames[0], max_core=_MAX_CORE, max_encoded=_MAX_ENCODED
        )

        rejected = endpoint.receive(wrong_wire, clock.next())
        self.assertEqual(rejected.results, 0)
        self.assertEqual(rejected.result, b"")
        self.assertTrue(rejected.handshake_active)
        self.assertTrue(rejected.bound)

        completed = endpoint.receive(correct_rsp_wires[0], clock.next())
        self.assertEqual(completed.status, 0)
        self.assertEqual(completed.results, 1)
        self.assertTrue(completed.result)
        self.assertEqual(interop.Sample.decode_read_result(completed.result).value, 6789)
        self.assertTrue(completed.handshake_active)
        self.assertTrue(completed.bound)

    def test_lost_result_retry_uses_fresh_pn_and_replays_without_second_dispatch(self) -> None:
        endpoint, peer, clock = self.open_pair("direct-nnpsk0.json", 0xC1)
        sample_events = peer.handle(PublishSample(value=2468, at_ms=clock.next()))
        interop._settle(peer, sample_events, clock)

        read_calls = 0
        original_read = peer.sample_producer.handle_read

        def count_read() -> tuple[int, bytes]:
            nonlocal read_calls
            read_calls += 1
            return original_read()

        peer.sample_producer.handle_read = count_read
        first_request = endpoint.submit_req(1, b"\x01", clock.next())
        self.assertEqual(first_request.status, 0)
        first_req_frames = [
            parse_frame(_core_from_wire(wire, clock), max_frame=_MAX_CORE)
            for wire in first_request.frames
        ]
        self.assertEqual(len(first_req_frames), 1)
        self.assertEqual(first_req_frames[0].message_type, 0)
        self.assertIsNotNone(first_req_frames[0].sequence)
        self.assertIsNotNone(first_req_frames[0].security)
        assert first_req_frames[0].security is not None

        first_peer_events = peer.handle(
            Receive(link=0, bytes=first_request.frames[0], at_ms=clock.next())
        )
        first_result_wires, _ = interop._settle(peer, first_peer_events, clock)
        first_responses = []
        for wire in first_result_wires:
            frame = parse_frame(_core_from_wire(wire, clock), max_frame=_MAX_CORE)
            if frame.message_type == 1 and frame.security is not None:
                first_responses.append((wire, frame))
        self.assertEqual(len(first_responses), 1)
        first_response_wire, first_response = first_responses[0]
        self.assertIsNotNone(first_response.security)
        self.assertEqual(read_calls, 1)

        # Drop the first protected result and let the real C reliability timer
        # drive its logical retry. It must preserve the request identity while
        # allocating a fresh SEC-1 packet number.
        retry = endpoint.poll(clock.advance(1281))
        self.assertEqual(retry.status, 0)
        if not retry.frames:
            retry = endpoint.poll(clock.advance(64))
        self.assertTrue(retry.frames)
        retry_req_frames = [
            parse_frame(_core_from_wire(wire, clock), max_frame=_MAX_CORE)
            for wire in retry.frames
        ]
        self.assertEqual(len(retry_req_frames), 1)
        retry_request = retry_req_frames[0]
        self.assertEqual(retry_request.message_type, 0)
        self.assertEqual(retry_request.sequence, first_req_frames[0].sequence)
        self.assertIsNotNone(retry_request.security)
        assert retry_request.security is not None
        self.assertGreater(
            retry_request.security.packet_number,
            first_req_frames[0].security.packet_number,
        )

        replay_events = peer.handle(
            Receive(link=0, bytes=retry.frames[0], at_ms=clock.next())
        )
        replay_wires, _ = interop._settle(peer, replay_events, clock)
        replay_responses = []
        for wire in replay_wires:
            frame = parse_frame(_core_from_wire(wire, clock), max_frame=_MAX_CORE)
            if frame.message_type == 1 and frame.security is not None:
                replay_responses.append((wire, frame))
        self.assertEqual(len(replay_responses), 1)
        replay_wire, replay_frame = replay_responses[0]
        self.assertEqual(read_calls, 1)
        self.assertEqual(replay_frame.sequence, first_response.sequence)
        first_reply_to = next(
            ext.value for ext in first_response.extensions if ext.extension_id == 1
        )
        replay_reply_to = next(
            ext.value for ext in replay_frame.extensions if ext.extension_id == 1
        )
        self.assertEqual(
            first_reply_to,
            encode_uleb(first_req_frames[0].sequence),
        )
        self.assertEqual(replay_reply_to, first_reply_to)
        self.assertIsNotNone(replay_frame.security)
        assert replay_frame.security is not None
        self.assertGreater(
            replay_frame.security.packet_number,
            first_response.security.packet_number,
        )
        self.assertTrue(replay_wire != first_response_wire)

        completed = endpoint.receive(replay_wire, clock.next())
        self.assertEqual(completed.status, 0)
        self.assertEqual(completed.results, 1)
        self.assertEqual(interop.Sample.decode_read_result(completed.result).value, 2468)

    def test_restart_rejects_old_frame_when_cid_is_reused(self) -> None:
        old_endpoint, old_peer, old_clock = self.open_pair(
            "direct-nnpsk0.json", 0xD1
        )
        old_events = old_peer.handle(
            PublishSample(value=1357, at_ms=old_clock.next())
        )
        old_wires, _ = interop._settle(old_peer, old_events, old_clock)
        old_telemetry_wires = []
        for wire in old_wires:
            frame = parse_frame(_core_from_wire(wire, old_clock), max_frame=_MAX_CORE)
            if frame.message_type == 5 and frame.security is not None:
                old_telemetry_wires.append((wire, frame))
        self.assertEqual(len(old_telemetry_wires), 1)
        old_wire, old_frame = old_telemetry_wires[0]
        self.assertIsNotNone(old_frame.security)
        assert old_frame.security is not None
        old_c_rx_cid = old_frame.security.receive_cid

        old_peer.handle(Disconnect(link=0, at_ms=old_clock.next()))
        old_endpoint.close()
        self.assertIsNotNone(old_endpoint.process.poll())

        new_endpoint, new_peer, new_clock = self.open_pair(
            "direct-nnpsk0.json", 0xE1
        )
        new_events = new_peer.handle(
            PublishSample(value=9753, at_ms=new_clock.next())
        )
        new_wires, _ = interop._settle(new_peer, new_events, new_clock)
        new_telemetry_wires = []
        for wire in new_wires:
            frame = parse_frame(_core_from_wire(wire, new_clock), max_frame=_MAX_CORE)
            if frame.message_type == 5 and frame.security is not None:
                new_telemetry_wires.append((wire, frame))
        self.assertEqual(len(new_telemetry_wires), 1)
        new_wire, new_frame = new_telemetry_wires[0]
        self.assertIsNotNone(new_frame.security)
        assert new_frame.security is not None
        self.assertEqual(new_frame.security.receive_cid, old_c_rx_cid)

        baseline = new_endpoint.last_state
        rejected = new_endpoint.receive(old_wire, new_clock.next())
        self.assertNotEqual(rejected.rx_status, 0)
        self.assertEqual(rejected.telemetry, baseline.telemetry)
        self.assertEqual(rejected.accepts, baseline.accepts)
        self.assertFalse(rejected.pending)
        self.assertTrue(rejected.handshake_active)
        self.assertTrue(rejected.bound)

        accepted = new_endpoint.receive(new_wire, new_clock.next())
        self.assertEqual(accepted.rx_status, 0)
        self.assertEqual(accepted.telemetry, baseline.telemetry + 1)
        self.assertTrue(accepted.handshake_active)
        self.assertTrue(accepted.bound)


if __name__ == "__main__":
    unittest.main()
