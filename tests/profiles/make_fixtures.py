"""Regenerate the small, independently interpreted P02 manifest fixtures."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
COMPONENTS = (
    "provider_retained", "provider_scratch", "association", "bootstrap",
    "sender", "assembly", "result", "history", "correlation", "control",
    "application_queue", "adapter", "stacks", "relay_cache", "freshness_tokens",
    "assembly_tombstone",
)


def _services(recovery, fresh_service_2):
    return [
        {
            "id": 1,
            "reply_service": 1,
            "service_encoding": "omitted",
            "schema": "DMP-reference/SAMPLE-1/2",
            "payload_desc": "omitted",
            "recovery": recovery,
            "security": "SEC-1",
            "freshness": False,
            "idempotent": True,
            "request_bytes": 1,
            "result_bytes": 17,
            "processing_ms": 10,
            "acl": [
                {"node": 10, "actions": ["produce", "result"]},
                {"node": 20, "actions": ["read", "status"]},
            ],
        },
        {
            "id": 2,
            "reply_service": 2,
            "service_encoding": "explicit",
            "schema": "DMP-test/OPAQUE-1/1",
            "payload_desc": "omitted",
            "recovery": recovery,
            "security": "SEC-1",
            "freshness": fresh_service_2,
            "idempotent": True,
            "request_bytes": 64,
            "result_bytes": 64,
            "processing_ms": 10,
            "acl": [
                {"node": 10, "actions": ["data", "result"]},
                {"node": 20, "actions": ["data", "result"]},
            ],
        },
    ]


def _resources(role, encoded_frame_bytes, freshness_enabled, control_slots,
               relay_cache_count=1):
    if role == "endpoint":
        grant_count = 2 if freshness_enabled else 0
        result_count = 4 + grant_count
        charges = [
            ("provider_retained", 3, 64),
            ("provider_scratch", 1, 128),
            ("association", 3, 128),
            ("bootstrap", 1, 120),
            ("sender", 4, 64),
            ("assembly", 1, 576),
            ("assembly_tombstone", 16, 48),
            ("result", result_count, 64),
            ("history", 2 * result_count, 32),
            ("correlation", result_count, 32),
            ("control", control_slots, encoded_frame_bytes),
            ("application_queue", 2, 64),
            ("adapter", control_slots + 1, encoded_frame_bytes),
            ("stacks", 1, 512),
            ("relay_cache", 1, 1),
            ("freshness_tokens", 8 if freshness_enabled else 1,
             16 if freshness_enabled else 1),
        ]
    else:
        charges = [(component, 1, 1) for component in COMPONENTS]
        charges[9] = ("control", 1, encoded_frame_bytes)
        charges[11] = ("adapter", 1, encoded_frame_bytes)
        charges[13] = ("relay_cache", relay_cache_count, 32)
    return {
        "role": role,
        "target": "host." + role,
        "flash_limit_bytes": 1000000,
        "flash_reserved_bytes": 500000,
        "regions": [{"id": "RAM", "limit_bytes": 10000}],
        "charges": [
            {"component": component, "region": "RAM", "count": count,
             "bytes_each": size}
            for component, count, size in charges
        ],
    }


def manifest(kind):
    direct = kind == "direct"
    retry_all = kind in ("direct", "test-radio-retry-all")
    recovery = "retry-all" if retry_all else "selective-32"
    if direct:
        profile = {"owner": "DMP-reference", "id": "DIRECT-1", "revision": 4}
        binding = {
            "id": "DMP-test/SIM-STREAM-R", "revision": 1, "kind": "stream-r",
            "segmentation": "none", "route_change": "fail-active-transfer",
            "topology": "point-to-point", "context": "association", "ttl": 0,
            "forward_mtu": 256, "return_mtu": 256, "encoded_mtu": 263,
            "frame_tx_ms": 1, "tx_ownership": "borrow",
            "completion": "exactly-once-generation-tagged",
            "synchronous_completion": True,
            "cancellation": "terminal-event-releases-buffer",
            "disconnect": "settle-all-submissions-fail-transfers",
            "access": "reserved-half-duplex-slots", "return_opportunity": True,
            "burst_gate": "serialize-pair-services-directions-and-bootstrap",
            "return_slot_period_ms": 64, "return_slot_width_ms": 42,
            "bootstrap_integrity": "CRC32C",
        }
        relays = []
    else:
        is_test = kind == "test-radio-retry-all"
        profile = {
            "owner": "DMP-test" if is_test else "DMP-reference",
            "id": "TEST-RADIO-RETRY-ALL" if is_test else "RADIO-1",
            "revision": 1 if is_test else 4,
        }
        binding = {
            "id": "DMP-test/SIM-PACKET", "revision": 1, "kind": "packet",
            "segmentation": "none", "route_change": "fail-active-transfer",
            "topology": "static-unicast", "context": "origin-explicit", "ttl": 2,
            "forward_mtu": 256, "return_mtu": 256, "encoded_mtu": 256,
            "frame_tx_ms": 1, "tx_ownership": "borrow",
            "completion": "exactly-once-generation-tagged",
            "synchronous_completion": True,
            "cancellation": "terminal-event-releases-buffer",
            "disconnect": "settle-all-submissions-fail-transfers",
            "access": "reserved-half-duplex-slots", "return_opportunity": True,
            "burst_gate": "serialize-pair-services-directions-and-bootstrap",
            "return_slot_period_ms": 64, "return_slot_width_ms": 42,
            "bootstrap_integrity": "CRC32C",
        }
        relays = [
            {
                "node": 30, "public_pn_filter": "reject-ge-2pow24",
                "cooldown_anchor": "last-forward-completion", "cooldown_ms": 50,
                "expiry_ms": 20000, "max_forwards_per_key": 8, "frame_tx_ms": 1,
                "per_origin_airtime_ms": 10000, "global_airtime_ms": 20000,
                "lower_duplicates": 1, "duplicate_tail_ms": 3,
                "forward_arrival_min_ms": 1, "forward_arrival_max_ms": 2,
                "return_arrival_min_ms": 7, "return_arrival_max_ms": 8,
            },
            {
                "node": 40, "public_pn_filter": "reject-ge-2pow24",
                "cooldown_anchor": "last-forward-completion", "cooldown_ms": 50,
                "expiry_ms": 20000, "max_forwards_per_key": 8, "frame_tx_ms": 1,
                "per_origin_airtime_ms": 10000, "global_airtime_ms": 20000,
                "lower_duplicates": 1, "duplicate_tail_ms": 3,
                "forward_arrival_min_ms": 7, "forward_arrival_max_ms": 8,
                "return_arrival_min_ms": 1, "return_arrival_max_ms": 2,
            },
        ]

    selective = not retry_all
    freshness_enabled = not direct
    encoded_frame_bytes = 263 if direct else 256
    relay_cache_count = 4 * (4 + 2) + (2 if selective else 0) + 2 + 14 * 2
    resources = [_resources("endpoint", encoded_frame_bytes, freshness_enabled,
                            4 if freshness_enabled else 2)]
    if relays:
        resources.append(_resources("relay", encoded_frame_bytes, freshness_enabled,
                                    1, relay_cache_count))

    return {
        "contract": "DMP-test-manifest/2",
        "revisions": {"core": 10, "security": 5, "bootstrap": 2,
                      "recovery": 1, "application": 2},
        "profile": profile,
        "identity": {
            "namespace": 1, "nodes": [10, 20], "default_service": 1,
            "epoch_source": "sec1-association", "restart": "fresh-handshake",
            "sample_epoch": "persistent-never-reused-u64", "sample_producer": 10,
        },
        "binding": binding,
        "services": _services(recovery, freshness_enabled),
        "limits": {
            "message_bytes": 64, "fragments": 4, "chunk_bytes": 16,
            "bootstrap_chunk_bytes": 60, "bootstrap_fragments": 2,
            "peers": 1, "assemblies_per_peer": 1,
            "assembly_tombstones_per_peer": 16, "operations_per_service": 1,
            "control_slots": 4 if freshness_enabled else 2,
            "application_queue_slots": 2,
            "adapter_slots": (4 if freshness_enabled else 2) + 1,
        },
        "security": {
            "mode": "NNpsk0", "cipher": 1,
            "credential": "provisioned-pairwise-psk",
            "trust_change": "owner-authorized-atomic-pin-and-acl",
            "pending_per_pair": 1, "active_per_pair": 1, "draining_per_pair": 1,
            "crypto_slots": 1, "full_capacity": "reject-new-until-capacity",
            "peer_restart": "retain-live-until-explicit-retirement",
            "failed_aead_limit": 1000, "replay_window_bits": 1024,
            "encryption_limit": 16777215, "plaintext_limit": 1073741823,
            "association_ms": 100000000, "drain_ms": 10000,
            "pairing_timeout_ms": 500, "preauth_slots": 1, "preauth_bytes": 120,
            "attempt_ms": 1000000, "episode_attempts": 2,
            "flight_attempts": 2, "flight_retry_ms": 1856,
            "confirmation_attempts": 2, "confirmation_timeout_ms": 320,
            "duplicate_responses_per_attempt": 1, "response_window_ms": 1000,
            "responses_per_window": 16, "response_bytes_per_window": 10000,
            "episode_ms": 2100000, "episode_crypto_ms": 2000,
            "crypto_per_attempt_ms": 1000, "episode_tx_bytes": 20000,
            "attempt_tx_bytes": 10000, "restart_backoff_ms": 1000,
            "later_episodes_per_window": 2, "later_window_ms": 10000000,
            "ingress_packets_per_window": 100, "ingress_window_ms": 1000,
            "global_crypto_ms_per_window": 100000,
        },
        "timing": {
            "queue_ms": 64, "forward_delay_ms": 20, "return_delay_ms": 20,
            "receipt_delay_ms": 110, "burst_span_ms": 256,
            "feedback_guard_ms": 4, "feedback_delay_ms": 110,
            "response_timeout_ms": 448,
            "deadline_order": "available-terminal-or-feedback-first",
            "send_horizon_ms": 960, "max_bursts": 2,
            "max_probes": 1 if selective else 0,
            "max_status": 2 if selective else 0,
            "burst_starts_ms": [0, 704], "jitter_ms": 0,
            "record_margin_ms": 5, "collect_ms": 980, "assembly_ms": 985,
            "inactivity_ms": 0, "dedup_ms": 1069, "rejection_ms": 1069,
            "result_cache_ms": 1069, "result_deadline_ms": 2240,
            "correlation_ms": 2304, "tombstone_ms": 2304, "late_result_ms": 10,
            "max_transfer_airtime_ms": 10000, "receipt_limit": 2,
            "feedback_buffers": 1,
        },
        "freshness": {
            "lease_ms": 2000 if freshness_enabled else 0,
            "grant_delivery_age_ms": 100 if freshness_enabled else 0,
            "grant_nodes": [10, 20] if freshness_enabled else [],
            "grant_acl": "same-authorized-service-only",
            "tokens_per_association": 4 if freshness_enabled else 0,
            "tokens_per_principal": 8 if freshness_enabled else 0,
            "grant_requests_per_pair": 2 if freshness_enabled else 0,
            "token_record_ms": 2000 if freshness_enabled else 0,
            "grant_result_ms": 1069 if freshness_enabled else 0,
        },
        "sample": {
            "init_attempts": 1, "init_retry_ms": 5, "init_deadline_ms": 2240,
            "synchronization": "correlated-read-current-generation",
            "no_sample_status": 64, "telemetry_bytes": 16,
            "read_request_bytes": 1, "read_result_bytes": 17,
            "status_request_bytes": 1, "status_result_bytes": 2,
        },
        "relays": relays,
        "resources": resources,
    }


def main():
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for kind, filename in (
        ("direct", "direct.json"),
        ("radio", "radio.json"),
        ("test-radio-retry-all", "test-radio-retry-all.json"),
    ):
        with (FIXTURES / filename).open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(manifest(kind), handle, indent=2, ensure_ascii=True)
            handle.write("\n")


if __name__ == "__main__":
    main()
