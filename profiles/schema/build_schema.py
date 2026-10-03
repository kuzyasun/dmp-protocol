"""Regenerate the portable JSON Schema. No third-party packages required."""
import json
from pathlib import Path


def integer(low=1, high=2147483647):
    return {"type": "integer", "minimum": low, "maximum": high}


def enum(*values):
    return {"enum": list(values)}


def obj(**fields):
    return {"type": "object", "additionalProperties": False,
            "required": list(fields), "properties": fields}


def array(item, low=1, high=64):
    return {"type": "array", "minItems": low, "maxItems": high, "items": item}


U32 = integer(0, 4294967295)
POS = integer()
TEXT = {"type": "string", "minLength": 1, "maxLength": 96,
        "pattern": "^[A-Za-z0-9_.:/+-]+$"}
BOOL = {"type": "boolean"}
COMPONENTS = ("provider_retained", "provider_scratch", "association", "bootstrap",
              "sender", "assembly", "assembly_tombstone", "result", "history", "correlation", "control",
              "application_queue", "adapter", "stacks", "relay_cache", "freshness_tokens")

SCHEMA = obj(
    contract=enum("DMP-test-manifest/2"),
    revisions=obj(core=enum(10), security=enum(5), bootstrap=enum(2),
                  recovery=enum(1), application=enum(2)),
    profile=obj(owner=enum("DMP-reference", "DMP-test"),
                id=enum("DIRECT-1", "RADIO-1", "TEST-RADIO-RETRY-ALL"), revision=integer(1, 4)),
    identity=obj(namespace=U32, nodes=array(U32, 2, 2), default_service=enum(1),
                 epoch_source=enum("sec1-association"), restart=enum("fresh-handshake"),
                 sample_epoch=enum("persistent-never-reused-u64"), sample_producer=U32),
    binding=obj(id=enum("DMP-test/SIM-STREAM-R", "DMP-test/SIM-PACKET"), revision=enum(1),
                kind=enum("stream-r", "packet"), segmentation=enum("none"),
                route_change=enum("fail-active-transfer"), topology=enum("point-to-point", "static-unicast"),
                context=enum("association", "origin-explicit"), ttl=integer(0, 4),
                forward_mtu=integer(32, 65535), return_mtu=integer(32, 65535),
                encoded_mtu=integer(32, 66000), frame_tx_ms=POS,
                tx_ownership=enum("copy", "borrow"), completion=enum("exactly-once-generation-tagged"),
                synchronous_completion=BOOL, cancellation=enum("terminal-event-releases-buffer"),
                disconnect=enum("settle-all-submissions-fail-transfers"),
                access=enum("reserved-half-duplex-slots"), return_opportunity=enum(True),
                burst_gate=enum("serialize-pair-services-directions-and-bootstrap"),
                return_slot_period_ms=POS, return_slot_width_ms=POS,
                bootstrap_integrity=enum("CRC32C")),
    services=array(obj(
        id=integer(1, 4294967295), reply_service=integer(1, 4294967295),
        service_encoding=enum("omitted", "explicit"),
        schema=enum("DMP-reference/SAMPLE-1/2", "DMP-test/OPAQUE-1/1"),
        payload_desc=enum("omitted"), recovery=enum("retry-all", "selective-32"),
        security=enum("SEC-1"), freshness=BOOL, idempotent=enum(True),
        request_bytes=integer(1, 1024), result_bytes=integer(1, 1024), processing_ms=POS,
        acl=array(obj(node=U32, actions=array(enum("produce", "read", "status", "data", "result"), 1, 5)), 2, 2)), 2, 2),
    limits=obj(message_bytes=integer(17, 1024), fragments=integer(2, 32), chunk_bytes=integer(1, 1023),
               bootstrap_chunk_bytes=integer(1, 119), bootstrap_fragments=integer(2, 120),
               peers=enum(1), assemblies_per_peer=enum(1),
               assembly_tombstones_per_peer=integer(1, 64), operations_per_service=enum(1),
               control_slots=integer(2, 64), application_queue_slots=POS, adapter_slots=POS),
    security=obj(mode=enum("NNpsk0", "XX"), cipher=enum(1),
                 credential=enum("provisioned-pairwise-psk", "authenticated-oob-xx"),
                 trust_change=enum("owner-authorized-atomic-pin-and-acl"),
                 pending_per_pair=integer(1, 4), active_per_pair=integer(1, 4),
                 draining_per_pair=integer(0, 4), crypto_slots=integer(1, 4),
                 full_capacity=enum("reject-new-until-capacity"),
                 peer_restart=enum("retain-live-until-explicit-retirement"),
                 failed_aead_limit=integer(1, 65536), replay_window_bits=enum(64, 128, 256, 512, 1024),
                 encryption_limit=integer(1, 16777216), plaintext_limit=integer(1, 1073741824),
                 association_ms=POS, drain_ms=integer(0), pairing_timeout_ms=POS,
                 preauth_slots=POS, preauth_bytes=POS, attempt_ms=POS,
                 flight_attempts=integer(1, 32), flight_retry_ms=POS,
                 confirmation_attempts=integer(1, 32), confirmation_timeout_ms=POS,
                 duplicate_responses_per_attempt=integer(0, 64), response_window_ms=POS,
                 responses_per_window=POS, response_bytes_per_window=POS,
                 episode_attempts=POS, episode_ms=POS, episode_crypto_ms=POS,
                 crypto_per_attempt_ms=POS, episode_tx_bytes=POS, attempt_tx_bytes=POS,
                 restart_backoff_ms=POS, later_episodes_per_window=POS, later_window_ms=POS,
                 ingress_packets_per_window=POS, ingress_window_ms=POS, global_crypto_ms_per_window=POS),
    timing=obj(queue_ms=POS, forward_delay_ms=POS, return_delay_ms=POS,
               receipt_delay_ms=POS, burst_span_ms=POS, feedback_guard_ms=POS,
               feedback_delay_ms=POS, response_timeout_ms=POS,
               deadline_order=enum("available-terminal-or-feedback-first"),
               send_horizon_ms=POS, max_bursts=integer(1, 32), max_probes=integer(0, 31),
               max_status=integer(0, 32), burst_starts_ms=array(integer(0), 1, 32),
               jitter_ms=integer(0), record_margin_ms=POS, collect_ms=POS,
               assembly_ms=POS, inactivity_ms=enum(0), dedup_ms=POS, rejection_ms=POS,
               result_cache_ms=POS, result_deadline_ms=POS, correlation_ms=POS,
               tombstone_ms=POS, late_result_ms=POS, max_transfer_airtime_ms=POS,
               receipt_limit=POS, feedback_buffers=POS),
    freshness=obj(lease_ms=integer(0, 60000), grant_delivery_age_ms=integer(0),
                  grant_nodes=array(U32, 0, 2), grant_acl=enum("same-authorized-service-only"),
                  tokens_per_association=integer(0, 64), tokens_per_principal=integer(0, 256),
                  grant_requests_per_pair=integer(0, 64), token_record_ms=integer(0),
                  grant_result_ms=integer(0)),
    sample=obj(init_attempts=POS, init_retry_ms=POS, init_deadline_ms=POS,
               synchronization=enum("correlated-read-current-generation"),
               no_sample_status=enum(64), telemetry_bytes=enum(16), read_request_bytes=enum(1),
               read_result_bytes=enum(17), status_request_bytes=enum(1), status_result_bytes=enum(2)),
    relays=array(obj(node=U32, public_pn_filter=enum("reject-ge-2pow24", "forward-structurally-valid"),
                     cooldown_anchor=enum("last-forward-completion"),
                     cooldown_ms=POS, expiry_ms=POS, max_forwards_per_key=POS,
                     frame_tx_ms=POS, per_origin_airtime_ms=POS, global_airtime_ms=POS,
                     lower_duplicates=integer(0, 16), duplicate_tail_ms=integer(0),
                     forward_arrival_min_ms=integer(0), forward_arrival_max_ms=POS,
                     return_arrival_min_ms=integer(0), return_arrival_max_ms=POS), 0, 4),
    resources=array(obj(role=enum("endpoint", "relay"), target=TEXT,
                        flash_limit_bytes=POS, flash_reserved_bytes=POS,
                        regions=array(obj(id=TEXT, limit_bytes=POS), 1, 8),
                        charges=array(obj(component=enum(*COMPONENTS), region=TEXT,
                                          count=POS, bytes_each=POS), 1, 112)), 1, 2),
)
SCHEMA = {"$schema": "https://json-schema.org/draft/2020-12/schema",
          "$id": "urn:dmp:test-manifest:2", **SCHEMA}

if __name__ == "__main__":
    Path(__file__).with_name("manifest-v2.schema.json").write_text(
        json.dumps(SCHEMA, indent=2) + "\n", encoding="utf-8", newline="\n")
