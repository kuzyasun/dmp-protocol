"""Frozen in-process test API; endpoint behavior is supplied by later P21 packages."""

from __future__ import annotations

from .manifest import identify_frozen_manifest


class PeerEndpoint:
    def __init__(self, manifest_bytes: bytes, test_credentials, entropy_source, test_services) -> None:
        self.manifest = identify_frozen_manifest(bytes(manifest_bytes))
        self.manifest_bytes = bytes(manifest_bytes)
        self.test_credentials = test_credentials
        self.entropy_source = entropy_source
        self.test_services = test_services

    def handle(self, input_event) -> tuple:
        raise NotImplementedError("endpoint lifecycle is implemented by later P21 packages")
