"""Run the existing independent P23 peer against an ESP-IDF image in QEMU."""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[3]
READY = b"\nDMP P23 ready\n"
HEADER = struct.Struct("<BBI")
PROFILES = ("direct-nnpsk0", "radio-xx")
IO_TIMEOUT = 15
SUITE_TIMEOUT = 120


def target_info(chip):
    sys.path.insert(0, str(Path(os.environ["IDF_PATH"]) / "tools"))
    from idf_py_actions.qemu_ext import QEMU_TARGETS

    return QEMU_TARGETS[chip]


def read_exact(read, size):
    result = bytearray()
    while len(result) < size:
        part = read(size - len(result))
        if not part:
            raise EOFError(f"P23 stream ended after {len(result)} of {size} bytes")
        result.extend(part)
    return bytes(result)


def socket_reader(connection):
    deadline = time.monotonic() + IO_TIMEOUT

    def receive(size):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("P23 guest read deadline expired")
        connection.settimeout(remaining)
        return connection.recv(size)

    return receive


def wait_ready(connection):
    receive = socket_reader(connection)
    prefix = bytearray()
    while len(prefix) < 8192:
        prefix.extend(read_exact(receive, 1))
        if prefix.endswith(READY):
            return
    raise RuntimeError("P23 guest did not emit its ready marker")


def relay_records(connection):
    incoming, outgoing = sys.stdin.buffer, sys.stdout.buffer
    while first := incoming.read(1):
        request = first + read_exact(incoming.read, HEADER.size - 1)
        version, _, size = HEADER.unpack(request)
        if version != 1 or size > 65536:
            raise ValueError("invalid P23 host request header")
        connection.settimeout(IO_TIMEOUT)
        connection.sendall(request + read_exact(incoming.read, size))
        receive = socket_reader(connection)
        response = read_exact(receive, HEADER.size)
        version, _, size = HEADER.unpack(response)
        if version != 1 or size > 32768:
            raise ValueError("invalid P23 guest response header")
        outgoing.write(response + read_exact(receive, size))
        outgoing.flush()


def run_guest(build, emulator, chip):
    target = target_info(chip)
    with tempfile.TemporaryDirectory(prefix="p23-qemu-", dir=build) as temporary, socket.socket() as listener:
        flash = Path(temporary) / "flash.bin"
        efuse = Path(temporary) / "efuse.bin"
        shutil.copyfile(build / "p23-qemu-flash.bin", flash)
        efuse.write_bytes(target.default_efuse)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(IO_TIMEOUT)
        port = listener.getsockname()[1]
        command = [emulator, *target.qemu_args.split(),
                   "-drive", f"file={flash},if=mtd,format=raw",
                   "-drive", f"file={efuse},if=none,format=raw,id=efuse",
                   "-global", f"driver=nvram.{chip}.efuse,property=drive,value=efuse",
                   "-global", f"driver=timer.{chip}.timg,property=wdt_disable,value=true",
                   "-nic", "none", "-display", "none", "-monitor", "none", "-no-reboot",
                   "-serial", f"tcp:127.0.0.1:{port},nodelay"]
        # This process owns the guest, temporary images, listener and serial stream.
        # The host driver reads stderr after failure. Keep guest diagnostics
        # off that pipe while commands and responses are in flight.
        with tempfile.TemporaryFile(dir=temporary) as diagnostics:
            try:
                with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=diagnostics) as guest:
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            wait_ready(connection)
                            relay_records(connection)
                            if guest.poll() is not None:
                                raise RuntimeError(f"P23 guest exited during the test ({guest.returncode})")
                    finally:
                        if guest.poll() is None:
                            guest.terminate()
                            try:
                                guest.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                guest.kill()
            except (OSError, EOFError, ValueError, RuntimeError) as error:
                end = diagnostics.seek(0, os.SEEK_END)
                diagnostics.seek(max(0, end - 1024))
                message = f"P23 guest transport failed: {error}".encode("utf-8", "replace")[:512]
                sys.stderr.buffer.write(message + b"\n" + diagnostics.read(1024) + b"\n")
                return False
    return True


def run_suite(build, emulator, chip, profile):
    settings = json.loads((build / "flasher_args.json").read_text(encoding="utf-8"))
    if settings["extra_esptool_args"]["chip"] != chip:
        raise ValueError("selected QEMU machine differs from the built image")
    subprocess.run(
        [sys.executable, "-m", "esptool", f"--chip={chip}", "merge-bin",
         "--output=p23-qemu-flash.bin", f"--pad-to-size={settings['flash_settings']['flash_size']}",
         "@flash_args"], cwd=build, check=True, timeout=30,
    )
    app = settings["app"]
    app_bytes = (build / app["file"]).read_bytes()
    with (build / "p23-qemu-flash.bin").open("rb") as flash:
        flash.seek(int(app["offset"], 16))
        if flash.read(len(app_bytes)) != app_bytes:
            raise ValueError("QEMU Flash image does not contain the measured app binary")

    command = [sys.executable, "-B", __file__, str(build), chip, profile, "--emulator", emulator, "workloads"]
    try:
        return subprocess.run(command, timeout=SUITE_TIMEOUT).returncode
    except subprocess.TimeoutExpired:
        print(f"P23 workloads exceeded {SUITE_TIMEOUT}s", file=sys.stderr)
        return 1


def run_workloads(build, emulator, chip, profile):

    sys.path[:0] = [str(ROOT / "tests/peer"), str(ROOT / "tests/peer/tests")]
    from dmp_peer.frame import parse_frame
    from test_p23_c_endpoint_interop import TestP23CPrimaryInterop, _CProcess
    from test_p23_radio_endpoint_interop import TestP23RadioEndpointInterop, _MAX_CORE

    driver = [sys.executable, "-B", __file__, str(build), chip, profile, "--emulator", emulator]

    class Direct(TestP23CPrimaryInterop):
        __unittest_skip__ = False

        def setUp(self):
            self.executable = driver

        def test_exact_direct(self):
            self._exercise_large_request_result("direct-nnpsk0.json", 0x61)

    class Radio(TestP23RadioEndpointInterop):
        __unittest_skip__ = False

        def setUp(self):
            self.executable = driver
            self.digest_index = json.loads((ROOT / "profiles/deployments/digests.json").read_bytes())["manifests"]

        def _receive_forwarded(self, c_endpoint, packet, at_ms):
            return c_endpoint.receive(packet, at_ms)

        def _decode_c_frame(self, packet):
            parse_frame(packet, max_frame=_MAX_CORE)
            return packet

        def test_exact_radio(self):
            self.test_selective_32_repairs_over_radio_xx()

        def test_exact_freshness(self):
            self._exercise_radio_freshness_rejections("radio-xx.json", 0xA1)

    class ProfileBoundary(unittest.TestCase):
        def test_reject_profile_or_mode_mismatch(self):
            digest_index = json.loads((ROOT / "profiles/deployments/digests.json").read_bytes())["manifests"]
            other = next(name for name in PROFILES if name != profile)
            mode = 1 if profile == "direct-nnpsk0" else 2
            for name, requested_mode in ((other, mode), (profile, 3 - mode)):
                with self.subTest(manifest=name, mode=requested_mode):
                    with self.assertRaisesRegex(AssertionError, "endpoint initialization failed"):
                        _CProcess(driver, bytes.fromhex(digest_index[f"{name}.json"]), bytes(32), mode=requested_mode)

    workloads = [Direct("test_exact_direct")] if profile == "direct-nnpsk0" else [
        Radio("test_exact_radio"), Radio("test_exact_freshness"),
    ]
    return unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(
        [ProfileBoundary("test_reject_profile_or_mode_mismatch"), *workloads],
    )).wasSuccessful()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("chip", choices=("esp32s3", "esp32c3"))
    parser.add_argument("profile", choices=PROFILES)
    parser.add_argument("--emulator", help="QEMU executable, defaults to the SDK tool on PATH")
    parser.add_argument("command", choices=("p23-driver", "workloads"), nargs="?")
    args = parser.parse_intermixed_args()
    build = args.build.resolve()
    emulator = args.emulator or target_info(args.chip).qemu_prog
    if args.command == "p23-driver":
        return 0 if run_guest(build, emulator, args.chip) else 1
    if args.command == "workloads":
        return 0 if run_workloads(build, emulator, args.chip, args.profile) else 1
    return run_suite(build, emulator, args.chip, args.profile)


if __name__ == "__main__":
    sys.exit(main())
