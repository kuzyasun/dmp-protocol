"""Reproduce a backend limitation; a pass is NOT fallible-startup acceptance."""
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_noise_init_abort.py <diagnostic-executable>")
    healthy = subprocess.run([sys.argv[1], "healthy"], capture_output=True,
                             text=True, timeout=10, check=False)
    if (healthy.returncode != 0 or "INIT_RETURNED result=0 rng_calls=" not in healthy.stdout
            or "OS_RNG_FAILURE_INJECTED" in healthy.stderr):
        raise SystemExit(f"Healthy startup control failed: {healthy!r}")
    failure = subprocess.run([sys.argv[1], "failure"], capture_output=True,
                             text=True, timeout=10, check=False)
    if (failure.returncode != 86 or "OS_RNG_FAILURE_INJECTED" not in failure.stderr
            or "INIT_RETURNED" in failure.stdout):
        raise SystemExit(f"Expected backend abort was not reproduced: {failure!r}")
    print(healthy.stdout.strip())
    print("Injected OS RNG failure reached real backend SIGABRT before Noise returned.")
    print("Expected limitation reproduced; cold-boot/no-process-exit gate remains FAILED.")


if __name__ == "__main__":
    main()
