set -e
mkdir -p build/pressure-results
cmake -S third_party/noise-c -B build/noise-upstream -G Ninja -DNOISE_C_BUILD_TESTS=ON > build/pressure-results/backend.log 2>&1
cmake -S . -B build/pressure-host -G Ninja -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=$PWD/build/noise-upstream/_deps/esphome_libsodium-1.10021.11 > build/pressure-results/build.log 2>&1
cmake --build build/pressure-host --target dmp_noise_console >> build/pressure-results/build.log 2>&1
ctest --test-dir build/pressure-host -L provider-console --output-on-failure > build/pressure-results/ctest.log 2>&1
python3 tests/provider/console/serial_pressure.py --host-exe build/pressure-host/tests/provider/dmp_noise_console --output build/pressure-results/host.jsonl > build/pressure-results/summary.json 2> build/pressure-results/runner.stderr.log
cat build/pressure-results/ctest.log
python3 - <<'PY'
import json, hashlib, pathlib
p=pathlib.Path('tests/provider/console/serial_pressure.py')
print('runner_sha256',hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest())
print('Pressure runner exited successfully; inspect summary.json and raw trace.')
PY
