set -e
export IDF_COMPONENT_MANAGER=0 PYTHONUTF8=1
mkdir -p build/console-results
cmake -S third_party/noise-c -B build/noise-upstream -G Ninja -DNOISE_C_BUILD_TESTS=ON > build/console-results/backend.log 2>&1
cmake -S . -B build/bench-host -G Ninja -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=$PWD/build/noise-upstream/_deps/esphome_libsodium-1.10021.11 > build/console-results/host-build.log 2>&1
cmake --build build/bench-host >> build/console-results/host-build.log 2>&1
ctest --test-dir build/bench-host --output-on-failure > build/console-results/host-tests.log 2>&1 || { cat build/console-results/host-tests.log; exit 1; }
cat build/console-results/host-tests.log
for chip in esp32s3 esp32c3; do
  eim run "idf.py -C tests/provider/targets/esp32-console -B $PWD/build/bench-$chip -DIDF_TARGET=$chip -DDMP_MCU_TEST_ONLY=ON -DDMP_SODIUM_SOURCE_DIR=$PWD/build/noise-upstream/_deps/esphome_libsodium-1.10021.11 build" v6.1 > build/console-results/$chip-build.log 2>&1
  test -f build/bench-$chip/dmp_provider_console.bin
  prefix=riscv32-esp-elf
  if [ "$chip" = esp32s3 ]; then prefix=xtensa-esp32s3-elf; fi
  eim run "python tests/provider/collect_mcu_build.py --build-dir build/bench-$chip --elf build/bench-$chip/dmp_provider_console.elf --nm $prefix-nm --size $prefix-size --output build/console-results/$chip-report.json" v6.1 > build/console-results/$chip-collect.log 2>&1
  eim run "python -m esp_idf_size --format json2 --output-file build/console-results/$chip-size.json build/bench-$chip/dmp_provider_console.map" v6.1 >> build/console-results/$chip-collect.log 2>&1
done
python3 - <<'PY'
import tarfile, pathlib, hashlib, json
paths = list(pathlib.Path('build/console-results').glob('*'))
paths += list(pathlib.Path('build/bench-host').rglob('console-traces/*.jsonl'))
paths += list(pathlib.Path('build/bench-host').rglob('LastTest.log'))
for chip in ('esp32s3','esp32c3'):
    root = pathlib.Path('build/bench-'+chip)
    for pattern in ('*.bin','*.elf','*.map','flasher_args.json','sdkconfig','compile_commands.json','CMakeCache.txt','bootloader/*.bin','partition_table/*.bin'):
        paths += list(root.glob(pattern))
manifest = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
pathlib.Path('build/console-results/artifact-hashes.json').write_text(json.dumps(manifest,indent=2)+'\n')
paths += [pathlib.Path('build/console-results/artifact-hashes.json')]
with tarfile.open('build/console-results.tar.gz','w:gz') as out:
    for p in paths:
        if p.is_file(): out.add(p,arcname=str(p))
print('Final host tests, two IDF 6.1 builds and symbol gates completed.')
PY
