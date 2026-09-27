set -e
export IDF_COMPONENT_MANAGER=0 PYTHONUTF8=1
mkdir -p build/parallel-results
cmake -S third_party/noise-c -B build/noise-upstream -G Ninja -DNOISE_C_BUILD_TESTS=ON > build/parallel-results/backend.log 2>&1
cmake -S . -B build/parallel-host -G Ninja -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=$PWD/build/noise-upstream/_deps/esphome_libsodium-1.10021.11 > build/parallel-results/host-build.log 2>&1
cmake --build build/parallel-host >> build/parallel-results/host-build.log 2>&1
ctest --test-dir build/parallel-host --output-on-failure > build/parallel-results/host-tests.log 2>&1 || { cat build/parallel-results/host-tests.log
build/parallel-host/tests/provider/dmp_noise_parallel 1 16 > build/parallel-results/host-one.json
build/parallel-host/tests/provider/dmp_noise_parallel 2 64 > build/parallel-results/host-two.json; exit 1; }
cat build/parallel-results/host-tests.log
build/parallel-host/tests/provider/dmp_noise_parallel 1 16 > build/parallel-results/host-one.json
build/parallel-host/tests/provider/dmp_noise_parallel 2 64 > build/parallel-results/host-two.json
for chip in esp32s3 esp32c3; do
  eim run "idf.py -C tests/provider/targets/esp32-parallel -B $PWD/build/parallel-$chip -DIDF_TARGET=$chip -DDMP_MCU_TEST_ONLY=ON -DDMP_SODIUM_SOURCE_DIR=$PWD/build/noise-upstream/_deps/esphome_libsodium-1.10021.11 build" v6.1 > build/parallel-results/$chip-build.log 2>&1
  test -f build/parallel-$chip/dmp_provider_parallel.bin
  prefix=riscv32-esp-elf
  if [ "$chip" = esp32s3 ]; then prefix=xtensa-esp32s3-elf; fi
  eim run "python tests/provider/collect_mcu_build.py --build-dir build/parallel-$chip --elf build/parallel-$chip/dmp_provider_parallel.elf --nm $prefix-nm --size $prefix-size --output build/parallel-results/$chip-report.json" v6.1 > build/parallel-results/$chip-collect.log 2>&1
  eim run "python -m esp_idf_size --format json2 --output-file build/parallel-results/$chip-size.json build/parallel-$chip/dmp_provider_parallel.map" v6.1 >> build/parallel-results/$chip-collect.log 2>&1
done
python3 - <<'PY'
import tarfile, pathlib, hashlib, json
paths = list(pathlib.Path('build/parallel-results').glob('*'))
paths += list(pathlib.Path('build/parallel-host').rglob('console-traces/*.jsonl'))
paths += list(pathlib.Path('build/parallel-host').rglob('LastTest.log'))
for chip in ('esp32s3','esp32c3'):
    root = pathlib.Path('build/parallel-'+chip)
    for pattern in ('*.bin','*.elf','*.map','flasher_args.json','sdkconfig','compile_commands.json','CMakeCache.txt','bootloader/*.bin','partition_table/*.bin'):
        paths += list(root.glob(pattern))
manifest = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
pathlib.Path('build/parallel-results/artifact-hashes.json').write_text(json.dumps(manifest,indent=2)+'\n')
paths += [pathlib.Path('build/parallel-results/artifact-hashes.json')]
with tarfile.open('build/parallel-results.tar.gz','w:gz') as out:
    for p in paths:
        if p.is_file(): out.add(p,arcname=str(p))
print('Final host tests, two IDF 6.1 builds and symbol gates completed.')
PY
