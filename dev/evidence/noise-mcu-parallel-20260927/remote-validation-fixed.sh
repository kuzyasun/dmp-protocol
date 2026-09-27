set -e
export IDF_COMPONENT_MANAGER=0 PYTHONUTF8=1
mkdir -p build/parallel2-results
cmake -S third_party/noise-c -B build/noise-upstream -G Ninja -DNOISE_C_BUILD_TESTS=ON > build/parallel2-results/backend.log 2>&1
cmake -S . -B build/parallel2-host -G Ninja -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=$PWD/build/noise-upstream/_deps/esphome_libsodium-1.10021.11 > build/parallel2-results/host-build.log 2>&1
cmake --build build/parallel2-host >> build/parallel2-results/host-build.log 2>&1
ctest --test-dir build/parallel2-host --output-on-failure > build/parallel2-results/host-tests.log 2>&1 || { cat build/parallel2-results/host-tests.log
build/parallel2-host/tests/provider/dmp_noise_parallel 1 16 > build/parallel2-results/host-one.json
build/parallel2-host/tests/provider/dmp_noise_parallel 2 64 > build/parallel2-results/host-two.json; exit 1; }
cat build/parallel2-results/host-tests.log
build/parallel2-host/tests/provider/dmp_noise_parallel 1 16 > build/parallel2-results/host-one.json
build/parallel2-host/tests/provider/dmp_noise_parallel 2 64 > build/parallel2-results/host-two.json
for chip in esp32s3 esp32c3; do
  eim run "idf.py -C tests/provider/targets/esp32-parallel -B $PWD/build/parallel2-$chip -DIDF_TARGET=$chip -DDMP_MCU_TEST_ONLY=ON -DDMP_SODIUM_SOURCE_DIR=$PWD/build/noise-upstream/_deps/esphome_libsodium-1.10021.11 build" v6.1 > build/parallel2-results/$chip-build.log 2>&1
  test -f build/parallel2-$chip/dmp_provider_parallel.bin
  prefix=riscv32-esp-elf
  if [ "$chip" = esp32s3 ]; then prefix=xtensa-esp32s3-elf; fi
  eim run "python tests/provider/collect_mcu_build.py --build-dir build/parallel2-$chip --elf build/parallel2-$chip/dmp_provider_parallel.elf --nm $prefix-nm --size $prefix-size --output build/parallel2-results/$chip-report.json" v6.1 > build/parallel2-results/$chip-collect.log 2>&1
  eim run "python -m esp_idf_size --format json2 --output-file build/parallel2-results/$chip-size.json build/parallel2-$chip/dmp_provider_parallel.map" v6.1 >> build/parallel2-results/$chip-collect.log 2>&1
done
python3 - <<'PY'
import tarfile, pathlib, hashlib, json
paths = list(pathlib.Path('build/parallel2-results').glob('*'))
paths += list(pathlib.Path('build/parallel2-host').rglob('console-traces/*.jsonl'))
paths += list(pathlib.Path('build/parallel2-host').rglob('LastTest.log'))
for chip in ('esp32s3','esp32c3'):
    root = pathlib.Path('build/parallel2-'+chip)
    for pattern in ('*.bin','*.elf','*.map','flasher_args.json','sdkconfig','compile_commands.json','CMakeCache.txt','bootloader/*.bin','partition_table/*.bin'):
        paths += list(root.glob(pattern))
manifest = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
pathlib.Path('build/parallel2-results/artifact-hashes.json').write_text(json.dumps(manifest,indent=2)+'\n')
paths += [pathlib.Path('build/parallel2-results/artifact-hashes.json')]
with tarfile.open('build/parallel2-results.tar.gz','w:gz') as out:
    for p in paths:
        if p.is_file(): out.add(p,arcname=str(p))
print('Final host tests, two IDF 6.1 builds and symbol gates completed.')
PY
