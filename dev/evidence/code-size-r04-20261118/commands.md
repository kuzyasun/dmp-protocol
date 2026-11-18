# R04 reproduction

## Windows host gate

From the R04 checkout root, initialize the Noise submodule at its gitlink.
Use the checked-out ESPHome sodium wrapper at revision
`40c22448d6e8f42be56c45f739b52a5c8d21c8ca` and its sodium submodule at
`d24faf56214469b354b01c8ba36257e04737101e`, with the wrapper's patches
applied. The checkout was prepared by the pinned Noise host recipe in
[R03](../code-size-r03-20261118/commands.md). Point the configure command
at that cached directory. The test configure checks the provider revisions
and input hashes before use. Use the archived fixture digests described
in the R03 recipe if the checkout's line endings require normalization.

```powershell
$cmake = (Get-Command cmake).Source
$ninja = (Get-Command ninja).Source.Replace('\', '/')
$gcc = (Get-Command gcc).Source.Replace('\', '/')
$gxx = (Get-Command g++).Source.Replace('\', '/')
$sodium = (Resolve-Path 'build/noise-upstream/_deps/esphome_libsodium-1.10021.11').Path.Replace('\', '/')
$hostBuild = 'build/r04-local-provider'
& $cmake -S . -B $hostBuild -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" "-DCMAKE_C_COMPILER=$gcc" "-DCMAKE_CXX_COMPILER=$gxx" -DCMAKE_BUILD_TYPE=Release -DDMP_BUILD_TESTS=ON "-DDMP_SODIUM_SOURCE_DIR=$sodium"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$targets = @(
    'dmp_test_reliability', 'dmp_test_endpoint', 'dmp_test_endpoint_none',
    'dmp_test_endpoint_sec', 'dmp_test_handshake', 'dmp_test_frag_status_vectors',
    'dmp_test_endpoint_sample_retry', 'dmp_test_endpoint_sec_sample_retry',
    'dmp_none_link_probe', 'dmp_test_none_capacity', 'dmp_test_none_multi_peer_traffic',
    'dmp_test_radio_none_selective', 'dmp_test_sample1_none',
    'dmp_test_sample1_none_5', 'dmp_test_sample1_none_16',
    'dmp_test_sample1_none_stream_r_5', 'dmp_test_sample1_none_stream_r_16',
    'dmp_test_sample1_none_radio_5', 'dmp_test_sample1_none_radio_16'
)
& $cmake --build $hostBuild --parallel 1 --target @targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
ctest --test-dir $hostBuild --output-on-failure -j 1 -R '^(reliability\.direct|endpoint\.|security\.handshake|recovery\.frag_status)'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$env:PYTHONPATH = (Resolve-Path 'tests/peer').Path
$env:DMP_P23_ENDPOINT_SEC_EXE = (Resolve-Path "$hostBuild/tests/security/dmp_test_endpoint_sec.exe").Path
$env:DMP_P23_SAMPLE1_NONE_DRIVER = (Resolve-Path "$hostBuild/dmp_test_sample1_none_stream_r_5.exe").Path
python -B -m unittest discover -v -s tests/peer/tests -p 'test_*.py'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -B -m unittest discover -v -s tests/peer/tests -p 'test_tcp_binding.py' -k test_split_and_coalesced_loopback_reads
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$nm = (Get-Command nm).Source
foreach ($archive in @('libdmp.a', 'libdmp_none.a')) {
    python tools/check_core_allocators.py "$hostBuild/$archive" --nm $nm
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
```

## Offline Windows qualification pairs

1. Create a disposable short-path snapshot from `git archive 389b295441257b2fded7c4e010e2f942327dee6a`.
   Extract the Noise gitlink revision from the submodule archive into
   `third_party/noise-c`. The gitlink and ESPHome component hash are in the
   [report](README.md). Copy the installed component to
   `tests/embedded/espnow_dmp/managed_components/esphome__libsodium`.
2. Activate the installed EIM ESP-IDF 6.1 PowerShell environment and set
   `$env:IDF_PY_BUILD_JOBS = '1'`. The measured toolchain was GCC 15.2.0.
   In the disposable application directory, the target lock has LF line
   endings and changes only the `target: esp32s3` or `target: esp32c3`
   line from the pinned R03 lock. Verify its hash against
   [size measurements](size-measurements.txt) before building the pair.
3. For each target, snapshot its baseline reliability source in Git LF form.
   Set `$app` to the snapshot's `tests/embedded/espnow_dmp` directory,
   `$chip` to the target, and `$build` to a fresh directory for that
   target. Build and record the following outputs.

```powershell
idf.py -C $app -B $build "-DIDF_TARGET=$chip" '-DPROJECT_VER=389b295-r04-size' build
idf.py -C $app -B $build "-DIDF_TARGET=$chip" '-DPROJECT_VER=389b295-r04-size' size
python -m esp_idf_size --format csv --archives "$build/dmp_espnow_dmp.map"
python -m esp_idf_size --format csv --files "$build/dmp_espnow_dmp.map"
python -m esp_idf_size --format csv "$build/dmp_espnow_dmp.map"
ninja -C $build -t commands dmp_espnow_dmp.elf | Select-Object -Last 1
Get-Item "$build/dmp_espnow_dmp.bin" | Select-Object -ExpandProperty Length
```

4. Save the baseline ELF, map, .bin, reports, linker command, config and
   lock. Copy the LF bytes of
   `git show <R04 commit>:src/reliability/reliability.c` into the snapshot
   and give the updated file a new mtime. Verify the digest from
   [verification](verification.txt). Repeat the commands in the same build
   directory and confirm Ninja recompiles only that C source before linking.
   Restore the baseline source before beginning the other target. Extract
   symbol sizes with the target's `nm -S --size-sort --radix=d` and stack
   prologues with `objdump -d` from the paired ELF files. The tool prefixes
   are `xtensa-esp32s3-elf` and `riscv32-esp-elf`.
