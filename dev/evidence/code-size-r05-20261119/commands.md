# R05 reproduction

Use the pinned provider and fixtures from the [R04 host recipe](../code-size-r04-20261118/commands.md).
Run its host configure, build, CTest, peer and allocator commands against R05
with `$hostBuild = 'build/r05-host'`. The measured peer pass ran with local
loopback access. Both subprocess drivers came from this host build.

For the regression's before result, build `dmp_test_none_multi_peer_traffic`
at `a3dfca46484d8cfa5702a8f59b49b1aff0f39fb3` using the R04 host recipe.
From the R05 checkout, build its final fixture against that R04 NONE pair.
Point `$baselineHost` at the resulting R04 build directory.

```powershell
$probe = 'build/r05-host/r04-with-final-borrow-test.exe'
gcc -std=c11 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -Werror -Iinclude -Isrc/application tests/endpoint/test_none_multi_peer_traffic.c "$baselineHost/libdmp_sample1_none.a" "$baselineHost/libdmp_none.a" -o $probe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $probe traffic
```

The expected baseline exit is 1 with the held-frame byte comparison shown in
[verification](verification.txt). Run the same fixture with the R05 library
using `ctest --test-dir build/r05-host --output-on-failure -j 1 -R '^endpoint\.none\.multi_peer_traffic$'`.

For ESP32, start with either target's R04 candidate from the
[R04 link recipe](../code-size-r04-20261118/commands.md). Use the same
disposable source and per-target build directory. Preserve both R04
candidate artifact sets. Check the unchanged R04 reliability source
against its LF hash in [R04 verification](../code-size-r04-20261118/verification.txt).
Copy only R05's `src/endpoint/endpoint.c` into the disposable checkout,
verify its LF hash in [R05 verification](verification.txt), and update that
file's mtime. Before each target, restore its recorded dependency lock.
Activate the same EIM ESP-IDF 6.1 environment and run the following with
`$app` set to the disposable qualification application, `$chip` to the
current target and `$build` to its existing R04 build directory.

```powershell
$env:IDF_PY_BUILD_JOBS = '1'
idf.py -C $app -B $build "-DIDF_TARGET=$chip" '-DPROJECT_VER=389b295-r04-size' build
idf.py -C $app -B $build "-DIDF_TARGET=$chip" '-DPROJECT_VER=389b295-r04-size' size
python -m esp_idf_size --format csv --archives "$build/dmp_espnow_dmp.map"
python -m esp_idf_size --format csv --files "$build/dmp_espnow_dmp.map"
python -m esp_idf_size --format csv "$build/dmp_espnow_dmp.map"
ninja -C $build -t commands dmp_espnow_dmp.elf | Select-Object -Last 1
Get-Item "$build/dmp_espnow_dmp.bin" | Select-Object -ExpandProperty Length
```

Compare the configuration, lock, linker script and command digests for
each pair. Extract symbols and prologues with the target's `nm` and
`objdump`. Serialize the two target runs. The application version string
was kept equal to R04's recorded version for both comparisons.
