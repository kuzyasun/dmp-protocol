add_executable(dmp_noise_console console/bench.c console/host_main.c
    noise_test_arena.c "${_fixture_header}")
set_target_properties(dmp_noise_console PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES)
target_include_directories(dmp_noise_console PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(dmp_noise_console PRIVATE dmp_noise_arena)
include(console/identity.cmake)
dmp_bench_identity(dmp_noise_console)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(dmp_noise_console PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-strict-aliasing)
endif()
add_test(NAME dmp_console_core COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/console/test_console_core.py" --exe $<TARGET_FILE:dmp_noise_console>)
set_tests_properties(dmp_console_core PROPERTIES TIMEOUT 30 LABELS "provider-console")
add_test(NAME dmp_console_client COMMAND "${Python3_EXECUTABLE}" -m unittest discover
    -s "${CMAKE_CURRENT_SOURCE_DIR}/console" -p test_serial_bench.py)
add_test(NAME dmp_console_live_pair COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/console/run_host_check.py" --exe $<TARGET_FILE:dmp_noise_console>
    --output-dir "${CMAKE_CURRENT_BINARY_DIR}/console-traces")
set_tests_properties(dmp_console_client dmp_console_live_pair PROPERTIES
    TIMEOUT 120 LABELS "provider-console")
if(WIN32)
    target_link_libraries(dmp_noise_console PRIVATE bcrypt)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_sources(dmp_noise_console PRIVATE noise_checked_no_legacy_rng.c)
        target_link_options(dmp_noise_console PRIVATE "-Wl,--wrap=randombytes_stir"
            "-Wl,--wrap=randombytes_buf")
    endif()
endif()
