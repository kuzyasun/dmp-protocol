cmake_minimum_required(VERSION 3.20)
project(dmp LANGUAGES C)

option(DMP_ENABLE_TEST_APIS "Retain the private handshake plaintext inspection API" ON)
option(DMP_HS_SHARED_ADMISSION_ONLY "Require an external admission registry for SEC-1 handshakes" OFF)

# The reusable C archive has no SDK, Python, or Node dependency. The P01B
# provider adapter is one archive member; tests/security link the reviewed
# Noise engine. Other objects do not reference it.
add_library(libdmp STATIC src/core/base.c src/core/codec.c
    src/integrity/crc32c.c src/stream/cobs.c src/stream/stream.c
    src/identity/identity.c src/identity/profile_admit.c
    src/reassembly/reassembly.c
    src/reliability/reliability.c
    src/endpoint/endpoint.c
    src/mesh/relay.c
    src/security/provider_adapter.c
    src/security/replay_window.c
    src/security/handshake.c
    src/security/handshake_transport.c)
add_library(dmp::dmp ALIAS libdmp)
set_target_properties(libdmp PROPERTIES OUTPUT_NAME dmp
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_compile_features(libdmp PUBLIC c_std_11)
target_compile_definitions(libdmp PUBLIC
    DMP_ENABLE_TEST_APIS=$<BOOL:${DMP_ENABLE_TEST_APIS}>
    DMP_HS_SHARED_ADMISSION_ONLY=$<BOOL:${DMP_HS_SHARED_ADMISSION_ONLY}>)
target_include_directories(libdmp PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(libdmp PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/noise-c/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/provider/backend")

function(dmp_strict_target target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()
dmp_strict_target(libdmp)

# NONE-only build composition: it compiles the same production core, endpoint,
# relay and SAMPLE-1 sources, while omitting the SEC-1 provider/Noise/handshake
# implementation. The tiny unavailable-entry stubs fail closed if a SEC-1 API
# is called accidentally; production NONE code must not reach them.
add_library(libdmp_none STATIC
    src/core/base.c src/core/codec.c src/integrity/crc32c.c
    src/stream/cobs.c src/stream/stream.c
    src/identity/identity.c src/identity/profile_admit.c
    src/reassembly/reassembly.c src/reliability/reliability.c
    src/endpoint/endpoint.c src/mesh/relay.c)
add_library(dmp::dmp_none ALIAS libdmp_none)
set_target_properties(libdmp_none PROPERTIES OUTPUT_NAME dmp_none
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_compile_features(libdmp_none PUBLIC c_std_11)
target_include_directories(libdmp_none PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(libdmp_none PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/security")
target_compile_definitions(libdmp_none PRIVATE DMP_ENDPOINT_NONE_ONLY=1)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(libdmp_none PRIVATE -O2 -ffunction-sections -fdata-sections)
endif()
dmp_strict_target(libdmp_none)

# RESCAN is not supported by every linker (notably Apple's ld64). Keep one
# portable helper for cyclic static-library sets: supported linkers use the
# native group feature; others rescan by repeating the archives in order.
function(dmp_link_rescan target)
    if(CMAKE_C_LINK_GROUP_USING_RESCAN_SUPPORTED)
        list(JOIN ARGN "," _rescan_group)
        target_link_libraries(${target} PRIVATE "$<LINK_GROUP:RESCAN,${_rescan_group}>")
    else()
        set(_rescan_libraries ${ARGN} ${ARGN})
        target_link_libraries(${target} PRIVATE ${_rescan_libraries})
    endif()
endfunction()

# SAMPLE-1 is an application example layered on the payload-agnostic core.
add_library(libdmp_sample1 STATIC
    src/application/sample1_epoch_owner.c
    src/application/sample1_endpoint.c
    src/application/sample1_epoch_store.c
    src/application/sample1_epoch_anchor_nvs.c)
add_library(dmp::sample1 ALIAS libdmp_sample1)
set_target_properties(libdmp_sample1 PROPERTIES
    OUTPUT_NAME dmp_sample1
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_link_libraries(libdmp_sample1 PUBLIC dmp::dmp)
target_include_directories(libdmp_sample1 PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/application")
dmp_strict_target(libdmp_sample1)

add_library(libdmp_sample1_none STATIC
    src/application/sample1_epoch_owner.c
    src/application/sample1_endpoint.c
    src/application/sample1_epoch_store.c
    src/application/sample1_epoch_anchor_nvs.c)
add_library(dmp::sample1_none ALIAS libdmp_sample1_none)
set_target_properties(libdmp_sample1_none PROPERTIES
    OUTPUT_NAME dmp_sample1_none C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_link_libraries(libdmp_sample1_none PUBLIC dmp::dmp_none)
target_include_directories(libdmp_sample1_none PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/application")
dmp_strict_target(libdmp_sample1_none)

option(DMP_BUILD_TESTS "Build library tests, host scaffold and provider experiments" ON)
option(DMP_NOISE_EXPERIMENTS "Build opt-in Noise candidate characterization tests" OFF)
option(DMP_FUZZ "Build bounded Clang libFuzzer targets with ASan/UBSan" OFF)

if(DMP_NOISE_EXPERIMENTS AND NOT DMP_BUILD_TESTS)
    message(FATAL_ERROR "DMP_NOISE_EXPERIMENTS requires DMP_BUILD_TESTS")
endif()
if(DMP_HS_SHARED_ADMISSION_ONLY AND (DMP_NOISE_EXPERIMENTS OR DMP_FUZZ))
    message(FATAL_ERROR
        "DMP_HS_SHARED_ADMISSION_ONLY does not support the Noise experiment or fuzz suites")
endif()

if(DMP_BUILD_TESTS)
    enable_testing()
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    set(DMP_SODIUM_SOURCE_DIR "" CACHE PATH
        "Pinned prepared libsodium tree for the P01B adapter tests")
endif()

if(DMP_BUILD_TESTS AND DMP_HS_SHARED_ADMISSION_ONLY)
    if(NOT IS_DIRECTORY "${DMP_SODIUM_SOURCE_DIR}")
        message(FATAL_ERROR
            "Shared-admission handshake tests require the pinned DMP_SODIUM_SOURCE_DIR")
    endif()
    enable_language(ASM)
    add_subdirectory(tests/security)
elseif(DMP_BUILD_TESTS)
    add_subdirectory(tests/core)
    add_subdirectory(tests/stream)
    add_subdirectory(tests/size)
    add_subdirectory(tests/identity)
    add_subdirectory(tests/reassembly)
    add_subdirectory(tests/reliability)
    add_subdirectory(tests/application)
    add_subdirectory(tests/endpoint)
    add_executable(dmp_none_link_probe tests/endpoint/none_link_probe.c)
    target_link_libraries(dmp_none_link_probe PRIVATE dmp::sample1_none)
    set_target_properties(dmp_none_link_probe PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(dmp_none_link_probe)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        if(APPLE)
            target_link_options(dmp_none_link_probe PRIVATE -Wl,-dead_strip)
        else()
            target_link_options(dmp_none_link_probe PRIVATE -Wl,--gc-sections)
        endif()
    endif()
    add_test(NAME endpoint.none_crypto_free_link COMMAND dmp_none_link_probe)
    set_tests_properties(endpoint.none_crypto_free_link PROPERTIES
        TIMEOUT 30 LABELS "endpoint;none;link")

    # Run the production endpoint loopback against the same NONE-only archive.
    # The test program supplies application callbacks and caller-owned storage;
    # no SEC-1 provider or handshake implementation is linked.
    add_executable(dmp_test_endpoint_none tests/endpoint/test_endpoint.c)
    target_link_libraries(dmp_test_endpoint_none PRIVATE dmp::sample1_none)
    set_target_properties(dmp_test_endpoint_none PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    set(_none_sample_manifest "${PROJECT_SOURCE_DIR}/profiles/deployments/direct-none.json")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_none_sample_manifest}")
    file(READ "${_none_sample_manifest}" _none_sample_manifest_json)
    string(JSON _none_sample_init_attempts GET "${_none_sample_manifest_json}" sample init_attempts)
    string(JSON _none_sample_init_retry_ms GET "${_none_sample_manifest_json}" sample init_retry_ms)
    string(JSON _none_sample_init_deadline_ms GET "${_none_sample_manifest_json}" sample init_deadline_ms)
    string(JSON _none_sample_status GET "${_none_sample_manifest_json}" sample no_sample_status)
    string(JSON _none_sample_result_deadline_ms GET "${_none_sample_manifest_json}" timing result_deadline_ms)
    target_compile_definitions(dmp_test_endpoint_none PRIVATE
        SAMPLE_INIT_ATTEMPTS=${_none_sample_init_attempts}
        SAMPLE_INIT_RETRY_MS=${_none_sample_init_retry_ms}
        SAMPLE_INIT_DEADLINE_MS=${_none_sample_init_deadline_ms}
        SAMPLE_RESULT_DEADLINE_MS=${_none_sample_result_deadline_ms}
        SAMPLE_NO_SAMPLE=${_none_sample_status})
    dmp_strict_target(dmp_test_endpoint_none)
    if(MSVC)
        target_compile_definitions(dmp_test_endpoint_none PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
    foreach(name sample1 packet fragment fragment_replay retry result_loss receipt_loss
                 duplicate quota sample_no_sample sample_init_budget sample_same_epoch
                 sample_new_epoch sample_late_assoc sample_superseded sample_invalid
                 sample_epoch_restart sample_epoch_fail sample_epoch_indeterminate
                 sample_epoch_index_exhaustion)
        add_test(NAME endpoint.none.${name} COMMAND dmp_test_endpoint_none ${name})
        set_tests_properties(endpoint.none.${name} PROPERTIES TIMEOUT 30 LABELS "endpoint;none")
    endforeach()

    # Higher-peer NONE cases use the same shared production endpoint with
    # explicit caller-owned arenas. Exercise 1/5/16 peers and unknown traffic.
    add_executable(dmp_test_none_capacity tests/endpoint/test_none_capacity.c)
    target_link_libraries(dmp_test_none_capacity PRIVATE dmp::dmp_none)
    target_include_directories(dmp_test_none_capacity PRIVATE src/application)
    set_target_properties(dmp_test_none_capacity PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(dmp_test_none_capacity)
    foreach(capacity 1 5 16)
        add_test(NAME endpoint.none.capacity_${capacity}
            COMMAND dmp_test_none_capacity ${capacity})
        set_tests_properties(endpoint.none.capacity_${capacity} PROPERTIES
            TIMEOUT 30 LABELS "endpoint;none;capacity")
    endforeach()
    add_test(NAME endpoint.none.unknown_traffic
        COMMAND dmp_test_none_capacity unknown)
    set_tests_properties(endpoint.none.unknown_traffic PROPERTIES
        TIMEOUT 30 LABELS "endpoint;none;capacity")

    add_executable(dmp_test_none_multi_peer_traffic
        tests/endpoint/test_none_multi_peer_traffic.c)
    target_link_libraries(dmp_test_none_multi_peer_traffic PRIVATE dmp::sample1_none)
    set_target_properties(dmp_test_none_multi_peer_traffic PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(dmp_test_none_multi_peer_traffic)
    add_test(NAME endpoint.none.multi_peer_traffic
        COMMAND dmp_test_none_multi_peer_traffic traffic)
    set_tests_properties(endpoint.none.multi_peer_traffic PROPERTIES
        TIMEOUT 30 LABELS "endpoint;none;multi-peer;traffic")

    add_executable(dmp_test_sample1_none tests/endpoint/test_sample1_none.c)
    target_link_libraries(dmp_test_sample1_none PRIVATE dmp::sample1_none)
    set_target_properties(dmp_test_sample1_none PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(dmp_test_sample1_none)
    add_test(NAME endpoint.none.sample1_production COMMAND dmp_test_sample1_none)
    set_tests_properties(endpoint.none.sample1_production PROPERTIES
        TIMEOUT 30 LABELS "endpoint;none;sample1")
    foreach(_sample_capacity IN ITEMS 5 16)
        add_executable(dmp_test_sample1_none_${_sample_capacity}
            tests/endpoint/test_sample1_none.c)
        target_compile_definitions(dmp_test_sample1_none_${_sample_capacity} PRIVATE
            SAMPLE_PEERS=${_sample_capacity})
        target_link_libraries(dmp_test_sample1_none_${_sample_capacity}
            PRIVATE dmp::sample1_none)
        set_target_properties(dmp_test_sample1_none_${_sample_capacity} PROPERTIES
            C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
        dmp_strict_target(dmp_test_sample1_none_${_sample_capacity})
        add_test(NAME endpoint.none.sample1_capacity_${_sample_capacity}
            COMMAND dmp_test_sample1_none_${_sample_capacity})
        set_tests_properties(endpoint.none.sample1_capacity_${_sample_capacity}
            PROPERTIES TIMEOUT 30 LABELS "endpoint;none;sample1;capacity")

        add_executable(dmp_test_sample1_none_stream_r_${_sample_capacity}
            tests/endpoint/test_sample1_none.c)
        target_compile_definitions(dmp_test_sample1_none_stream_r_${_sample_capacity}
            PRIVATE SAMPLE_PEERS=${_sample_capacity}
                    SAMPLE_FRAMING_MODE=DMP_ENDPOINT_FRAMING_STREAM_R)
        target_link_libraries(dmp_test_sample1_none_stream_r_${_sample_capacity}
            PRIVATE dmp::sample1_none)
        set_target_properties(dmp_test_sample1_none_stream_r_${_sample_capacity}
            PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
        dmp_strict_target(dmp_test_sample1_none_stream_r_${_sample_capacity})
        add_test(NAME endpoint.none.sample1_stream_r_capacity_${_sample_capacity}
            COMMAND dmp_test_sample1_none_stream_r_${_sample_capacity})
        set_tests_properties(endpoint.none.sample1_stream_r_capacity_${_sample_capacity}
            PROPERTIES TIMEOUT 30 LABELS "endpoint;none;sample1;capacity;stream-r")

    endforeach()

    foreach(_sample_capacity IN ITEMS 5 16)
        add_executable(dmp_test_sample1_none_radio_${_sample_capacity}
            tests/endpoint/test_sample1_none.c)
        target_compile_definitions(dmp_test_sample1_none_radio_${_sample_capacity}
            PRIVATE SAMPLE_PEERS=${_sample_capacity} SAMPLE_RADIO=1)
        target_link_libraries(dmp_test_sample1_none_radio_${_sample_capacity}
            PRIVATE dmp::sample1_none)
        set_target_properties(dmp_test_sample1_none_radio_${_sample_capacity}
            PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
        dmp_strict_target(dmp_test_sample1_none_radio_${_sample_capacity})
        add_test(NAME endpoint.none.sample1_radio_capacity_${_sample_capacity}
            COMMAND dmp_test_sample1_none_radio_${_sample_capacity})
        set_tests_properties(endpoint.none.sample1_radio_capacity_${_sample_capacity}
            PROPERTIES TIMEOUT 30 LABELS "endpoint;none;sample1;capacity;radio;selective")
    endforeach()

    add_executable(dmp_test_radio_none_selective
        tests/endpoint/test_radio_none_selective.c)
    target_link_libraries(dmp_test_radio_none_selective PRIVATE dmp::dmp_none)
    set_target_properties(dmp_test_radio_none_selective PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(dmp_test_radio_none_selective)
    add_test(NAME endpoint.none.radio_selective_data
        COMMAND dmp_test_radio_none_selective)
    set_tests_properties(endpoint.none.radio_selective_data PROPERTIES
        TIMEOUT 30 LABELS "endpoint;none;radio;selective")

    add_subdirectory(tests/provider)
    if(IS_DIRECTORY "${DMP_SODIUM_SOURCE_DIR}")
        enable_language(ASM)
        add_subdirectory(tests/security)
    else()
        message(STATUS
            "P01B adapter tests are not registered; set DMP_SODIUM_SOURCE_DIR")
    endif()
    add_subdirectory(tests/harness)
    add_subdirectory(tests/mesh)
    add_subdirectory(tests/benchmark)
    add_subdirectory(tests/recovery)
    add_subdirectory(tests/workloads)
    add_subdirectory(tests/scenarios)
    add_subdirectory(tests/memory)
    add_subdirectory(tests/host/espnow_pair)
    add_subdirectory(tests/host/espnow_dmp)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
       CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_executable(dmp_test_allocator_paths tests/core/allocator_probe.c)
        target_link_libraries(dmp_test_allocator_paths PRIVATE dmp::dmp)
        set_target_properties(dmp_test_allocator_paths PROPERTIES
            C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
        dmp_strict_target(dmp_test_allocator_paths)
        target_link_options(dmp_test_allocator_paths PRIVATE
            -Wl,--wrap=malloc
            -Wl,--wrap=calloc
            -Wl,--wrap=realloc
            -Wl,--wrap=free)
        add_test(NAME core.allocator_paths COMMAND dmp_test_allocator_paths)
        set_tests_properties(core.allocator_paths PROPERTIES
            TIMEOUT 10 LABELS "core-foundation;allocation")
    endif()
    add_test(NAME profiles.contract
        COMMAND "${Python3_EXECUTABLE}" -m unittest discover
                -s "${CMAKE_CURRENT_SOURCE_DIR}/tests/profiles" -p "test_*.py" -v)
    set_tests_properties(profiles.contract PROPERTIES LABELS "profile-validator" TIMEOUT 30)
    find_program(DMP_NODE_EXECUTABLE NAMES node nodejs REQUIRED)
    add_test(NAME fixtures.sec1
        COMMAND "${DMP_NODE_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/dev/dmp_verify_security_vectors.cjs")
    set_tests_properties(fixtures.sec1 PROPERTIES LABELS "fixture-only" TIMEOUT 30)
    add_test(NAME fixtures.recovery
        COMMAND "${DMP_NODE_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/dev/dmp_verify_recovery_vectors.cjs")
    set_tests_properties(fixtures.recovery PROPERTIES LABELS "recovery;fixture-only" TIMEOUT 30)
endif()


if(DMP_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR
       NOT CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
        message(FATAL_ERROR "DMP_FUZZ requires the Clang GNU-style driver")
    endif()
    target_compile_options(libdmp PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=undefined)
    target_link_options(libdmp PUBLIC
        -fsanitize=address,undefined
        -fno-sanitize-recover=undefined)
    set(DMP_FUZZ_LIBDMP_INSTRUMENTED ON)
    add_subdirectory(tests/fuzz)
endif()
