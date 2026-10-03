cmake_minimum_required(VERSION 3.20)
project(dmp LANGUAGES C)

# The reusable C archive has no SDK, Python, Node or crypto dependency.
add_library(libdmp STATIC src/core/base.c src/core/codec.c
    src/integrity/crc32c.c src/stream/cobs.c src/stream/stream.c
    src/identity/identity.c src/identity/profile_admit.c)
add_library(dmp::dmp ALIAS libdmp)
set_target_properties(libdmp PROPERTIES OUTPUT_NAME dmp
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_compile_features(libdmp PUBLIC c_std_11)
target_include_directories(libdmp PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

function(dmp_strict_target target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()
dmp_strict_target(libdmp)

option(DMP_BUILD_TESTS "Build library tests, host scaffold and provider experiments" ON)
option(DMP_NOISE_EXPERIMENTS "Build opt-in Noise candidate characterization tests" OFF)
option(DMP_FUZZ "Build bounded Clang libFuzzer targets with ASan/UBSan" OFF)

if(DMP_NOISE_EXPERIMENTS AND NOT DMP_BUILD_TESTS)
    message(FATAL_ERROR "DMP_NOISE_EXPERIMENTS requires DMP_BUILD_TESTS")
endif()

if(DMP_BUILD_TESTS)
    enable_testing()
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    add_subdirectory(tests/core)
    add_subdirectory(tests/stream)
    add_subdirectory(tests/identity)
    add_subdirectory(tests/provider)
    add_subdirectory(tests/harness)
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
