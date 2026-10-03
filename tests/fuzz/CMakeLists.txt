cmake_minimum_required(VERSION 3.20)

# Coordinator integration fragment. This is not a standalone project and it does
# not instrument libdmp. Root CMake must compile libdmp with the address and
# undefined sanitizers, set DMP_FUZZ_LIBDMP_INSTRUMENTED, then add_subdirectory.
# See tests/fuzz/README.md. libFuzzer belongs on these executables only.

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    message(FATAL_ERROR
        "Add tests/fuzz from an instrumented libdmp build. "
        "The README smoke command compiles this package without root CMake.")
endif()

if(NOT TARGET libdmp)
    message(FATAL_ERROR "tests/fuzz requires the libdmp target")
endif()

if(NOT DMP_FUZZ_LIBDMP_INSTRUMENTED)
    message(FATAL_ERROR
        "Set DMP_FUZZ_LIBDMP_INSTRUMENTED ON only after libdmp objects use "
        "-fsanitize=address,undefined. Do not put -fsanitize=fuzzer on libdmp.")
endif()

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR
   NOT CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
    message(FATAL_ERROR
        "tests/fuzz libFuzzer targets require the Clang GNU-style driver, "
        "not clang-cl")
endif()

function(dmp_add_fuzz_target target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE dmp::dmp)
    target_compile_definitions(${target} PRIVATE DMP_FUZZ_LIBFUZZER)
    target_compile_features(${target} PRIVATE c_std_11)
    set_target_properties(${target} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -O1 -g -fno-omit-frame-pointer
        -fsanitize=fuzzer,address,undefined
        -fno-sanitize-recover=undefined)
    target_link_options(${target} PRIVATE
        -fsanitize=fuzzer,address,undefined
        -fno-sanitize-recover=undefined)
endfunction()

dmp_add_fuzz_target(dmp_fuzz_core fuzz_core.c)
dmp_add_fuzz_target(dmp_fuzz_stream fuzz_stream.c)

add_executable(dmp_fuzz_selfcheck selfcheck.c fuzz_core.c fuzz_stream.c)
target_link_libraries(dmp_fuzz_selfcheck PRIVATE dmp::dmp)
target_compile_features(dmp_fuzz_selfcheck PRIVATE c_std_11)
set_target_properties(dmp_fuzz_selfcheck PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_compile_options(dmp_fuzz_selfcheck PRIVATE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined)
dmp_strict_target(dmp_fuzz_selfcheck)
if(DMP_BUILD_TESTS)
    add_test(NAME fuzz.selfcheck COMMAND dmp_fuzz_selfcheck)
    set_tests_properties(fuzz.selfcheck PROPERTIES
        TIMEOUT 10 LABELS "fuzz;bounded")
endif()

add_executable(dmp_fuzz_seed_corpus seed_corpus.c)
target_link_libraries(dmp_fuzz_seed_corpus PRIVATE dmp::dmp)
target_compile_features(dmp_fuzz_seed_corpus PRIVATE c_std_11)
set_target_properties(dmp_fuzz_seed_corpus PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_fuzz_seed_corpus)
