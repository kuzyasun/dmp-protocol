# MEM-02: explicit custom storage build; no replacement of the baseline target.
add_library(dmp_noise_arena STATIC ${_noise_entropy_sources})
target_include_directories(dmp_noise_arena PUBLIC
    "${PROJECT_SOURCE_DIR}/third_party/noise-c/include"
    "${PROJECT_SOURCE_DIR}/third_party/noise-c/src")
target_compile_definitions(dmp_noise_arena PUBLIC
    NOISE_USE_CUSTOM_ALLOCATOR=1 NOISE_USE_CUSTOM_RAND=1 NOISE_USE_SODIUM_RAND=0
    NOISE_REQUIRE_FALLIBLE_RAND=1 NOISE_USE_PTHREAD=0)
target_compile_definitions(dmp_noise_arena PRIVATE NOISE_REQUIRE_SODIUM_FAST_PATH)
target_link_libraries(dmp_noise_arena PUBLIC dmp_sodium_checked)

dmp_add_provider_experiment(dmp_noise_arena_unit noise_test_arena.c noise_test_arena_probe.c)
set_tests_properties(dmp_noise_arena_unit PROPERTIES LABELS "allocator-unit")

dmp_add_provider_experiment(dmp_noise_allocator_probe
    noise_allocator_probe.c noise_test_arena.c noise_fixture_probe.c
    noise_checked_fixture_port.c "${_fixture_header}")
target_include_directories(dmp_noise_allocator_probe PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(dmp_noise_allocator_probe PRIVATE
    DMP_TEST_NOISE_ENTROPY_PORT=1 DMP_NOISE_FIXTURE_EMBEDDED_RUNNER=1)
target_link_libraries(dmp_noise_allocator_probe PRIVATE dmp_noise_arena)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # The test port reuses declared byte storage for different object types.
    # Make that storage policy explicit; alignment alone is not an aliasing model.
    target_compile_options(dmp_noise_arena PRIVATE -fno-strict-aliasing)
    target_compile_options(dmp_noise_allocator_probe PRIVATE -fno-strict-aliasing)
elseif(NOT MSVC)
    message(FATAL_ERROR "MEM-02 static arena needs an explicit compiler aliasing contract")
endif()

include(owner_experiment.cmake)
include(console/experiment.cmake)
include(parallel/experiment.cmake)
set_tests_properties(dmp_noise_allocator_probe PROPERTIES LABELS "provider-allocator-experiment")
if(WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_sources(dmp_noise_allocator_probe PRIVATE noise_checked_no_legacy_rng.c)
    target_link_options(dmp_noise_allocator_probe PRIVATE
        "-Wl,--wrap=randombytes_stir" "-Wl,--wrap=randombytes_buf")
endif()
