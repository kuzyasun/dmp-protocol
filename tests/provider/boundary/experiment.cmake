dmp_add_provider_experiment(dmp_noise_boundary boundary/probe.c boundary/peer.c
    noise_test_arena.c noise_checked_fixture_port.c "${_fixture_header}")
target_include_directories(dmp_noise_boundary PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(dmp_noise_boundary PRIVATE DMP_TEST_NOISE_ENTROPY_PORT=1)
target_link_libraries(dmp_noise_boundary PRIVATE dmp_noise_arena)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(dmp_noise_boundary PRIVATE -fno-strict-aliasing)
endif()
if(WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_sources(dmp_noise_boundary PRIVATE noise_checked_no_legacy_rng.c)
    target_link_options(dmp_noise_boundary PRIVATE "-Wl,--wrap=randombytes_stir" "-Wl,--wrap=randombytes_buf")
endif()
set_tests_properties(dmp_noise_boundary PROPERTIES TIMEOUT 30 LABELS "provider-boundary")
