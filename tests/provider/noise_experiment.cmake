# Host characterization only. No production provider or network fetch by default.
# First prepare the backend using the standalone fork build in README.md.
set(DMP_SODIUM_SOURCE_DIR "" CACHE PATH "Prepared ESPHome sodium source for experiments")
if(NOT IS_DIRECTORY "${DMP_SODIUM_SOURCE_DIR}")
    message(FATAL_ERROR "Set DMP_SODIUM_SOURCE_DIR to the prepared pinned backend")
endif()
find_package(Git REQUIRED)
function(dmp_require_revision directory expected)
    execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${directory}" rev-parse HEAD
        OUTPUT_VARIABLE actual OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE result)
    if(NOT result EQUAL 0 OR NOT actual STREQUAL expected)
        message(FATAL_ERROR "Unexpected experiment source revision at ${directory}: ${actual}")
    endif()
endfunction()
dmp_require_revision("${PROJECT_SOURCE_DIR}/third_party/noise-c"
    0d86934919dc9220eaa49574bc9b22f0abe972b2)
dmp_require_revision("${DMP_SODIUM_SOURCE_DIR}"
    40c22448d6e8f42be56c45f739b52a5c8d21c8ca)
dmp_require_revision("${DMP_SODIUM_SOURCE_DIR}/libsodium"
    d24faf56214469b354b01c8ba36257e04737101e)

add_subdirectory("${DMP_SODIUM_SOURCE_DIR}" "${PROJECT_BINARY_DIR}/experiment-sodium")
set(NOISE_C_BUILD_TESTS ON CACHE BOOL "Run inherited candidate tests" FORCE)
set(NOISE_C_FIND_LIBSODIUM OFF CACHE BOOL "Use pinned experiment backend" FORCE)
add_subdirectory("${PROJECT_SOURCE_DIR}/third_party/noise-c"
    "${PROJECT_BINARY_DIR}/experiment-noise")
target_compile_definitions(noise_c PRIVATE NOISE_REQUIRE_SODIUM_FAST_PATH)

dmp_add_provider_experiment(dmp_noise_baseline_probe noise_baseline_probe.c)
target_link_libraries(dmp_noise_baseline_probe PRIVATE noise_c)
set_tests_properties(dmp_noise_baseline_probe PROPERTIES LABELS "expected-limitations")

find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
set(_fixture_header "${CMAKE_CURRENT_BINARY_DIR}/generated/noise_fixture_probe.h")
add_custom_command(OUTPUT "${_fixture_header}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/generate_noise_fixture_header.py"
        --input "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Security_Test_Vectors.json"
        --output "${_fixture_header}"
    DEPENDS generate_noise_fixture_header.py
        "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Security_Test_Vectors.json"
    VERBATIM)
dmp_add_provider_experiment(dmp_noise_fixture_probe noise_fixture_probe.c "${_fixture_header}")
target_include_directories(dmp_noise_fixture_probe PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(dmp_noise_fixture_probe PRIVATE noise_c)

dmp_add_provider_experiment(dmp_noise_pn_probe noise_pn_probe.c "${_fixture_header}")
target_include_directories(dmp_noise_pn_probe PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(dmp_noise_pn_probe PRIVATE noise_c)

dmp_add_provider_experiment(dmp_noise_dh_probe noise_dh_probe.c "${_fixture_header}")
target_include_directories(dmp_noise_dh_probe PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
    "${PROJECT_SOURCE_DIR}/third_party/noise-c/src")
target_link_libraries(dmp_noise_dh_probe PRIVATE noise_c)

# Separate library configuration: tests supply the checked entropy symbol.
# The inherited sodium-RNG regression library above is not a fallible port.
get_target_property(_noise_entropy_sources noise_c SOURCES)
list(TRANSFORM _noise_entropy_sources PREPEND "${PROJECT_SOURCE_DIR}/third_party/noise-c/")
add_library(dmp_noise_fallible_entropy STATIC ${_noise_entropy_sources})
target_include_directories(dmp_noise_fallible_entropy PUBLIC
    "${PROJECT_SOURCE_DIR}/third_party/noise-c/include"
    "${PROJECT_SOURCE_DIR}/third_party/noise-c/src")
target_compile_definitions(dmp_noise_fallible_entropy PUBLIC
    NOISE_USE_CUSTOM_RAND=1 NOISE_USE_SODIUM_RAND=0 NOISE_REQUIRE_FALLIBLE_RAND=1)
target_compile_definitions(dmp_noise_fallible_entropy PRIVATE NOISE_REQUIRE_SODIUM_FAST_PATH)
target_link_libraries(dmp_noise_fallible_entropy PUBLIC sodium)

dmp_add_provider_experiment(dmp_noise_rng_state_probe noise_rng_state_probe.c)
target_link_libraries(dmp_noise_rng_state_probe PRIVATE dmp_noise_fallible_entropy)
dmp_add_provider_experiment(dmp_noise_rng_handshake_probe
    noise_rng_handshake_probe.c "${_fixture_header}")
target_include_directories(dmp_noise_rng_handshake_probe PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(dmp_noise_rng_handshake_probe PRIVATE dmp_noise_fallible_entropy)
