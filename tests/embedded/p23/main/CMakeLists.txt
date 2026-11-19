get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
set(fixture "${CMAKE_CURRENT_BINARY_DIR}/noise_fixture_probe.h")
set(profile "${CMAKE_CURRENT_BINARY_DIR}/p23_target_profile.h")
set(manifest "${DMP_ROOT}/profiles/deployments/${DMP_P23_PROFILE}.json")
set(digests "${DMP_ROOT}/profiles/deployments/digests.json")
set(vectors "${DMP_ROOT}/docs/DMP_v2_Security_Test_Vectors.json")
set(fixture_generator "${DMP_ROOT}/tests/provider/generate_noise_fixture_header.py")
set(profile_generator "${CMAKE_CURRENT_LIST_DIR}/../generate_profile.py")

idf_component_register(SRCS
    "${DMP_ROOT}/tests/endpoint/test_endpoint_sec.c"
    "${DMP_ROOT}/tests/provider/noise_checked_no_legacy_rng.c"
    "p23_uart.c"
    PRIV_REQUIRES dmp esp_driver_uart)

find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
add_custom_command(OUTPUT "${fixture}"
    COMMAND "${Python3_EXECUTABLE}" -B "${fixture_generator}" --input "${vectors}" --output "${fixture}"
    DEPENDS "${fixture_generator}" "${vectors}"
    VERBATIM)
add_custom_command(OUTPUT "${profile}"
    COMMAND "${Python3_EXECUTABLE}" -B "${profile_generator}" "${manifest}" "${profile}"
    DEPENDS "${profile_generator}" "${manifest}" "${digests}"
        "${DMP_ROOT}/tests/identity/parity_drive.py"
        "${DMP_ROOT}/tools/validate_profile.py"
        "${DMP_ROOT}/profiles/schema/manifest-v1.schema.json"
    VERBATIM)
target_sources(${COMPONENT_LIB} PRIVATE "${fixture}" "${profile}")
target_include_directories(${COMPONENT_LIB} PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_BINARY_DIR}" "${DMP_ROOT}/src/security")
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_definitions(${COMPONENT_LIB} PRIVATE DMP_P23_TARGET=1)
# The shared translation unit also contains the separate host scenario entry points.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror -Wno-unused-function)
target_link_options(${COMPONENT_LIB} INTERFACE -Wl,--wrap=randombytes_stir -Wl,--wrap=randombytes_buf)
