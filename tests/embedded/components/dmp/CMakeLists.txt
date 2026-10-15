get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

idf_component_register(
    SRCS
        "${DMP_ROOT}/src/core/base.c"
        "${DMP_ROOT}/src/core/codec.c"
        "${DMP_ROOT}/src/integrity/crc32c.c"
        "${DMP_ROOT}/src/stream/cobs.c"
        "${DMP_ROOT}/src/stream/stream.c"
        "${DMP_ROOT}/src/identity/identity.c"
        "${DMP_ROOT}/src/identity/profile_admit.c"
        "${DMP_ROOT}/src/reassembly/reassembly.c"
        "${DMP_ROOT}/src/reliability/reliability.c"
        "${DMP_ROOT}/src/endpoint/endpoint.c"
        "${DMP_ROOT}/src/mesh/relay.c"
        "${DMP_ROOT}/src/security/provider_adapter.c"
        "${DMP_ROOT}/src/security/replay_window.c"
        "${DMP_ROOT}/src/security/handshake.c"
        "${DMP_ROOT}/src/security/handshake_transport.c"
        "${DMP_ROOT}/src/application/sample1_epoch_owner.c"
        "${DMP_ROOT}/src/application/sample1_endpoint.c"
        "${DMP_ROOT}/src/application/sample1_epoch_store.c"
        "${DMP_ROOT}/src/application/sample1_epoch_anchor_nvs.c"
        "${DMP_ROOT}/tests/embedded/components/dmp/prehardware_link_probe.c"
    INCLUDE_DIRS "${DMP_ROOT}/include" "${DMP_ROOT}/src/application"
    PRIV_INCLUDE_DIRS
        "${DMP_ROOT}/src/security"
        "${DMP_ROOT}/tests/provider/backend"
    REQUIRES nvs_flash
    PRIV_REQUIRES noise-c)

target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)

# Match the checked host provider: Noise must use the DMP allocator and checked
# entropy ports, and retain both NNpsk0 and XX patterns for the S3/C3 link gate.
idf_component_get_property(DMP_NOISE_COMPONENT_LIB noise-c COMPONENT_LIB)
get_target_property(DMP_NOISE_COMPILE_DEFINITIONS
    ${DMP_NOISE_COMPONENT_LIB} COMPILE_DEFINITIONS)
if(DMP_NOISE_COMPILE_DEFINITIONS)
    list(REMOVE_ITEM DMP_NOISE_COMPILE_DEFINITIONS
        NOISE_USE_PROTOCOL_NAME_TABLE=0 NOISE_USE_FALLBACK=0 NOISE_USE_HFS=0)
endif()
set_target_properties(${DMP_NOISE_COMPONENT_LIB} PROPERTIES
    COMPILE_DEFINITIONS "${DMP_NOISE_COMPILE_DEFINITIONS}")
target_compile_definitions(${DMP_NOISE_COMPONENT_LIB} PRIVATE
    NOISE_USE_CUSTOM_RAND=1 NOISE_USE_SODIUM_RAND=0 NOISE_REQUIRE_FALLIBLE_RAND=1
    NOISE_USE_CUSTOM_ALLOCATOR=1 NOISE_USE_LIBSODIUM=1 NOISE_USE_REFERENCE_BACKEND=0
    NOISE_USE_AES=0 NOISE_USE_OPENSSL=0 NOISE_USE_PTHREAD=0
    NOISE_REQUIRE_SODIUM_FAST_PATH
    NOISE_USE_PROTOCOL_NAME_TABLE=1 NOISE_USE_FALLBACK=1 NOISE_USE_HFS=1)
