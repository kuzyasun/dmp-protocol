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
    INCLUDE_DIRS "${DMP_ROOT}/include" "${DMP_ROOT}/src/application"
    PRIV_INCLUDE_DIRS
        "${DMP_ROOT}/third_party/noise-c/include"
        "${DMP_ROOT}/tests/provider/backend"
    REQUIRES nvs_flash)

target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
