get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

idf_component_register(
    SRCS
        "main.c"
        "qual_console_line.c"
        "qual_handshake_frame.c"
        "qual_handshake_readiness.c"
        "qual_tx_completion.c"
        "qual_transport_outcome.c"
        "${DMP_ROOT}/tests/provider/noise_checked_no_legacy_rng.c"
    INCLUDE_DIRS
        "."
        "${DMP_ROOT}/include"
        "${DMP_ROOT}/src/application"
        "${DMP_ROOT}/src/security"
        "${DMP_ROOT}/tests/provider/backend"
    REQUIRES
        dmp
        esp_event
        esp_netif
        esp_timer
        esp_wifi
        nvs_flash
)

target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
target_link_options(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=randombytes_stir"
    "-Wl,--wrap=randombytes_buf")
