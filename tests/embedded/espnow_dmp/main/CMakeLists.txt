get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

idf_component_register(
    SRCS "main.c"
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
