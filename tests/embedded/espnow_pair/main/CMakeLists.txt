get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

idf_component_register(
    SRCS
        "main.c"
        "${DMP_ROOT}/src/core/base.c"
        "${DMP_ROOT}/src/core/codec.c"
        "${DMP_ROOT}/src/integrity/crc32c.c"
    INCLUDE_DIRS "${DMP_ROOT}/include"
    REQUIRES esp_event esp_netif esp_timer esp_wifi)

target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
