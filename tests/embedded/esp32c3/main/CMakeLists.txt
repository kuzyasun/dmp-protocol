idf_component_register(
    SRCS "${CMAKE_CURRENT_LIST_DIR}/../../esp32s3/main/main.c"
    REQUIRES dmp)
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
