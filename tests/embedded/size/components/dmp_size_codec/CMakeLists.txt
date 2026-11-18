get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../.." ABSOLUTE)

set(dmp_sources
    "${DMP_ROOT}/src/core/codec.c"
    "${DMP_ROOT}/src/integrity/crc32c.c")
if(DMP_SIZE_PROBE_STREAM_R)
    list(APPEND dmp_sources
        "${DMP_ROOT}/src/core/base.c"
        "${DMP_ROOT}/src/stream/cobs.c"
        "${DMP_ROOT}/src/stream/stream.c")
endif()

idf_component_register(SRCS ${dmp_sources} INCLUDE_DIRS "${DMP_ROOT}/include")
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
