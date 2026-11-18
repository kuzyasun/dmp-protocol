get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

idf_component_register(SRCS "${DMP_ROOT}/tests/size/codec_probe.c"
                       PRIV_REQUIRES dmp_size_codec)
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
if(DMP_SIZE_PROBE_STREAM_R)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DMP_SIZE_PROBE_STREAM_R=1)
endif()
