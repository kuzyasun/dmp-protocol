get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../.." ABSOLUTE)

set(dmp_sources
    "${DMP_ROOT}/src/core/codec.c"
    "${DMP_ROOT}/src/integrity/crc32c.c")
if(DMP_SIZE_PROBE_STREAM_R OR DMP_SIZE_NONE_PROFILE)
    list(APPEND dmp_sources
        "${DMP_ROOT}/src/core/base.c"
        "${DMP_ROOT}/src/stream/cobs.c"
        "${DMP_ROOT}/src/stream/stream.c")
endif()
if(DMP_SIZE_NONE_PROFILE)
    list(APPEND dmp_sources
        "${DMP_ROOT}/src/identity/identity.c"
        "${DMP_ROOT}/src/identity/profile_admit.c"
        "${DMP_ROOT}/src/reassembly/reassembly.c"
        "${DMP_ROOT}/src/reliability/reliability.c"
        "${DMP_ROOT}/src/endpoint/endpoint.c")
endif()
if(DMP_SIZE_NONE_PROFILE STREQUAL "direct")
    list(APPEND dmp_sources
        "${DMP_ROOT}/src/application/sample1_epoch_owner.c"
        "${DMP_ROOT}/src/application/sample1_endpoint.c")
endif()

idf_component_register(SRCS ${dmp_sources}
    INCLUDE_DIRS "${DMP_ROOT}/include" "${DMP_ROOT}/src/application")
if(DMP_SIZE_NONE_PROFILE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        DMP_ENDPOINT_NONE_ONLY=1
        DMP_ENABLE_ENDPOINT_STREAM_R=$<BOOL:${DMP_ENABLE_ENDPOINT_STREAM_R}>)
endif()
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
