foreach(probe IN ITEMS core core_stream_r)
    set(target dmp_size_${probe})
    add_executable(${target} codec_probe.c)
    target_link_libraries(${target} PRIVATE dmp::dmp)
    set_target_properties(${target} PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(${target})
    add_test(NAME size.${probe} COMMAND ${target})
    set_tests_properties(size.${probe} PROPERTIES TIMEOUT 10 LABELS "size-probe")
endforeach()

target_compile_definitions(dmp_size_core_stream_r PRIVATE DMP_SIZE_PROBE_STREAM_R=1)
