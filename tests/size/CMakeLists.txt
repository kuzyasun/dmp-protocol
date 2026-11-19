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

if(NOT DMP_ENABLE_ENDPOINT_STREAM_R AND CMAKE_NM AND NOT MSVC)
    add_test(NAME size.none_packet_symbols
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/endpoint/check_none_link_symbols.py" --packet
            "${CMAKE_NM}" "$<TARGET_FILE:dmp_size_none_radio>")
    set_tests_properties(size.none_packet_symbols PROPERTIES TIMEOUT 30 LABELS "size-probe;none;link")
endif()

target_compile_definitions(dmp_size_core_stream_r PRIVATE DMP_SIZE_PROBE_STREAM_R=1)

include(none_manifest.cmake)
foreach(kind IN ITEMS direct radio)
    set(target dmp_size_none_${kind})
    if(kind STREQUAL "direct")
        if(NOT DMP_ENABLE_ENDPOINT_STREAM_R)
            continue()
        endif()
        set(workload ../endpoint/test_sample1_none.c)
    else()
        set(workload ../endpoint/test_radio_none_selective.c)
    endif()
    add_executable(${target} "${workload}")
    target_link_libraries(${target} PRIVATE dmp::sample1_none)
    set_target_properties(${target} PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(${target})
    dmp_configure_none_probe(${target} "${kind}")
    add_test(NAME size.none_${kind} COMMAND ${target})
    set_tests_properties(size.none_${kind} PROPERTIES TIMEOUT 30 LABELS "size-probe;none")
endforeach()
