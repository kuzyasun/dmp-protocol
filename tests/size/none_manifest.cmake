function(dmp_configure_none_probe target kind)
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    set(probe_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")
    get_filename_component(root "${probe_dir}/../.." ABSOLUTE)
    set(manifest "${root}/profiles/deployments/${kind}-none.json")
    set(header_dir "${CMAKE_CURRENT_BINARY_DIR}/${target}-manifest")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${manifest}" "${root}/profiles/deployments/digests.json"
        "${probe_dir}/generate_none_manifest.py"
        "${root}/tests/identity/parity_drive.py"
        "${root}/tools/validate_profile.py" "${root}/profiles/schema/manifest-v1.schema.json")
    file(MAKE_DIRECTORY "${header_dir}")
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -B "${probe_dir}/generate_none_manifest.py"
            "${manifest}" "${header_dir}/none_manifest.h"
        RESULT_VARIABLE generated)
    if(NOT generated EQUAL 0)
        message(FATAL_ERROR "Could not generate the ${kind}-none workload config")
    endif()
    target_include_directories(${target} PRIVATE "${header_dir}")
    target_compile_definitions(${target} PRIVATE DMP_NONE_MANIFEST_PROBE=1)
    if(kind STREQUAL "direct")
        target_compile_definitions(${target} PRIVATE
            SAMPLE_FRAMING_MODE=DMP_ENDPOINT_FRAMING_STREAM_R)
    elseif(NOT DMP_ENABLE_ENDPOINT_STREAM_R)
        target_compile_definitions(${target} PRIVATE DMP_NONE_PACKET_ONLY_PROBE=1)
    endif()
endfunction()
