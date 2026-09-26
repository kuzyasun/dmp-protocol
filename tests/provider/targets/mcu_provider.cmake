# Isolated MCU-01 experiment only; never included by the DMP library build.
function(dmp_add_mcu_provider)
    if(NOT DMP_MCU_TEST_ONLY)
        message(FATAL_ERROR "This target contains public deterministic test keys; set DMP_MCU_TEST_ONLY=ON")
    endif()
    get_filename_component(_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../../.." ABSOLUTE)
    set(_provider "${_root}/tests/provider")
    if(NOT IS_DIRECTORY "${DMP_SODIUM_SOURCE_DIR}/libsodium")
        message(FATAL_ERROR "Set DMP_SODIUM_SOURCE_DIR to the prepared pinned backend")
    endif()
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    find_package(Git REQUIRED)
    foreach(_pair
        "${_root}/third_party/noise-c|c40f2dca78eee064e521233a5d884853d471028a"
        "${DMP_SODIUM_SOURCE_DIR}|40c22448d6e8f42be56c45f739b52a5c8d21c8ca"
        "${DMP_SODIUM_SOURCE_DIR}/libsodium|d24faf56214469b354b01c8ba36257e04737101e")
        string(REPLACE "|" ";" _parts "${_pair}")
        list(GET _parts 0 _directory)
        list(GET _parts 1 _expected)
        execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${_directory}" rev-parse HEAD
            OUTPUT_VARIABLE _actual OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE _result)
        if(NOT _result EQUAL 0 OR NOT _actual STREQUAL _expected)
            message(FATAL_ERROR "Unexpected source revision at ${_directory}: ${_actual}")
        endif()
    endforeach()
    set(_checked "${CMAKE_CURRENT_BINARY_DIR}/checked-sodium")
    execute_process(COMMAND "${Python3_EXECUTABLE}" "${_provider}/backend/prepare_checked_sodium.py"
        --source "${DMP_SODIUM_SOURCE_DIR}" --output "${_checked}"
        RESULT_VARIABLE _result OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
    if(NOT _result EQUAL 0)
        message(FATAL_ERROR "Checked startup preparation failed: ${_out}${_err}")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${_provider}/backend/checked-init.patch" "${_provider}/backend/inputs.json"
        "${_provider}/backend/prepare_checked_sodium.py"
        "${DMP_SODIUM_SOURCE_DIR}/libsodium/src/libsodium/sodium/core.c"
        "${DMP_SODIUM_SOURCE_DIR}/libsodium/src/libsodium/sodium/utils.c")

    # Use the existing generic source inventories, not the upstream IDF component
    # branch which disables the protocol table and therefore excludes XX.
    # Function scope leaves the surrounding IDF build's ESP_PLATFORM unchanged.
    set(ESP_PLATFORM OFF)
    set(NOISE_C_BUILD_TESTS OFF CACHE BOOL "No inherited host executables" FORCE)
    set(NOISE_C_FIND_LIBSODIUM OFF CACHE BOOL "Use pinned local backend" FORCE)
    add_subdirectory("${DMP_SODIUM_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/sodium")
    get_target_property(_sources sodium SOURCES)
    list(TRANSFORM _sources PREPEND "${DMP_SODIUM_SOURCE_DIR}/")
    foreach(_file core utils)
        list(REMOVE_ITEM _sources "${DMP_SODIUM_SOURCE_DIR}/libsodium/src/libsodium/sodium/${_file}.c")
        list(APPEND _sources "${_checked}/libsodium/src/libsodium/sodium/${_file}.c")
    endforeach()
    set_property(TARGET sodium PROPERTY SOURCES "${_sources}")
    target_include_directories(sodium PRIVATE "${_provider}/backend")
    target_compile_definitions(sodium PRIVATE DMP_SODIUM_CHECKED_INIT=1)
    add_subdirectory("${_root}/third_party/noise-c" "${CMAKE_CURRENT_BINARY_DIR}/noise")
    target_compile_definitions(noise_c PUBLIC
        NOISE_USE_CUSTOM_ALLOCATOR=1 NOISE_USE_CUSTOM_RAND=1 NOISE_USE_SODIUM_RAND=0
        NOISE_REQUIRE_FALLIBLE_RAND=1 NOISE_USE_PTHREAD=0
        NOISE_USE_PROTOCOL_NAME_TABLE=1 NOISE_USE_FALLBACK=1 NOISE_USE_HFS=1)
    target_compile_definitions(noise_c PRIVATE NOISE_REQUIRE_SODIUM_FAST_PATH)

    set(_fixture "${CMAKE_CURRENT_BINARY_DIR}/generated/noise_fixture_probe.h")
    add_custom_command(OUTPUT "${_fixture}"
        COMMAND "${Python3_EXECUTABLE}" "${_provider}/generate_noise_fixture_header.py"
            --input "${_root}/docs/DMP_v2_Security_Test_Vectors.json" --output "${_fixture}"
        DEPENDS "${_provider}/generate_noise_fixture_header.py"
            "${_root}/docs/DMP_v2_Security_Test_Vectors.json" VERBATIM)
    add_library(dmp_mcu_fixture STATIC
        "${_provider}/noise_allocator_probe.c" "${_provider}/noise_test_arena.c"
        "${_provider}/noise_fixture_probe.c" "${_provider}/noise_checked_fixture_port.c"
        "${_provider}/noise_checked_no_legacy_rng.c" "${_fixture}")
    set_source_files_properties("${_provider}/noise_allocator_probe.c" PROPERTIES
        COMPILE_DEFINITIONS "main=dmp_mcu_fixture_main")
    target_include_directories(dmp_mcu_fixture PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated"
        "${_provider}/backend")
    target_compile_definitions(dmp_mcu_fixture PRIVATE
        DMP_TEST_NOISE_ENTROPY_PORT=1 DMP_NOISE_FIXTURE_EMBEDDED_RUNNER=1)
    target_link_libraries(dmp_mcu_fixture PUBLIC noise_c)
    target_link_options(dmp_mcu_fixture INTERFACE
        "-Wl,--wrap=randombytes_stir" "-Wl,--wrap=randombytes_buf")
    foreach(_target noise_c sodium dmp_mcu_fixture)
        set_target_properties(${_target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES)
        target_compile_options(${_target} PRIVATE -ffunction-sections -fdata-sections -fstack-usage)
    endforeach()
    target_compile_options(noise_c PRIVATE -fno-strict-aliasing)
    target_compile_options(dmp_mcu_fixture PRIVATE -fno-strict-aliasing -Wall -Wextra -Werror)
endfunction()
