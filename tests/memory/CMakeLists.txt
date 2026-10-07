# One-device P01B provider measurement plus host/MCU layout reconciliation.
add_test(NAME memory.ram_report_unit
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_ram_report.py")
set_tests_properties(memory.ram_report_unit PROPERTIES TIMEOUT 30 LABELS memory)

if(NOT TARGET dmp_p01b_noise OR NOT TARGET dmp_p01b_sodium)
    message(STATUS "RAM measurement not registered; P01B provider targets are absent")
    return()
endif()

set(_fixture "${CMAKE_BINARY_DIR}/tests/security/noise_fixture_probe.h")
add_executable(dmp_ram_measure ram_measure.c "${_fixture}")
add_dependencies(dmp_ram_measure dmp_test_provider)
target_include_directories(dmp_ram_measure PRIVATE
    "${PROJECT_SOURCE_DIR}/src/security"
    "${CMAKE_BINARY_DIR}/tests/security")
target_link_libraries(dmp_ram_measure PRIVATE
    "$<LINK_GROUP:RESCAN,libdmp,dmp_p01b_noise,dmp_p01b_sodium>")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(dmp_ram_measure PRIVATE pthread)
endif()
set_target_properties(dmp_ram_measure PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_ram_measure)
if(MSVC)
    target_compile_definitions(dmp_ram_measure PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Runnable endpoint initialization milestone. This does not claim lifecycle
# memory phases beyond initial construction; those remain in the report tool's
# fail-closed not_measured state until the process-isolated peer harness lands.
add_executable(dmp_ram_endpoint_initial ram_endpoint_measure.c)
add_dependencies(dmp_ram_endpoint_initial dmp_test_provider)
target_include_directories(dmp_ram_endpoint_initial PRIVATE
    "${PROJECT_SOURCE_DIR}/src/security")
target_link_libraries(dmp_ram_endpoint_initial PRIVATE
    "$<LINK_GROUP:RESCAN,libdmp,dmp_p01b_noise,dmp_p01b_sodium>")
set_target_properties(dmp_ram_endpoint_initial PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_ram_endpoint_initial)
if(MSVC)
    target_compile_definitions(dmp_ram_endpoint_initial PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
foreach(_profile test-direct-minimal-128 test-direct-minimal-256)
    add_test(NAME memory.${_profile}.endpoint_initial
        COMMAND dmp_ram_endpoint_initial
            --manifest "${PROJECT_SOURCE_DIR}/profiles/deployments/${_profile}.json")
    set_tests_properties(memory.${_profile}.endpoint_initial PROPERTIES
        TIMEOUT 30 LABELS memory)
endforeach()

add_executable(dmp_ram_endpoint_process ram_endpoint_process.c "${_fixture}"
    "${PROJECT_SOURCE_DIR}/tests/harness/sha256.c")
add_dependencies(dmp_ram_endpoint_process dmp_test_provider)
target_include_directories(dmp_ram_endpoint_process PRIVATE
    "${PROJECT_SOURCE_DIR}/src/security"
    "${PROJECT_SOURCE_DIR}/tests/harness"
    "${CMAKE_BINARY_DIR}/tests/security")
target_link_libraries(dmp_ram_endpoint_process PRIVATE
    "$<LINK_GROUP:RESCAN,libdmp,dmp_p01b_noise,dmp_p01b_sodium>")
if(WIN32)
    target_link_libraries(dmp_ram_endpoint_process PRIVATE ws2_32)
endif()
set_target_properties(dmp_ram_endpoint_process PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_ram_endpoint_process)
if(MSVC)
    target_compile_definitions(dmp_ram_endpoint_process PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
foreach(_profile test-direct-minimal-128 test-direct-minimal-256)
    add_test(NAME memory.${_profile}.endpoint_lifecycle
        COMMAND dmp_ram_endpoint_process
            --manifest "${PROJECT_SOURCE_DIR}/profiles/deployments/${_profile}.json")
    set_tests_properties(memory.${_profile}.endpoint_lifecycle PROPERTIES
        TIMEOUT 60 LABELS memory)
endforeach()

set(_profiles direct-nnpsk0 direct-nnpsk0-async radio-nnpsk0 radio-nnpsk0-n2
    test-radio-retry-all-nnpsk0 test-direct-minimal-128 test-direct-minimal-256)
foreach(_profile IN LISTS _profiles)
    set(_measure "${CMAKE_CURRENT_BINARY_DIR}/${_profile}.json")
    set(_report "${CMAKE_CURRENT_BINARY_DIR}/${_profile}-report.json")
    set(_layout "${CMAKE_CURRENT_BINARY_DIR}/${_profile}-layout.json")
    add_test(NAME memory.${_profile}
        COMMAND dmp_ram_measure
            --manifest "${PROJECT_SOURCE_DIR}/profiles/deployments/${_profile}.json"
            --output "${_measure}")
    add_test(NAME memory.${_profile}.report
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tools/ram_report.py"
            --manifest "${PROJECT_SOURCE_DIR}/profiles/deployments/${_profile}.json"
            --measurement "${_measure}"
            --output "${_report}"
            --check)
    add_test(NAME memory.${_profile}.layout
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tools/ram_layout.py"
            --manifest "${PROJECT_SOURCE_DIR}/profiles/deployments/${_profile}.json"
            --measurement "${_measure}"
            --mcu-abi "${CMAKE_CURRENT_BINARY_DIR}/mcu-abi.json"
            --output "${_layout}"
            --check)
    set_tests_properties(memory.${_profile} PROPERTIES
        TIMEOUT 120 LABELS memory
        ENVIRONMENT "RAM_BUILD_TYPE=${CMAKE_BUILD_TYPE};RAM_C_FLAGS=${CMAKE_C_FLAGS}")
    set_tests_properties(memory.${_profile}.report PROPERTIES
        TIMEOUT 30 LABELS memory DEPENDS memory.${_profile})
    set_tests_properties(memory.${_profile}.layout PROPERTIES
        TIMEOUT 30 LABELS memory)
endforeach()

find_program(DMP_ARM_NONE_EABI_GCC arm-none-eabi-gcc)
if(DMP_ARM_NONE_EABI_GCC)
    set(_mcu_cc "${DMP_ARM_NONE_EABI_GCC}")
else()
    set(_mcu_cc "")
endif()
add_test(NAME memory.mcu_abi
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tools/ram_mcu_abi.py"
        --source-root "${PROJECT_SOURCE_DIR}"
        --layout "${CMAKE_CURRENT_SOURCE_DIR}/mcu_layout.c"
        --output "${CMAKE_CURRENT_BINARY_DIR}/mcu-abi.json"
        --work "${CMAKE_CURRENT_BINARY_DIR}/mcu"
        --cc "${_mcu_cc}")
set_tests_properties(memory.mcu_abi PROPERTIES TIMEOUT 180 LABELS memory)
foreach(_profile IN LISTS _profiles)
    set_tests_properties(memory.${_profile}.layout PROPERTIES
        DEPENDS "memory.${_profile};memory.mcu_abi")
endforeach()
