if(NOT TARGET dmp_p01b_noise OR NOT TARGET dmp_p01b_sodium)
    message(STATUS "P19 recovery gate is not registered; sodium targets are absent")
    return()
endif()

set(_p19_fixture "${CMAKE_CURRENT_BINARY_DIR}/noise_fixture_probe.h")
add_custom_command(OUTPUT "${_p19_fixture}"
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/provider/generate_noise_fixture_header.py"
        --input "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Security_Test_Vectors.json"
        --output "${_p19_fixture}"
    DEPENDS "${PROJECT_SOURCE_DIR}/tests/provider/generate_noise_fixture_header.py"
        "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Security_Test_Vectors.json"
    VERBATIM)

add_executable(dmp_test_recovery_gate recovery_gate.c "${_p19_fixture}"
    "${PROJECT_SOURCE_DIR}/tests/harness/harness.c")
target_include_directories(dmp_test_recovery_gate PRIVATE
    "${PROJECT_SOURCE_DIR}/src/security"
    "${PROJECT_SOURCE_DIR}/tests/endpoint"
    "${PROJECT_SOURCE_DIR}/tests/harness"
    "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(dmp_test_recovery_gate PRIVATE dmp_test_workloads
    "$<LINK_GROUP:RESCAN,libdmp,dmp_p01b_noise,dmp_p01b_sodium>")
set_target_properties(dmp_test_recovery_gate PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_recovery_gate)
if(MSVC)
    target_compile_definitions(dmp_test_recovery_gate PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

foreach(name geometry r6 r7 retry_all relay_sample feedback gaps pn_limit async async_radio freshness)
    add_test(NAME scenarios.${name} COMMAND dmp_test_recovery_gate ${name})
    set_tests_properties(scenarios.${name} PROPERTIES TIMEOUT 120 LABELS "recovery;scenario")
endforeach()
