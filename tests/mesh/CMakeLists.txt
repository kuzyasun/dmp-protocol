add_executable(dmp_test_relay test_relay.c ../harness/harness.c)
target_link_libraries(dmp_test_relay PRIVATE dmp::dmp)
if(TARGET dmp_p01b_noise AND TARGET dmp_p01b_sodium)
    target_link_libraries(dmp_test_relay PRIVATE
        "$<LINK_GROUP:RESCAN,libdmp,dmp_p01b_noise,dmp_p01b_sodium>")
endif()
target_include_directories(dmp_test_relay PRIVATE
    "${CMAKE_SOURCE_DIR}/tests/harness"
    "${CMAKE_SOURCE_DIR}/src/security")
set_target_properties(dmp_test_relay PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_relay)
if(MSVC)
    target_compile_definitions(dmp_test_relay PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME relay.transparent COMMAND dmp_test_relay)
set_tests_properties(relay.transparent PROPERTIES TIMEOUT 60 LABELS "relay")
