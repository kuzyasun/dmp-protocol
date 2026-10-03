add_executable(dmp-harness main.c scenario.c harness.c manifest.c json.c sha256.c)
target_link_libraries(dmp-harness PRIVATE dmp::dmp)
target_compile_definitions(dmp-harness PRIVATE
    DMP_MANIFEST_SCHEMA_PATH="${PROJECT_SOURCE_DIR}/profiles/schema/manifest-v2.schema.json")
set_target_properties(dmp-harness PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp-harness)
if(MSVC)
    target_compile_definitions(dmp-harness PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(dmp_test_harness_port test_port.c scenario.c harness.c manifest.c json.c sha256.c)
target_link_libraries(dmp_test_harness_port PRIVATE dmp::dmp)
target_compile_definitions(dmp_test_harness_port PRIVATE
    DMP_MANIFEST_SCHEMA_PATH="${PROJECT_SOURCE_DIR}/profiles/schema/manifest-v2.schema.json")
set_target_properties(dmp_test_harness_port PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_harness_port)
if(MSVC)
    target_compile_definitions(dmp_test_harness_port PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

add_test(NAME harness.port COMMAND dmp_test_harness_port)
set_tests_properties(harness.port PROPERTIES TIMEOUT 60 LABELS "harness")

add_test(NAME harness.subprocess
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_harness.py"
            "$<TARGET_FILE:dmp-harness>")
set_tests_properties(harness.subprocess PROPERTIES TIMEOUT 180 LABELS "harness")
