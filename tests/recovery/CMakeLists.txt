set(frag_header "${CMAKE_CURRENT_BINARY_DIR}/frag_status_cases.h")
add_custom_command(OUTPUT "${frag_header}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/emit_frag_status_cases.py"
        "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Recovery_Test_Vectors.json" "${frag_header}"
    DEPENDS emit_frag_status_cases.py
        "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Recovery_Test_Vectors.json"
    VERBATIM)
add_executable(dmp_test_frag_status_vectors test_frag_status_vectors.c "${frag_header}")
target_include_directories(dmp_test_frag_status_vectors PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(dmp_test_frag_status_vectors PRIVATE dmp::dmp)
set_target_properties(dmp_test_frag_status_vectors PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_frag_status_vectors)
add_test(NAME recovery.frag_status COMMAND dmp_test_frag_status_vectors)
set_tests_properties(recovery.frag_status PROPERTIES TIMEOUT 30 LABELS "recovery;fixture-only")
