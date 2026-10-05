add_library(dmp_test_workloads STATIC opaque.c)
target_include_directories(dmp_test_workloads PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(dmp_test_workloads PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_workloads)

add_executable(dmp_test_opaque_len opaque_selfcheck.c)
target_link_libraries(dmp_test_opaque_len PRIVATE dmp_test_workloads)
set_target_properties(dmp_test_opaque_len PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_opaque_len)
add_test(NAME workloads.opaque_len COMMAND dmp_test_opaque_len)
set_tests_properties(workloads.opaque_len PROPERTIES TIMEOUT 10 LABELS "workload")
