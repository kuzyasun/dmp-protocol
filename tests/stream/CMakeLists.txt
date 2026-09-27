add_executable(dmp_test_stream test_stream.c)
target_link_libraries(dmp_test_stream PRIVATE dmp::dmp)
target_include_directories(dmp_test_stream PRIVATE "${PROJECT_SOURCE_DIR}/src/stream")
set_target_properties(dmp_test_stream PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_stream)
add_test(NAME stream.framing COMMAND dmp_test_stream)
set_tests_properties(stream.framing PROPERTIES TIMEOUT 20 LABELS "stream-framing")
