add_executable(dmp_test_endpoint test_endpoint.c)
target_link_libraries(dmp_test_endpoint PRIVATE dmp::dmp)
set_target_properties(dmp_test_endpoint PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_endpoint)
if(MSVC)
    target_compile_definitions(dmp_test_endpoint PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

foreach(name sample1 sample_snapshot fragment fragment_replay fragment_tlv retry duplicate quota sample_no_sample sample_init_budget sample_same_epoch sample_new_epoch sample_late_assoc sample_superseded sample_invalid)
    add_test(NAME endpoint.${name} COMMAND dmp_test_endpoint ${name})
    set_tests_properties(endpoint.${name} PROPERTIES TIMEOUT 30 LABELS "endpoint")
endforeach()
