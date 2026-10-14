add_executable(dmp_test_endpoint test_endpoint.c)
target_link_libraries(dmp_test_endpoint PRIVATE dmp::dmp)
set_target_properties(dmp_test_endpoint PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)

# Keep the host SAMPLE-1 state-machine checks tied to the selected deployment
# manifest instead of copying application initialization budgets into C.
set(_sample_manifest "${PROJECT_SOURCE_DIR}/profiles/deployments/direct-nnpsk0.json")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_sample_manifest}")
file(READ "${_sample_manifest}" _sample_manifest_json)
string(JSON _sample_init_attempts GET "${_sample_manifest_json}" sample init_attempts)
string(JSON _sample_init_retry_ms GET "${_sample_manifest_json}" sample init_retry_ms)
string(JSON _sample_init_deadline_ms GET "${_sample_manifest_json}" sample init_deadline_ms)
string(JSON _sample_no_sample_status GET "${_sample_manifest_json}" sample no_sample_status)
string(JSON _sample_result_deadline_ms GET "${_sample_manifest_json}" timing result_deadline_ms)
target_compile_definitions(dmp_test_endpoint PRIVATE
    SAMPLE_INIT_ATTEMPTS=${_sample_init_attempts}
    SAMPLE_INIT_RETRY_MS=${_sample_init_retry_ms}
    SAMPLE_INIT_DEADLINE_MS=${_sample_init_deadline_ms}
    SAMPLE_RESULT_DEADLINE_MS=${_sample_result_deadline_ms}
    SAMPLE_NO_SAMPLE=${_sample_no_sample_status})
dmp_strict_target(dmp_test_endpoint)
if(MSVC)
    target_compile_definitions(dmp_test_endpoint PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

foreach(name sample1 packet single_frame_profile sample_snapshot fragment fragment_replay fragment_tlv retry result_loss receipt_loss duplicate quota sample_no_sample sample_init_budget sample_same_epoch sample_new_epoch sample_late_assoc sample_superseded sample_invalid sample_epoch_restart sample_epoch_fail sample_epoch_indeterminate sample_epoch_index_exhaustion)
    add_test(NAME endpoint.${name} COMMAND dmp_test_endpoint ${name})
    set_tests_properties(endpoint.${name} PROPERTIES TIMEOUT 30 LABELS "endpoint")
endforeach()
