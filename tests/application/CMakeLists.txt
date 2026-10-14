add_executable(dmp_test_sample1_epoch_owner test_sample1_epoch_owner.c)
target_link_libraries(dmp_test_sample1_epoch_owner PRIVATE dmp::sample1)
set_target_properties(dmp_test_sample1_epoch_owner PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_sample1_epoch_owner)
if(MSVC)
    target_compile_definitions(dmp_test_sample1_epoch_owner PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME application.sample1_epoch_owner COMMAND dmp_test_sample1_epoch_owner)
set_tests_properties(application.sample1_epoch_owner PROPERTIES
    TIMEOUT 30 LABELS "application;sample1")

add_executable(dmp_test_sample1_epoch_store test_sample1_epoch_store.c)
target_link_libraries(dmp_test_sample1_epoch_store PRIVATE dmp::sample1)
set_target_properties(dmp_test_sample1_epoch_store PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_sample1_epoch_store)
if(MSVC)
    target_compile_definitions(dmp_test_sample1_epoch_store PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME application.sample1_epoch_store COMMAND dmp_test_sample1_epoch_store)
set_tests_properties(application.sample1_epoch_store PROPERTIES
    TIMEOUT 30 LABELS "application;sample1")

add_executable(dmp_test_sample1_epoch_anchor_nvs test_sample1_epoch_anchor_nvs.c)
target_link_libraries(dmp_test_sample1_epoch_anchor_nvs PRIVATE dmp::sample1)
set_target_properties(dmp_test_sample1_epoch_anchor_nvs PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_sample1_epoch_anchor_nvs)
if(MSVC)
    target_compile_definitions(dmp_test_sample1_epoch_anchor_nvs PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME application.sample1_epoch_anchor_nvs COMMAND dmp_test_sample1_epoch_anchor_nvs)
set_tests_properties(application.sample1_epoch_anchor_nvs PROPERTIES
    TIMEOUT 30 LABELS "application;sample1")
