add_executable(dmp_test_identity test_identity.c auth_context_stub.c)
target_link_libraries(dmp_test_identity PRIVATE dmp::dmp)
set_target_properties(dmp_test_identity PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_identity)
if(MSVC)
    target_compile_definitions(dmp_test_identity PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME identity.context COMMAND dmp_test_identity)
set_tests_properties(identity.context PROPERTIES TIMEOUT 20 LABELS "identity")

add_executable(dmp_test_profile_admit test_profile_admit.c)
target_link_libraries(dmp_test_profile_admit PRIVATE dmp::dmp)
target_compile_definitions(dmp_test_profile_admit PRIVATE
    DMP_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
set_target_properties(dmp_test_profile_admit PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_profile_admit)
if(MSVC)
    target_compile_definitions(dmp_test_profile_admit PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME identity.profile_admit COMMAND dmp_test_profile_admit)
set_tests_properties(identity.profile_admit PROPERTIES TIMEOUT 30 LABELS "identity")

add_test(NAME identity.profile_parity
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/parity_drive.py"
            "$<TARGET_FILE:dmp_test_profile_admit>")
set_tests_properties(identity.profile_parity PROPERTIES
    TIMEOUT 180 LABELS "identity;profile-validator")
