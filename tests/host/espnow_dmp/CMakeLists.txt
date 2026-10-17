add_test(NAME host.espnow_dmp.serial_stub
    COMMAND "${Python3_EXECUTABLE}" -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}" -p "test_*.py" -v)
set_tests_properties(host.espnow_dmp.serial_stub PROPERTIES
    LABELS "host;espnow-dmp;stub" TIMEOUT 30)

add_executable(dmp_test_qual_console_line
    test_qual_console_line.c
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main/qual_console_line.c")
target_include_directories(dmp_test_qual_console_line PRIVATE
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main")
set_target_properties(dmp_test_qual_console_line PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_qual_console_line)
add_test(NAME host.espnow_dmp.console_line
    COMMAND dmp_test_qual_console_line)
set_tests_properties(host.espnow_dmp.console_line PROPERTIES
    LABELS "host;espnow-dmp;stub" TIMEOUT 10)

add_executable(dmp_test_qual_handshake_frame
    test_qual_handshake_frame.c
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main/qual_handshake_frame.c")
target_include_directories(dmp_test_qual_handshake_frame PRIVATE
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main")
target_link_libraries(dmp_test_qual_handshake_frame PRIVATE dmp::dmp)
set_target_properties(dmp_test_qual_handshake_frame PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_qual_handshake_frame)
add_test(NAME host.espnow_dmp.handshake_frame
    COMMAND dmp_test_qual_handshake_frame)
set_tests_properties(host.espnow_dmp.handshake_frame PROPERTIES
    LABELS "host;espnow-dmp;security" TIMEOUT 10)

add_executable(dmp_test_qual_transport_outcome
    test_qual_transport_outcome.c
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main/qual_transport_outcome.c")
target_include_directories(dmp_test_qual_transport_outcome PRIVATE
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main")
target_link_libraries(dmp_test_qual_transport_outcome PRIVATE dmp::dmp)
set_target_properties(dmp_test_qual_transport_outcome PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_qual_transport_outcome)
add_test(NAME host.espnow_dmp.transport_outcome
    COMMAND dmp_test_qual_transport_outcome)
set_tests_properties(host.espnow_dmp.transport_outcome PROPERTIES
    LABELS "host;espnow-dmp;transport" TIMEOUT 10)

add_executable(dmp_test_qual_tx_completion
    test_qual_tx_completion.c
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main/qual_tx_completion.c")
target_include_directories(dmp_test_qual_tx_completion PRIVATE
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main")
set_target_properties(dmp_test_qual_tx_completion PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_qual_tx_completion)
add_test(NAME host.espnow_dmp.tx_completion
    COMMAND dmp_test_qual_tx_completion)
set_tests_properties(host.espnow_dmp.tx_completion PROPERTIES
    LABELS "host;espnow-dmp;transport" TIMEOUT 10)

add_executable(dmp_test_qual_handshake_readiness
    test_qual_handshake_readiness.c
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main/qual_handshake_readiness.c")
target_include_directories(dmp_test_qual_handshake_readiness PRIVATE
    "${PROJECT_SOURCE_DIR}/tests/embedded/espnow_dmp/main")
set_target_properties(dmp_test_qual_handshake_readiness PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_qual_handshake_readiness)
add_test(NAME host.espnow_dmp.handshake_readiness
    COMMAND dmp_test_qual_handshake_readiness)
set_tests_properties(host.espnow_dmp.handshake_readiness PROPERTIES
    LABELS "host;espnow-dmp;security" TIMEOUT 10)
