add_test(NAME host.espnow_dmp.serial_stub
    COMMAND "${Python3_EXECUTABLE}" -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}" -p "test_*.py" -v)
set_tests_properties(host.espnow_dmp.serial_stub PROPERTIES
    LABELS "host;espnow-dmp;stub" TIMEOUT 30)
