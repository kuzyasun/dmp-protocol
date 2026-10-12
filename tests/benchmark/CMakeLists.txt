if(TARGET dmp_test_endpoint_sec)
    add_test(NAME benchmark.p24
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/test_p24_bench.py")
    set_tests_properties(benchmark.p24 PROPERTIES
        TIMEOUT 180
        LABELS "benchmark;peer;interop"
        ENVIRONMENT
            "DMP_P23_ENDPOINT_SEC_EXE=$<TARGET_FILE:dmp_test_endpoint_sec>;PYTHONPATH=${PROJECT_SOURCE_DIR}/tests/peer")
endif()
