cmake_minimum_required(VERSION 3.20)
project(dmp LANGUAGES C)

# P00 is a host experiment scaffold, not a libdmp implementation.
option(DMP_BUILD_TESTS "Build host scaffold and provider experiments" ON)
option(DMP_NOISE_EXPERIMENTS "Build opt-in Noise candidate characterization tests" OFF)

if(DMP_NOISE_EXPERIMENTS AND NOT DMP_BUILD_TESTS)
    message(FATAL_ERROR "DMP_NOISE_EXPERIMENTS requires DMP_BUILD_TESTS")
endif()

if(DMP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests/provider)
    find_program(DMP_NODE_EXECUTABLE NAMES node nodejs REQUIRED)
    add_test(NAME fixtures.sec1
        COMMAND "${DMP_NODE_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/dev/dmp_verify_security_vectors.cjs")
    set_tests_properties(fixtures.sec1 PROPERTIES LABELS "fixture-only" TIMEOUT 30)
endif()
