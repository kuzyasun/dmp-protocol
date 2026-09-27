if(UNIX)
    find_package(Threads REQUIRED)
    add_executable(dmp_noise_parallel parallel/parallel.c parallel/host.c
        noise_test_arena.c "${_fixture_header}")
    set_target_properties(dmp_noise_parallel PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES)
    target_include_directories(dmp_noise_parallel PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_link_libraries(dmp_noise_parallel PRIVATE dmp_noise_arena Threads::Threads)
    target_compile_options(dmp_noise_parallel PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-strict-aliasing)
    add_test(NAME dmp_parallel_one COMMAND dmp_noise_parallel 1 16)
    add_test(NAME dmp_parallel_two COMMAND dmp_noise_parallel 2 64)
    set_tests_properties(dmp_parallel_one dmp_parallel_two PROPERTIES TIMEOUT 120 LABELS "provider-parallel")
    add_test(NAME dmp_parallel_acceptance COMMAND "${Python3_EXECUTABLE}" -O -m unittest discover
        -s "${CMAKE_CURRENT_SOURCE_DIR}/parallel" -p test_serial_parallel.py)
    set_tests_properties(dmp_parallel_acceptance PROPERTIES TIMEOUT 30 LABELS "provider-parallel")
endif()
