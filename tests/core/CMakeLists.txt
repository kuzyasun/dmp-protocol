foreach(name IN ITEMS base headers)
    add_executable(dmp_test_${name} test_${name}.c)
    target_link_libraries(dmp_test_${name} PRIVATE dmp::dmp)
    set_target_properties(dmp_test_${name} PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(dmp_test_${name})
    add_test(NAME core.${name} COMMAND dmp_test_${name})
    set_tests_properties(core.${name} PROPERTIES TIMEOUT 10 LABELS "core-foundation")
endforeach()

set(packet_header "${CMAKE_CURRENT_BINARY_DIR}/public_packets.h")
add_custom_command(OUTPUT "${packet_header}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/generate_packet_vectors.py"
        "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Security_Test_Vectors.json" "${packet_header}"
    DEPENDS generate_packet_vectors.py "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Security_Test_Vectors.json"
    VERBATIM)
add_executable(dmp_test_public_packets test_public_packets.c "${packet_header}")
target_include_directories(dmp_test_public_packets PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(dmp_test_public_packets PRIVATE dmp::dmp)
set_target_properties(dmp_test_public_packets PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_public_packets)
add_test(NAME core.public_packets COMMAND dmp_test_public_packets)
set_tests_properties(core.public_packets PROPERTIES TIMEOUT 20 LABELS "core-codec")

foreach(name IN ITEMS codec pipeline)
    add_executable(dmp_test_${name} test_${name}.c)
    target_link_libraries(dmp_test_${name} PRIVATE dmp::dmp)
    set_target_properties(dmp_test_${name} PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    dmp_strict_target(dmp_test_${name})
    add_test(NAME core.${name} COMMAND dmp_test_${name})
    set_tests_properties(core.${name} PROPERTIES TIMEOUT 20 LABELS "core-codec")
endforeach()

# Optional consumer smoke only; libdmp itself requires no C++ toolchain.
include(CheckLanguage)
check_language(CXX)
if(CMAKE_CXX_COMPILER)
    enable_language(CXX)
    add_executable(dmp_test_headers_cpp test_headers.cpp)
    target_link_libraries(dmp_test_headers_cpp PRIVATE dmp::dmp)
    set_target_properties(dmp_test_headers_cpp PROPERTIES
        CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
    dmp_strict_target(dmp_test_headers_cpp)
    add_test(NAME core.headers_cpp COMMAND dmp_test_headers_cpp)
    set_tests_properties(core.headers_cpp PROPERTIES TIMEOUT 10 LABELS "core-foundation")
endif()
