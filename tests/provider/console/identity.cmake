# Content identity of provider test sources, fixtures and build registration.
# Compiler/configuration and actual binary hashes remain separate evidence.
function(dmp_bench_identity target)
    get_filename_component(_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../../.." ABSOLUTE)
    file(GLOB_RECURSE _inputs CONFIGURE_DEPENDS
        "${_root}/tests/provider/*.c" "${_root}/tests/provider/*.h"
        "${_root}/tests/provider/*.cmake" "${_root}/tests/provider/CMakeLists.txt"
        "${_root}/tests/provider/*/CMakeLists.txt" "${_root}/tests/provider/*/sdkconfig.defaults")
    list(APPEND _inputs "${_root}/docs/DMP_v2_Security_Test_Vectors.json"
        "${_root}/tests/provider/backend/checked-init.patch"
        "${_root}/tests/provider/backend/inputs.json")
    list(SORT _inputs)
    set(_identity "Noise=c40f2dc;port=40c2244;libsodium=d24faf5;")
    foreach(_input IN LISTS _inputs)
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_input}")
        file(READ "${_input}" _content)
        string(REPLACE "\r\n" "\n" _content "${_content}")
        string(SHA256 _hash "${_content}")
        file(RELATIVE_PATH _relative "${_root}" "${_input}")
        string(APPEND _identity "${_relative}=${_hash};")
    endforeach()
    string(SHA256 _identity "${_identity}")
    target_compile_definitions(${target} PRIVATE DMP_BENCH_BUILD_ID="${_identity}")
endfunction()
