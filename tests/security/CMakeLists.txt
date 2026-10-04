# Link tests/security to the provider adapter already compiled into libdmp.
find_package(Git REQUIRED)
set(DMP_NOISE_PIN "c40f2dca78eee064e521233a5d884853d471028a")
set(DMP_SODIUM_PIN "40c22448d6e8f42be56c45f739b52a5c8d21c8ca")
set(DMP_LIBSODIUM_PIN "d24faf56214469b354b01c8ba36257e04737101e")

function(dmp_require_revision directory expected)
    execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${directory}" rev-parse HEAD
        OUTPUT_VARIABLE actual OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE result)
    if(NOT result EQUAL 0 OR NOT actual STREQUAL expected)
        message(FATAL_ERROR "Unexpected provider source revision at ${directory}: ${actual}")
    endif()
endfunction()
dmp_require_revision("${PROJECT_SOURCE_DIR}/third_party/noise-c" "${DMP_NOISE_PIN}")
dmp_require_revision("${DMP_SODIUM_SOURCE_DIR}" "${DMP_SODIUM_PIN}")
dmp_require_revision("${DMP_SODIUM_SOURCE_DIR}/libsodium" "${DMP_LIBSODIUM_PIN}")

set(_checked_dir "${CMAKE_CURRENT_BINARY_DIR}/checked-sodium")
set(_patch_dir "${PROJECT_SOURCE_DIR}/tests/provider/backend")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${_patch_dir}/checked-init.patch" "${_patch_dir}/inputs.json"
    "${_patch_dir}/prepare_checked_sodium.py")
execute_process(COMMAND "${Python3_EXECUTABLE}"
    "${_patch_dir}/prepare_checked_sodium.py"
    --source "${DMP_SODIUM_SOURCE_DIR}" --output "${_checked_dir}"
    RESULT_VARIABLE _checked_result
    OUTPUT_VARIABLE _checked_output ERROR_VARIABLE _checked_error)
if(NOT _checked_result EQUAL 0)
    message(FATAL_ERROR "Checked backend preparation failed: ${_checked_output}${_checked_error}")
endif()

add_subdirectory("${DMP_SODIUM_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/sodium-import" EXCLUDE_FROM_ALL)
get_target_property(_sodium_sources sodium SOURCES)
list(TRANSFORM _sodium_sources PREPEND "${DMP_SODIUM_SOURCE_DIR}/")
foreach(_file core utils)
    list(REMOVE_ITEM _sodium_sources
        "${DMP_SODIUM_SOURCE_DIR}/libsodium/src/libsodium/sodium/${_file}.c")
    list(APPEND _sodium_sources
        "${_checked_dir}/libsodium/src/libsodium/sodium/${_file}.c")
endforeach()
get_target_property(_sodium_includes sodium INCLUDE_DIRECTORIES)
get_target_property(_sodium_options sodium COMPILE_OPTIONS)
add_library(dmp_p01b_sodium STATIC ${_sodium_sources})
target_include_directories(dmp_p01b_sodium PUBLIC ${_sodium_includes} "${_patch_dir}")
target_compile_options(dmp_p01b_sodium PRIVATE ${_sodium_options})
target_compile_definitions(dmp_p01b_sodium PRIVATE CONFIGURED=1 DMP_SODIUM_CHECKED_INIT=1)

set(_noise_root "${PROJECT_SOURCE_DIR}/third_party/noise-c")
set(_noise_sources
    src/backend/openssl/cipher-aesgcm.c
    src/backend/ref/cipher-aesgcm.c
    src/backend/ref/cipher-chachapoly.c
    src/backend/ref/dh-curve25519.c
    src/backend/ref/hash-blake2b.c
    src/backend/ref/hash-blake2s.c
    src/backend/ref/hash-sha256.c
    src/backend/sodium/cipher-aesgcm.c
    src/backend/sodium/cipher-chachapoly.c
    src/backend/sodium/dh-curve25519.c
    src/backend/sodium/hash-blake2b.c
    src/backend/sodium/hash-sha256.c
    src/crypto/aes/rijndael-alg-fst.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2s.c
    src/crypto/chacha/chacha.c
    src/crypto/donna/curve25519-donna-c64.c
    src/crypto/donna/curve25519-donna.c
    src/crypto/donna/poly1305-donna.c
    src/crypto/sha2/sha256.c
    src/crypto/sha2/sha512.c
    src/crypto/x25519/x25519.c
    src/protocol/cipherstate.c
    src/protocol/dhstate.c
    src/protocol/errors.c
    src/protocol/handshakestate.c
    src/protocol/hashstate.c
    src/protocol/internal.c
    src/protocol/names-single.c
    src/protocol/patterns-single.c
    src/protocol/names.c
    src/protocol/patterns.c
    src/protocol/rand_os.c
    src/protocol/rand_sodium.c
    src/protocol/randstate.c
    src/protocol/signstate.c
    src/protocol/symmetricstate.c
    src/protocol/util.c)
list(TRANSFORM _noise_sources PREPEND "${_noise_root}/")
add_library(dmp_p01b_noise STATIC ${_noise_sources})
target_include_directories(dmp_p01b_noise PUBLIC
    "${_noise_root}/include" "${_noise_root}/src")
target_compile_definitions(dmp_p01b_noise PRIVATE
    NOISE_USE_CUSTOM_RAND=1 NOISE_USE_SODIUM_RAND=0 NOISE_REQUIRE_FALLIBLE_RAND=1
    NOISE_USE_CUSTOM_ALLOCATOR=1 NOISE_USE_LIBSODIUM=1 NOISE_USE_REFERENCE_BACKEND=0
    NOISE_USE_AES=0 NOISE_USE_OPENSSL=0 NOISE_USE_PTHREAD=0
    NOISE_REQUIRE_SODIUM_FAST_PATH)
target_link_libraries(dmp_p01b_noise PUBLIC dmp_p01b_sodium)

set(_fixture_header "${CMAKE_CURRENT_BINARY_DIR}/noise_fixture_probe.h")
add_custom_command(OUTPUT "${_fixture_header}"
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/provider/generate_noise_fixture_header.py"
        --input "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Security_Test_Vectors.json"
        --output "${_fixture_header}"
    DEPENDS "${PROJECT_SOURCE_DIR}/tests/provider/generate_noise_fixture_header.py"
        "${PROJECT_SOURCE_DIR}/docs/DMP_v2_Security_Test_Vectors.json"
    VERBATIM)
add_executable(dmp_test_provider test_provider.c "${_fixture_header}")
target_include_directories(dmp_test_provider PRIVATE
    "${PROJECT_SOURCE_DIR}/src/security" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(dmp_test_provider PRIVATE
    "$<LINK_GROUP:RESCAN,libdmp,dmp_p01b_noise,dmp_p01b_sodium>")
set_target_properties(dmp_test_provider PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_provider)
add_test(NAME security.provider_adapter COMMAND dmp_test_provider)
set_tests_properties(security.provider_adapter PROPERTIES
    TIMEOUT 60 LABELS "provider-adapter")

add_executable(dmp_test_handshake test_handshake.c "${_fixture_header}")
target_include_directories(dmp_test_handshake PRIVATE
    "${PROJECT_SOURCE_DIR}/src/security" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(dmp_test_handshake PRIVATE
    "$<LINK_GROUP:RESCAN,libdmp,dmp_p01b_noise,dmp_p01b_sodium>")
set_target_properties(dmp_test_handshake PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
dmp_strict_target(dmp_test_handshake)
add_test(NAME security.handshake COMMAND dmp_test_handshake)
set_tests_properties(security.handshake PROPERTIES
    TIMEOUT 60 LABELS "handshake")
