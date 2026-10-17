get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

idf_component_register(
    SRCS
        "${DMP_ROOT}/src/core/base.c"
        "${DMP_ROOT}/src/core/codec.c"
        "${DMP_ROOT}/src/integrity/crc32c.c"
        "${DMP_ROOT}/src/stream/cobs.c"
        "${DMP_ROOT}/src/stream/stream.c"
        "${DMP_ROOT}/src/identity/identity.c"
        "${DMP_ROOT}/src/identity/profile_admit.c"
        "${DMP_ROOT}/src/reassembly/reassembly.c"
        "${DMP_ROOT}/src/reliability/reliability.c"
        "${DMP_ROOT}/src/endpoint/endpoint.c"
        "${DMP_ROOT}/src/mesh/relay.c"
        "${DMP_ROOT}/src/security/provider_adapter.c"
        "${DMP_ROOT}/src/security/replay_window.c"
        "${DMP_ROOT}/src/security/handshake.c"
        "${DMP_ROOT}/src/security/handshake_transport.c"
        "${DMP_ROOT}/src/application/sample1_epoch_owner.c"
        "${DMP_ROOT}/src/application/sample1_endpoint.c"
        "${DMP_ROOT}/src/application/sample1_epoch_store.c"
        "${DMP_ROOT}/src/application/sample1_epoch_anchor_nvs.c"
        "${DMP_ROOT}/tests/embedded/components/dmp/prehardware_link_probe.c"
    INCLUDE_DIRS "${DMP_ROOT}/include" "${DMP_ROOT}/src/application"
    PRIV_INCLUDE_DIRS
        "${DMP_ROOT}/src/security"
        "${DMP_ROOT}/tests/provider/backend"
    REQUIRES nvs_flash
    PRIV_REQUIRES noise-c)

target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
if(DMP_ESP_NOW_QUAL_DIAGNOSTICS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DMP_HANDSHAKE_QUAL_DIAGNOSTICS=1)
endif()

# The ESPHome component's default sodium_init() stirs its legacy void
# randombytes backend. The selected DMP provider uses checked platform entropy
# instead, so compile the same pinned checked-startup patch used by the provider
# qualification target. The helper validates both source hashes before writing
# generated files outside the managed component tree.
idf_component_get_property(DMP_SODIUM_COMPONENT_LIB esphome__libsodium COMPONENT_LIB)
idf_component_get_property(DMP_SODIUM_COMPONENT_DIR esphome__libsodium COMPONENT_DIR)
if(NOT DMP_SODIUM_COMPONENT_LIB OR NOT TARGET ${DMP_SODIUM_COMPONENT_LIB})
    message(FATAL_ERROR "ESPHome libsodium component target is unavailable")
endif()
if(NOT IS_DIRECTORY "${DMP_SODIUM_COMPONENT_DIR}/libsodium")
    message(FATAL_ERROR "ESPHome libsodium component source tree is unavailable")
endif()

find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
set(DMP_PROVIDER_ROOT "${DMP_ROOT}/tests/provider")
set(DMP_CHECKED_SODIUM_DIR "${CMAKE_CURRENT_BINARY_DIR}/checked-sodium")
set(DMP_SODIUM_PATCH_DIR "${DMP_PROVIDER_ROOT}/backend")
set(DMP_SODIUM_CORE_SOURCE
    "${DMP_SODIUM_COMPONENT_DIR}/libsodium/src/libsodium/sodium/core.c")
set(DMP_SODIUM_UTILS_SOURCE
    "${DMP_SODIUM_COMPONENT_DIR}/libsodium/src/libsodium/sodium/utils.c")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${DMP_SODIUM_PATCH_DIR}/checked-init.patch"
    "${DMP_SODIUM_PATCH_DIR}/inputs.json"
    "${DMP_SODIUM_PATCH_DIR}/prepare_checked_sodium.py"
    "${DMP_SODIUM_CORE_SOURCE}"
    "${DMP_SODIUM_UTILS_SOURCE}")
execute_process(
    COMMAND "${Python3_EXECUTABLE}"
        "${DMP_SODIUM_PATCH_DIR}/prepare_checked_sodium.py"
        --source "${DMP_SODIUM_COMPONENT_DIR}"
        --output "${DMP_CHECKED_SODIUM_DIR}"
    RESULT_VARIABLE DMP_CHECKED_SODIUM_RESULT
    OUTPUT_VARIABLE DMP_CHECKED_SODIUM_OUTPUT
    ERROR_VARIABLE DMP_CHECKED_SODIUM_ERROR)
if(NOT DMP_CHECKED_SODIUM_RESULT EQUAL 0)
    message(FATAL_ERROR
        "Checked libsodium startup preparation failed: "
        "${DMP_CHECKED_SODIUM_OUTPUT}${DMP_CHECKED_SODIUM_ERROR}")
endif()

get_target_property(DMP_SODIUM_SOURCES ${DMP_SODIUM_COMPONENT_LIB} SOURCES)
set(DMP_SODIUM_REPLACED_CORE FALSE)
set(DMP_SODIUM_REPLACED_UTILS FALSE)
set(DMP_SODIUM_CHECKED_SOURCES)
foreach(DMP_SODIUM_SOURCE IN LISTS DMP_SODIUM_SOURCES)
    if(IS_ABSOLUTE "${DMP_SODIUM_SOURCE}")
        set(DMP_SODIUM_SOURCE_PATH "${DMP_SODIUM_SOURCE}")
    else()
        get_filename_component(DMP_SODIUM_SOURCE_PATH "${DMP_SODIUM_SOURCE}"
            ABSOLUTE BASE_DIR "${DMP_SODIUM_COMPONENT_DIR}")
    endif()
    file(TO_CMAKE_PATH "${DMP_SODIUM_SOURCE_PATH}" DMP_SODIUM_SOURCE_PATH)
    file(TO_CMAKE_PATH "${DMP_SODIUM_CORE_SOURCE}" DMP_SODIUM_CORE_SOURCE_NORMALIZED)
    file(TO_CMAKE_PATH "${DMP_SODIUM_UTILS_SOURCE}" DMP_SODIUM_UTILS_SOURCE_NORMALIZED)
    if(DMP_SODIUM_SOURCE_PATH STREQUAL DMP_SODIUM_CORE_SOURCE_NORMALIZED)
        list(APPEND DMP_SODIUM_CHECKED_SOURCES
            "${DMP_CHECKED_SODIUM_DIR}/libsodium/src/libsodium/sodium/core.c")
        set(DMP_SODIUM_REPLACED_CORE TRUE)
    elseif(DMP_SODIUM_SOURCE_PATH STREQUAL DMP_SODIUM_UTILS_SOURCE_NORMALIZED)
        list(APPEND DMP_SODIUM_CHECKED_SOURCES
            "${DMP_CHECKED_SODIUM_DIR}/libsodium/src/libsodium/sodium/utils.c")
        set(DMP_SODIUM_REPLACED_UTILS TRUE)
    else()
        list(APPEND DMP_SODIUM_CHECKED_SOURCES "${DMP_SODIUM_SOURCE}")
    endif()
endforeach()
if(NOT DMP_SODIUM_REPLACED_CORE OR NOT DMP_SODIUM_REPLACED_UTILS)
    message(FATAL_ERROR
        "Could not replace the pinned ESPHome libsodium core.c and utils.c sources")
endif()
set_property(TARGET ${DMP_SODIUM_COMPONENT_LIB} PROPERTY SOURCES
    "${DMP_SODIUM_CHECKED_SOURCES}")
target_include_directories(${DMP_SODIUM_COMPONENT_LIB} PRIVATE
    "${DMP_SODIUM_PATCH_DIR}")
target_compile_definitions(${DMP_SODIUM_COMPONENT_LIB} PRIVATE
    DMP_SODIUM_CHECKED_INIT=1)

# Match the checked host provider: Noise must use the DMP allocator and checked
# entropy ports, and retain both NNpsk0 and XX patterns for the S3/C3 link gate.
idf_component_get_property(DMP_NOISE_COMPONENT_LIB noise-c COMPONENT_LIB)
get_target_property(DMP_NOISE_COMPILE_DEFINITIONS
    ${DMP_NOISE_COMPONENT_LIB} COMPILE_DEFINITIONS)
if(DMP_NOISE_COMPILE_DEFINITIONS)
    list(REMOVE_ITEM DMP_NOISE_COMPILE_DEFINITIONS
        NOISE_USE_PROTOCOL_NAME_TABLE=0 NOISE_USE_FALLBACK=0 NOISE_USE_HFS=0)
endif()
set_target_properties(${DMP_NOISE_COMPONENT_LIB} PROPERTIES
    COMPILE_DEFINITIONS "${DMP_NOISE_COMPILE_DEFINITIONS}")
target_compile_definitions(${DMP_NOISE_COMPONENT_LIB} PRIVATE
    NOISE_USE_CUSTOM_RAND=1 NOISE_USE_SODIUM_RAND=0 NOISE_REQUIRE_FALLIBLE_RAND=1
    NOISE_USE_CUSTOM_ALLOCATOR=1 NOISE_USE_LIBSODIUM=1 NOISE_USE_REFERENCE_BACKEND=0
    NOISE_USE_AES=0 NOISE_USE_OPENSSL=0 NOISE_USE_PTHREAD=0
    NOISE_REQUIRE_SODIUM_FAST_PATH
    NOISE_USE_PROTOCOL_NAME_TABLE=1 NOISE_USE_FALLBACK=1 NOISE_USE_HFS=1)
