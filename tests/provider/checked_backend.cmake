# BINIT-01: separately built experimental backend; original source stays intact.
# The inherited source list includes an assembly unit; enable it in this scope.
enable_language(ASM)
set(_checked_dir "${CMAKE_CURRENT_BINARY_DIR}/checked-sodium")
set(_checked_patch_dir "${CMAKE_CURRENT_SOURCE_DIR}/backend")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${_checked_patch_dir}/checked-init.patch" "${_checked_patch_dir}/inputs.json"
    "${_checked_patch_dir}/prepare_checked_sodium.py"
    "${DMP_SODIUM_SOURCE_DIR}/libsodium/src/libsodium/sodium/core.c"
    "${DMP_SODIUM_SOURCE_DIR}/libsodium/src/libsodium/sodium/utils.c")
execute_process(COMMAND "${Python3_EXECUTABLE}"
    "${_checked_patch_dir}/prepare_checked_sodium.py"
    --source "${DMP_SODIUM_SOURCE_DIR}" --output "${_checked_dir}"
    RESULT_VARIABLE _checked_result OUTPUT_VARIABLE _checked_output ERROR_VARIABLE _checked_error)
if(NOT _checked_result EQUAL 0)
    message(FATAL_ERROR "Checked backend preparation failed: ${_checked_output}${_checked_error}")
endif()

get_target_property(_checked_sodium_sources sodium SOURCES)
list(TRANSFORM _checked_sodium_sources PREPEND "${DMP_SODIUM_SOURCE_DIR}/")
foreach(_file core utils)
    list(REMOVE_ITEM _checked_sodium_sources
        "${DMP_SODIUM_SOURCE_DIR}/libsodium/src/libsodium/sodium/${_file}.c")
    list(APPEND _checked_sodium_sources
        "${_checked_dir}/libsodium/src/libsodium/sodium/${_file}.c")
endforeach()

add_library(dmp_sodium_checked STATIC ${_checked_sodium_sources})
get_target_property(_checked_sodium_includes sodium INCLUDE_DIRECTORIES)
get_target_property(_checked_sodium_options sodium COMPILE_OPTIONS)
target_include_directories(dmp_sodium_checked PUBLIC
    ${_checked_sodium_includes} "${_checked_patch_dir}")
target_compile_options(dmp_sodium_checked PRIVATE ${_checked_sodium_options})
target_compile_definitions(dmp_sodium_checked PRIVATE CONFIGURED=1 DMP_SODIUM_CHECKED_INIT=1)

add_library(dmp_noise_checked_startup STATIC ${_noise_entropy_sources})
target_include_directories(dmp_noise_checked_startup PUBLIC
    "${PROJECT_SOURCE_DIR}/third_party/noise-c/include"
    "${PROJECT_SOURCE_DIR}/third_party/noise-c/src")
target_compile_definitions(dmp_noise_checked_startup PUBLIC
    NOISE_USE_CUSTOM_RAND=1 NOISE_USE_SODIUM_RAND=0 NOISE_REQUIRE_FALLIBLE_RAND=1
    NOISE_USE_PTHREAD=0)
target_compile_definitions(dmp_noise_checked_startup PRIVATE NOISE_REQUIRE_SODIUM_FAST_PATH)
target_link_libraries(dmp_noise_checked_startup PUBLIC dmp_sodium_checked)

add_test(NAME dmp_checked_backend_preparation
    COMMAND "${Python3_EXECUTABLE}" "${_checked_patch_dir}/test_prepare_checked_sodium.py")
set_tests_properties(dmp_checked_backend_preparation PROPERTIES TIMEOUT 30 LABELS "build-input-validation")

dmp_add_provider_experiment(dmp_noise_checked_init_probe noise_checked_init_probe.c)
target_link_libraries(dmp_noise_checked_init_probe PRIVATE dmp_noise_checked_startup)
foreach(_case ready-failure read-failure)
    add_test(NAME dmp_noise_checked_init_${_case} COMMAND dmp_noise_checked_init_probe ${_case})
    set_tests_properties(dmp_noise_checked_init_${_case} PROPERTIES TIMEOUT 30 LABELS "provider-experiment")
endforeach()

foreach(_probe fixture pn dh rng_state rng_handshake)
    set(_name "dmp_checked_noise_${_probe}_probe")
    dmp_add_provider_experiment(${_name} "noise_${_probe}_probe.c"
        noise_checked_fixture_port.c "${_fixture_header}")
    target_include_directories(${_name} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_link_libraries(${_name} PRIVATE dmp_noise_checked_startup)
    if(NOT _probe MATCHES "^rng_")
        target_compile_definitions(${_name} PRIVATE DMP_TEST_NOISE_ENTROPY_PORT=1)
    endif()
endforeach()

if(WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    dmp_add_provider_experiment(dmp_noise_checked_init_os_probe noise_checked_init_probe.c)
    target_compile_definitions(dmp_noise_checked_init_os_probe PRIVATE DMP_TEST_WINDOWS_ENTROPY=1)
    target_link_options(dmp_noise_checked_init_os_probe PRIVATE "-Wl,--wrap=SystemFunction036")
    target_link_libraries(dmp_noise_checked_init_os_probe PRIVATE dmp_noise_checked_startup)
    foreach(_case ready-failure read-failure)
        add_test(NAME dmp_noise_checked_init_os_${_case}
            COMMAND dmp_noise_checked_init_os_probe ${_case})
        set_tests_properties(dmp_noise_checked_init_os_${_case} PROPERTIES
            TIMEOUT 30 LABELS "provider-experiment")
    endforeach()
endif()

if(WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(_checked_guard_targets dmp_noise_checked_init_probe dmp_noise_checked_init_os_probe)
    foreach(_probe fixture pn dh rng_state rng_handshake)
        list(APPEND _checked_guard_targets "dmp_checked_noise_${_probe}_probe")
    endforeach()
    foreach(_target IN LISTS _checked_guard_targets)
        target_sources(${_target} PRIVATE noise_checked_no_legacy_rng.c)
        target_link_options(${_target} PRIVATE
            "-Wl,--wrap=randombytes_stir" "-Wl,--wrap=randombytes_buf")
    endforeach()
endif()

# Repeat inherited regression suites on the checked backend as well.
foreach(_suite unit vector)
    get_target_property(_suite_sources noise-c-test-${_suite} SOURCES)
    list(TRANSFORM _suite_sources PREPEND "${PROJECT_SOURCE_DIR}/third_party/noise-c/")
    set(_target "dmp_checked_noise_${_suite}")
    add_executable(${_target} ${_suite_sources} noise_checked_fixture_port.c)
    get_target_property(_suite_options noise-c-test-${_suite} COMPILE_OPTIONS)
    target_compile_options(${_target} PRIVATE ${_suite_options})
    target_compile_definitions(${_target} PRIVATE DMP_TEST_NOISE_ENTROPY_PORT=1)
    target_link_libraries(${_target} PRIVATE dmp_noise_checked_startup)
    # Inherited vector runner locates its source files through argv.
    if(_suite STREQUAL "vector")
        add_test(NAME ${_target} COMMAND ${_target}
            "${PROJECT_SOURCE_DIR}/third_party/noise-c/tests/vector/noise-c-basic.txt"
            "${PROJECT_SOURCE_DIR}/third_party/noise-c/tests/vector/cacophony.txt"
            "${PROJECT_SOURCE_DIR}/third_party/noise-c/tests/vector/noise-c-fallback.txt"
            "${PROJECT_SOURCE_DIR}/third_party/noise-c/tests/vector/noise-c-hybrid.txt")
    else()
        add_test(NAME ${_target} COMMAND ${_target})
    endif()
    set_tests_properties(${_target} PROPERTIES TIMEOUT 30 LABELS "inherited-regression")
    if(WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_sources(${_target} PRIVATE noise_checked_no_legacy_rng.c)
        target_link_options(${_target} PRIVATE
            "-Wl,--wrap=randombytes_stir" "-Wl,--wrap=randombytes_buf")
    endif()
endforeach()

# MEM-01 observes the real allocator boundary without changing provider code.
# These link wrappers are tested only with the selected Windows GNU host ABI.
if(WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    dmp_add_provider_experiment(dmp_noise_memory_probe noise_memory_probe.c
        noise_checked_fixture_port.c noise_checked_no_legacy_rng.c "${_fixture_header}")
    target_include_directories(dmp_noise_memory_probe PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_compile_definitions(dmp_noise_memory_probe PRIVATE DMP_TEST_NOISE_ENTROPY_PORT=1)
    target_link_libraries(dmp_noise_memory_probe PRIVATE dmp_noise_checked_startup)
    target_link_options(dmp_noise_memory_probe PRIVATE
        "-Wl,--wrap=malloc" "-Wl,--wrap=calloc" "-Wl,--wrap=realloc" "-Wl,--wrap=free"
        "-Wl,--wrap=randombytes_stir" "-Wl,--wrap=randombytes_buf")
    set_tests_properties(dmp_noise_memory_probe PROPERTIES LABELS "provider-memory-experiment")
else()
    message(STATUS "MEM-01 allocator wrappers unavailable on this configuration; not counted as passed")
endif()

include(allocator_experiment.cmake)
