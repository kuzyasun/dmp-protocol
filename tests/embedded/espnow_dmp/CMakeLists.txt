cmake_minimum_required(VERSION 3.16)

option(DMP_DMP_C3_UART0_CONSOLE "Use UART0 for the ESP32-C3 test console" OFF)

if(IDF_TARGET STREQUAL "esp32s3")
    set(_dmp_target_defaults "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.esp32s3.defaults")
elseif(IDF_TARGET STREQUAL "esp32c3")
    set(_dmp_target_defaults "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.esp32c3.defaults")
    if(DMP_DMP_C3_UART0_CONSOLE)
        list(APPEND _dmp_target_defaults
            "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.esp32c3.uart0.defaults")
    endif()
else()
    message(FATAL_ERROR "ESP-NOW DMP qualification supports ESP32-S3 and ESP32-C3 only")
endif()

if(DMP_DMP_C3_UART0_CONSOLE AND NOT IDF_TARGET STREQUAL "esp32c3")
    message(FATAL_ERROR "DMP_DMP_C3_UART0_CONSOLE is only supported for ESP32-C3")
endif()

set(SDKCONFIG_DEFAULTS
    "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults;${_dmp_target_defaults}")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
set(DMP_ESP_NOW_QUAL_DIAGNOSTICS ON CACHE BOOL
    "Enable handshake failure-stage diagnostics in the ESP-NOW qualification image" FORCE)
get_filename_component(DMP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../components/dmp"
    "${DMP_ROOT}/third_party/noise-c")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(dmp_espnow_dmp)

if(NOT IDF_VERSION_MAJOR EQUAL 6 OR NOT IDF_VERSION_MINOR EQUAL 1)
    message(FATAL_ERROR "The ESP-NOW DMP qualification requires the selected ESP-IDF 6.1")
endif()
