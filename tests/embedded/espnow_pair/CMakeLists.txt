cmake_minimum_required(VERSION 3.16)

option(DMP_PAIR_C3_UART0_CONSOLE "Use UART0 for the ESP32-C3 test console" OFF)

if(IDF_TARGET STREQUAL "esp32s3")
    set(_pair_target_defaults "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.esp32s3.defaults")
elseif(IDF_TARGET STREQUAL "esp32c3")
    set(_pair_target_defaults "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.esp32c3.defaults")
    if(DMP_PAIR_C3_UART0_CONSOLE)
        list(APPEND _pair_target_defaults
            "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.esp32c3.uart0.defaults")
    endif()
else()
    message(FATAL_ERROR "ESP-NOW pair smoke supports ESP32-S3 and ESP32-C3 only")
endif()

if(DMP_PAIR_C3_UART0_CONSOLE AND NOT IDF_TARGET STREQUAL "esp32c3")
    message(FATAL_ERROR "DMP_PAIR_C3_UART0_CONSOLE is only supported for ESP32-C3")
endif()

set(SDKCONFIG_DEFAULTS
    "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults;${_pair_target_defaults}")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(dmp_espnow_pair)

if(NOT IDF_VERSION_MAJOR EQUAL 6 OR NOT IDF_VERSION_MINOR EQUAL 1)
    message(FATAL_ERROR "The ESP-NOW pair smoke requires the selected ESP-IDF 6.1")
endif()
