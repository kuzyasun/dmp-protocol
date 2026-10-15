cmake_minimum_required(VERSION 3.16)

if(IDF_TARGET STREQUAL "esp32s3")
    set(_pair_target_defaults "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.esp32s3.defaults")
elseif(IDF_TARGET STREQUAL "esp32c3")
    set(_pair_target_defaults "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.esp32c3.defaults")
else()
    message(FATAL_ERROR "ESP-NOW pair smoke supports ESP32-S3 and ESP32-C3 only")
endif()

set(SDKCONFIG_DEFAULTS
    "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults;${_pair_target_defaults}")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(dmp_espnow_pair)

if(NOT IDF_VERSION_MAJOR EQUAL 6 OR NOT IDF_VERSION_MINOR EQUAL 1)
    message(FATAL_ERROR "The ESP-NOW pair smoke requires the selected ESP-IDF 6.1")
endif()
