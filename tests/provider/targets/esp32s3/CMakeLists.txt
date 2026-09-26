cmake_minimum_required(VERSION 3.24)
set(COMPONENTS main)
set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# Set before project() so both component and final-ELF directories inherit it.
# The SDK uses GNU ld with a CXX final link driver.
set(CMAKE_LINK_GROUP_USING_RESCAN "LINKER:--start-group" "LINKER:--end-group")
set(CMAKE_LINK_GROUP_USING_RESCAN_SUPPORTED TRUE)
project(dmp_mcu_test_only)
if(NOT IDF_TARGET STREQUAL "esp32s3")
    message(FATAL_ERROR "This experiment requires IDF_TARGET=esp32s3")
endif()
