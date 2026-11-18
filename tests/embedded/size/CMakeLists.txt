cmake_minimum_required(VERSION 3.16)

option(DMP_SIZE_PROBE_STREAM_R "Exercise Stream R around the Core size workload" OFF)

set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
set(COMPONENTS main)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(dmp_size_probe)
