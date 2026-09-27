idf_component_register(SRCS "main.c" INCLUDE_DIRS "../../../parallel"
    REQUIRES esp_driver_uart esp_timer esp_hw_support bootloader_support heap)
set(DMP_MCU_PARALLEL ON)
include(../../mcu_provider.cmake)
dmp_add_mcu_provider()
target_include_directories(dmp_mcu_fixture PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../../../parallel")
# Source identity is also needed by the UART reporting port.
include(../../../console/identity.cmake)
dmp_bench_identity(${COMPONENT_LIB})
target_link_libraries(${COMPONENT_LIB} PRIVATE
    "$<LINK_GROUP:RESCAN,dmp_mcu_fixture,noise_c,sodium>")
