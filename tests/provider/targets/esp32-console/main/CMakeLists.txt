idf_component_register(SRCS "main.c"
    INCLUDE_DIRS "../../../console"
    REQUIRES esp_driver_uart esp_timer esp_hw_support bootloader_support heap)
set(DMP_MCU_CONSOLE ON)
include(../../mcu_provider.cmake)
dmp_add_mcu_provider()
# The provider calls platform hooks after libmain has been scanned. Keep their
# object in the same rescan group as the caller, rather than relying on main
# archive order or force-linking arbitrary symbols.
target_sources(dmp_mcu_fixture PRIVATE "${CMAKE_CURRENT_LIST_DIR}/platform.c")
target_include_directories(dmp_mcu_fixture PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../../../console")
target_link_libraries(dmp_mcu_fixture PRIVATE idf::esp_timer idf::esp_hw_support
    idf::bootloader_support idf::heap idf::freertos)
target_link_libraries(${COMPONENT_LIB} PRIVATE
    "$<LINK_GROUP:RESCAN,dmp_mcu_fixture,noise_c,sodium>")
