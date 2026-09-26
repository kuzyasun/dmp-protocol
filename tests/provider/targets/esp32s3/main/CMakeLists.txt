idf_component_register(SRCS "main.c")
option(DMP_MCU_PROVIDER_ENABLED "Link deterministic provider fixture; otherwise SDK baseline" ON)
if(DMP_MCU_PROVIDER_ENABLED)
    include(../../mcu_provider.cmake)
    dmp_add_mcu_provider()
    # Provider/backend hooks point back into the fixture archive. Rescan the
    # complete group so ports are resolved regardless of archive member order.
    target_link_libraries(${COMPONENT_LIB} PRIVATE
        "$<LINK_GROUP:RESCAN,dmp_mcu_fixture,noise_c,sodium>")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DMP_MCU_PROVIDER_ENABLED=1)
endif()
