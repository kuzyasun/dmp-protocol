/* Build/link experiment with public deterministic keys. Never a product image. */
#ifdef DMP_MCU_PROVIDER_ENABLED
int dmp_mcu_fixture_main(void);
volatile int dmp_mcu_fixture_result = -1;
#endif

void app_main(void)
{
#ifdef DMP_MCU_PROVIDER_ENABLED
    dmp_mcu_fixture_result = dmp_mcu_fixture_main();
#endif
}
