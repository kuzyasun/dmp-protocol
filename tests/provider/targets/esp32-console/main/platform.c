/* ESP-IDF 6.1 laboratory port. No RF/ADC clients may run beside this RNG port. */
#include "bench.h"
#include "bootloader_random.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

uint64_t dmp_bench_time_us(void) { return (uint64_t)esp_timer_get_time(); }
int dmp_bench_entropy(void *bytes, size_t size)
{
    /* SDK requires active entropy input when RF is disabled. Serialized console
       owns this source; disable it before returning. Never combine with ADC/RF. */
    bootloader_random_enable();
    esp_fill_random(bytes, size);
    bootloader_random_disable();
    return 0; /* SDK API has no hardware-health failure report; no quality proof. */
}
void dmp_bench_platform_metrics(dmp_bench_metrics *m)
{
    m->heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    m->heap_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    m->heap_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    m->stack_free_min = uxTaskGetStackHighWaterMark(NULL); /* IDF returns bytes. */
    m->target = CONFIG_IDF_TARGET;
    m->idf = esp_get_idf_version();
}
