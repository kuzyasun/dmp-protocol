/* Private bounded task probe. No RF, ADC clients, or shared Noise contexts. */
#include "parallel.h"
#include "report.h"
#include "bootloader_random.h"
#include "driver/uart.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include <string.h>

#if CONFIG_IDF_TARGET_ESP32S3 && CONFIG_FREERTOS_UNICORE
#error "MCU-04 ESP32-S3 must enable both cores"
#endif

#define STACK_BYTES 12288u
static StackType_t stacks[2][STACK_BYTES / sizeof(StackType_t)];
static StaticTask_t task_storage[2];
static TaskHandle_t tasks[2];
static StaticSemaphore_t entropy_storage;
static SemaphoreHandle_t entropy_mutex;
static StaticEventGroup_t event_storage;
static EventGroupHandle_t events;
static portMUX_TYPE metric_lock = portMUX_INITIALIZER_UNLOCKED;
static unsigned active, peak, core_mask, dual_core_overlap, active_cores[2];
static unsigned cycles, run_count, current_workers, sync_rounds[2], ids[2] = {0, 1};
static int errors[2];
static size_t stack_free[2];
static dmp_parallel_result results[2];
static uint32_t boot_id;

unsigned dmp_parallel_worker_id(void)
{
    TaskHandle_t current = xTaskGetCurrentTaskHandle();
    for (unsigned i = 0; i < 2; ++i) if (current == tasks[i]) return i;
    return DMP_PARALLEL_WORKERS;
}
uint64_t dmp_parallel_time_us(void) { return (uint64_t)esp_timer_get_time(); }
int dmp_parallel_entropy(void *bytes, size_t size)
{
    if (xSemaphoreTake(entropy_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) return 1;
    /* Sole owner of ADC entropy source; never enable RF beside this port. */
    bootloader_random_enable();
    esp_fill_random(bytes, size);
    bootloader_random_disable();
    xSemaphoreGive(entropy_mutex);
    return 0;
}
void dmp_parallel_call_enter(void)
{
    unsigned core = (unsigned)xPortGetCoreID();
    portENTER_CRITICAL(&metric_lock);
    ++active;
    ++active_cores[core];
    core_mask |= 1u << core;
    if (active > peak) peak = active;
    if (active_cores[0] && active_cores[1]) ++dual_core_overlap;
    portEXIT_CRITICAL(&metric_lock);
}
void dmp_parallel_call_leave(void)
{
    unsigned core = (unsigned)xPortGetCoreID();
    portENTER_CRITICAL(&metric_lock);
    --active;
    --active_cores[core];
    portEXIT_CRITICAL(&metric_lock);
}
int dmp_parallel_yield(void)
{
    unsigned id = dmp_parallel_worker_id();
    EventBits_t mask = ((1u << current_workers) - 1u) << 12;
    if (id >= current_workers) return 1;
    /* A delay by each worker independently can starve IDLE on a single core:
       the other worker stays runnable. Rendezvous, then block both together. */
    EventBits_t arrived = xEventGroupSync(events, 1u << (id + 12), mask,
                                         pdMS_TO_TICKS(5000));
    if ((arrived & mask) != mask) return 1;
    ++sync_rounds[id];
    vTaskDelay(2);
    return 0;
}
static void worker(void *argument)
{
    unsigned id = *(unsigned *)argument;
    for (;;) {
        if (!ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000))) continue;
        /* Main waits for both ready bits before releasing the start gate. */
        xEventGroupSetBits(events, 1u << (id + 4));
        if (!(xEventGroupWaitBits(events, 1u << 8, pdFALSE, pdTRUE,
                                 pdMS_TO_TICKS(5000)) & (1u << 8))) {
            errors[id] = -1;
        } else {
            errors[id] = dmp_parallel_run(id, cycles, &results[id]);
        }
        stack_free[id] = uxTaskGetStackHighWaterMark(NULL);
        xEventGroupSetBits(events, 1u << id);
    }
}
static void identity(unsigned id, const char *op)
{
    printf("DMPPAR {\"id\":%u,\"op\":\"%s\",\"boot\":\"%08" PRIx32
           "\",\"target\":\"%s\",\"idf\":\"%s\",\"build\":\"%s\"",
           id, op, boot_id, CONFIG_IDF_TARGET, esp_get_idf_version(), DMP_BENCH_BUILD_ID);
}
static int execute(unsigned id, unsigned count, unsigned requested_cycles)
{
    EventBits_t mask = (1u << count) - 1u;
    size_t heap_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    cycles = requested_cycles;
    current_workers = count;
    active = peak = core_mask = dual_core_overlap = 0;
    memset(active_cores, 0, sizeof(active_cores));
    memset(results, 0, sizeof(results));
    memset(errors, 0, sizeof(errors));
    memset(sync_rounds, 0, sizeof(sync_rounds));
    xEventGroupClearBits(events, 0xffff);
    for (unsigned i = 0; i < count; ++i) xTaskNotifyGive(tasks[i]);
    if ((xEventGroupWaitBits(events, mask << 4, pdFALSE, pdTRUE,
                            pdMS_TO_TICKS(5000)) & (mask << 4)) != (mask << 4)) return 1;
    uint64_t start = dmp_parallel_time_us();
    xEventGroupSetBits(events, 1u << 8);
    if ((xEventGroupWaitBits(events, mask, pdFALSE, pdTRUE,
                            pdMS_TO_TICKS(90000)) & mask) != mask) return 1;
    uint64_t elapsed = dmp_parallel_time_us() - start;
    int failed = active != 0 || peak != count;
    for (unsigned i = 0; i < count; ++i)
        if (errors[i] || !dmp_parallel_result_ok(&results[i], cycles) ||
            sync_rounds[i] != cycles) failed = 1;
    if (count == 2 && portNUM_PROCESSORS == 2 && (!dual_core_overlap || core_mask != 3)) failed = 1;
    identity(id, "RUN");
    printf(",\"success\":%s,\"run\":%u,\"workers\":%u,\"cycles\":%u,"
           "\"cores\":%u,\"core_mask\":%u,\"max_inflight\":%u,\"dual_core_overlap\":%u,"
           "\"elapsed_us\":%" PRIu64 ",\"heap_before\":%zu,\"heap_after\":%zu,"
           "\"heap_min\":%zu,\"main_stack_free\":%u,\"worker_stack_bytes\":%u,"
           "\"worker_stack_free\":[%zu,%zu],\"sync_rounds\":[%u,%u],\"results\":[",
           failed ? "false" : "true", ++run_count, count, cycles,
           (unsigned)portNUM_PROCESSORS, core_mask, peak, dual_core_overlap, elapsed,
           heap_before, heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
           heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
           (unsigned)uxTaskGetStackHighWaterMark(NULL), STACK_BYTES, stack_free[0], stack_free[1],
           sync_rounds[0], sync_rounds[1]);
    for (unsigned i = 0; i < count; ++i) {
        if (i) putchar(',');
        dmp_parallel_print_result(&results[i]);
    }
    puts("]}");
    fflush(stdout);
    return 0;
}
void app_main(void)
{
    char line[96], op[16], trailing;
    size_t used = 0;
    unsigned id, count, requested_cycles, last_id = 0;
    int discard = 0;
    const uart_port_t port = CONFIG_ESP_CONSOLE_UART_NUM;
    entropy_mutex = xSemaphoreCreateMutexStatic(&entropy_storage);
    events = xEventGroupCreateStatic(&event_storage);
    if (!entropy_mutex || !events || dmp_parallel_entropy(&boot_id, sizeof(boot_id)) ||
        dmp_parallel_init()) { puts("DMPPAR_INIT_FAILED"); return; }
    for (unsigned i = 0; i < 2; ++i) {
        tasks[i] = xTaskCreateStaticPinnedToCore(worker, "noise-worker", STACK_BYTES,
            &ids[i], 4, stacks[i], &task_storage[i], i % portNUM_PROCESSORS);
        if (!tasks[i]) { puts("DMPPAR_TASK_FAILED"); return; }
    }
    ESP_ERROR_CHECK(uart_driver_install(port, 2048, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_set_baudrate(port, 115200));
    for (;;) {
        uint8_t c;
        if (uart_read_bytes(port, &c, 1, pdMS_TO_TICKS(100)) <= 0) continue;
        if (c != '\n') {
            if (c != '\r') {
                if (used == sizeof(line) - 1 || c < 32 || c > 126) discard = 1;
                else if (!discard) line[used++] = (char)c;
            }
            continue;
        }
        line[used] = 0;
        if (!discard && sscanf(line, "%u %15s %c", &id, op, &trailing) == 2 &&
            strcmp(op, "HELLO") == 0) {
            identity(id, "HELLO");
            printf(",\"last_id\":%u,\"cores\":%u}\n", last_id, (unsigned)portNUM_PROCESSORS);
        } else if (!discard && sscanf(line, "%u RUN %u %u %c", &id, &count,
                   &requested_cycles, &trailing) == 3 && id > last_id && count >= 1 &&
                   count <= 2 && requested_cycles >= 4 && requested_cycles <= 256 &&
                   requested_cycles % 4 == 0) {
            last_id = id;
            if (execute(id, count, requested_cycles)) {
                puts("DMPPAR_TIMEOUT_FATAL");
                return; /* No unsafe read/cleanup/reuse of possibly active workers. */
            }
        } else puts("DMPPAR_INVALID_COMMAND");
        fflush(stdout);
        used = 0;
        discard = 0;
    }
}
