/* One bounded command task, no scenario logic or automatic radio behavior. */
#include "bench.h"
#include "driver/uart.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include <stdio.h>
#include <string.h>

void app_main(void)
{
    static char line[DMP_BENCH_LINE], response[DMP_BENCH_REPLY];
    size_t used = 0;
    int discarded = 0;
    const uart_port_t port = CONFIG_ESP_CONSOLE_UART_NUM;
    /* Keep SDK-selected UART0 pins for the USB bridge. No board GPIO guesses. */
    ESP_ERROR_CHECK(uart_driver_install(port, 4096, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_set_baudrate(port, 115200));
    if (dmp_bench_init()) { puts("DMPBENCH_INIT_FAILED"); return; }
    for (;;) {
        uint8_t c;
        int received = uart_read_bytes(port, &c, 1, pdMS_TO_TICKS(100));
        if (received <= 0) continue;
        if (c == '\n') {
            if (used && line[used - 1] == '\r') --used;
            line[used] = 0;
            dmp_bench_command(discarded ? NULL : line, response);
            int length = (int)strlen(response);
            if (uart_write_bytes(port, response, length) != length ||
                uart_write_bytes(port, "\n", 1) != 1) {
                /* Unknown response delivery: do not re-execute the command. */
                puts("DMPBENCH_SERIAL_WRITE_FAILED");
            }
            used = 0;
            discarded = 0;
        } else if (!discarded) {
            if (used == sizeof(line) - 1 || c == 0 ||
                (c < 32 && c != '\r' && c != '\t') || c > 126) discarded = 1;
            else line[used++] = (char)c;
        }
    }
}
