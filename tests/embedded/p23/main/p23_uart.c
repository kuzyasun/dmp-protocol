#include "p23_uart.h"

#include "driver/uart.h"
#include "freertos/FreeRTOS.h"

void p23_uart_start(void)
{
    const uart_config_t configuration = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &configuration));
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 2048, 0, 0, NULL, 0));
}

size_t p23_uart_read(uint8_t *bytes, size_t length)
{
    int read = uart_read_bytes(UART_NUM_0, bytes, length, portMAX_DELAY);
    return read > 0 ? (size_t)read : 0U;
}

int p23_uart_write(const uint8_t *bytes, size_t length)
{
    int written = uart_write_bytes(UART_NUM_0, bytes, length);
    return written >= 0 && (size_t)written == length;
}
