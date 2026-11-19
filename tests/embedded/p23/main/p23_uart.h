#ifndef DMP_P23_UART_H
#define DMP_P23_UART_H

#include <stddef.h>
#include <stdint.h>

void p23_uart_start(void);
size_t p23_uart_read(uint8_t *bytes, size_t length);
int p23_uart_write(const uint8_t *bytes, size_t length);

#endif
