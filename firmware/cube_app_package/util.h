#pragma once
#include <stdint.h>

/* System timing functions */
uint32_t sys_now(void); /* Returns milliseconds since boot */

/* UART communication */
int uart_tx_char(char c); /* Implement in Cube project or use provided implementation */

/* Logging and debug functions */
void logf(const char *fmt,...);
void hexdump(const void *data,int len);
