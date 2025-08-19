#pragma once
#include <stdint.h>
int uart_tx_char(char c); /* Implement in Cube project */
void logf(const char *fmt,...);
void hexdump(const void *data,int len);
