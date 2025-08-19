#include "util.h"
#include <stdarg.h>
#include <stdio.h>

/* STM32 HAL includes for UART and timing */
#ifdef STM32F407xx
#include "stm32f4xx_hal.h"
extern UART_HandleTypeDef huart1;
#endif

/* System time functions for STM32 */
uint32_t sys_now(void) {
#ifdef STM32F407xx
    return HAL_GetTick(); /* Returns milliseconds since boot */
#else
    /* Placeholder for non-STM32 builds */
    return 0;
#endif
}

/* UART implementation for STM32 */
int uart_tx_char(char c) {
#ifdef STM32F407xx
    HAL_UART_Transmit(&huart1, (uint8_t*)&c, 1, 10);
    return 1;
#else
    /* Placeholder for non-STM32 builds - could output to stdout */
    putchar(c);
    return 1;
#endif
}

void logf(const char *fmt,...){ 
    char buf[256]; 
    va_list ap; 
    va_start(ap,fmt); 
    vsnprintf(buf,sizeof buf,fmt,ap); 
    va_end(ap); 
    for(char *p=buf; *p; ++p) uart_tx_char(*p); 
    uart_tx_char('\r'); 
    uart_tx_char('\n'); 
}

void hexdump(const void *data,int len){ 
    const unsigned char *p=(const unsigned char*)data; 
    char line[8]; 
    int col=0; 
    for(int i=0;i<len;i++){ 
        int n=snprintf(line,sizeof line,"%02x ",p[i]); 
        for(int j=0;j<n;j++) uart_tx_char(line[j]); 
        if(++col==16){ 
            uart_tx_char('\r'); 
            uart_tx_char('\n'); 
            col=0; 
        }
    } 
    if(col){ 
        uart_tx_char('\r'); 
        uart_tx_char('\n'); 
    }
}
