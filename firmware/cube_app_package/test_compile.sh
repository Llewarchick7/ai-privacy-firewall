#!/bin/bash
# Simple compilation test for firmware package
# This tests basic syntax and header dependencies

echo "Testing firmware package compilation..."

cd /home/runner/work/ai-privacy-firewall/ai-privacy-firewall/firmware/cube_app_package

# Test basic C compilation with minimal flags
echo "Testing C file syntax..."

# Create a simple test that includes all headers
cat > test_compile.c << 'EOF'
/* Test compilation of all firmware components */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/* Mock STM32 HAL for testing */
typedef struct {
    uint32_t dummy;
} UART_HandleTypeDef;

#define HAL_GetTick() ((uint32_t)1000)
#define HAL_UART_Transmit(huart, data, len, timeout) 0
#define STM32F407xx

/* Mock LWIP for testing */
struct netif { int dummy; };
struct netif *netif_default = NULL;
int dhcp_supplied_address(struct netif *netif) { return 1; }

UART_HandleTypeDef huart1;

/* Include all our headers */
#include "config.h"
#include "app_main.h"
#include "dns_batch.h"
#include "dns_capture.h" 
#include "hmac_sha256.h"
#include "net_client.h"
#include "util.h"

/* Test function to ensure all symbols are accessible */
int test_function(void) {
    config_validate();
    APP_Init();
    return 0;
}
EOF

# Try to compile the test
gcc -c test_compile.c -I. -DSTM32F407xx -o test_compile.o 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Basic compilation test passed!"
    rm -f test_compile.c test_compile.o
else
    echo "❌ Compilation test failed - see errors above"
fi

echo "Compilation test complete."