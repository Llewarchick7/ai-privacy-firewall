#pragma once
#include <stdint.h>
#include <stdbool.h>
int dns_capture_init(void);
void dns_capture_process(void);
int get_network_ready_status(void); /* Provided by lwip glue or custom */
int sync_time_with_server(void);     /* Implement network time sync */
