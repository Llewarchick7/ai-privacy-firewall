#pragma once
#include <stdint.h>
#include <stdbool.h>

/* DNS capture and network monitoring functions */
int dns_capture_init(void);
void dns_capture_process(void);

/* Network status functions */
int get_network_ready_status(void); /* Returns 1 when DHCP assigns IP */
int sync_time_with_server(void);     /* Network time sync (NTP) */
