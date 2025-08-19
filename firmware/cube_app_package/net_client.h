#pragma once
#include <stdint.h>
uint32_t now_epoch_seconds();
int http_post_ingest(const char *host,uint16_t port,const char *path,const char *device_id,const char *timestamp_str,const char *hmac_hex,const char *json_body,int timeout_ms);
