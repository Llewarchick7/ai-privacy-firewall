#pragma once
#define FW_VERSION "0.1.0"
#define BACKEND_HOST "192.168.1.100"
#define BACKEND_PORT 8000
#define BACKEND_INGEST_PATH "/api/dns/ingest-lite"
#define DEVICE_ID "aa:bb:cc:dd:ee:ff"
#define DEVICE_SECRET_HEX "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define BATCH_INTERVAL_MS 3000
#define MAX_DOMAINS_PER_BATCH 60
#define RING_CAPACITY 256
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define LOG_ENABLE_DEBUG 1
void config_validate();
