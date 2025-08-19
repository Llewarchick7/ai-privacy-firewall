#pragma once
#define FW_VERSION "1.0.0"
/* Update these for your network environment */
#define BACKEND_HOST "192.168.1.100"  /* Replace with your server IP */
#define BACKEND_PORT 8000
#define BACKEND_INGEST_PATH "/api/dns/ingest-lite"
/* Update with your unique device information */
#define DEVICE_ID "f4:07:ve:t6:la:n8"  /* STM32F407VET6 + LAN8760 identifier */
#define DEVICE_SECRET_HEX "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
/* Timing and capacity settings */
#define BATCH_INTERVAL_MS 5000  /* Send every 5 seconds for demo */
#define MAX_DOMAINS_PER_BATCH 20  /* Smaller batches for demo */
#define RING_CAPACITY 128  /* Reduced for memory efficiency */
/* Crypto settings */
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
/* Debug settings */
#define LOG_ENABLE_DEBUG 1
void config_validate();
