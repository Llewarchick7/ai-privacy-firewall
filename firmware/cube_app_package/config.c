#include "config.h"
#include "util.h"
#include <string.h>

void config_validate() {
    /* Validate DEVICE_SECRET_HEX */
    const char *secret = DEVICE_SECRET_HEX;
    if (strlen(secret) != 64) {
        logf("ERROR: DEVICE_SECRET_HEX must be exactly 64 hex characters");
        return;
    }
    
    for (int i = 0; i < 64; i++) {
        char c = secret[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            logf("ERROR: DEVICE_SECRET_HEX contains invalid character at position %d", i);
            return;
        }
    }
    
    /* Validate DEVICE_ID format (should be MAC address format) */
    const char *device_id = DEVICE_ID;
    if (strlen(device_id) != 17) {
        logf("WARNING: DEVICE_ID should be in MAC address format (xx:xx:xx:xx:xx:xx)");
    }
    
    /* Validate backend configuration */
    if (BACKEND_PORT == 0 || BACKEND_PORT > 65535) {
        logf("ERROR: BACKEND_PORT must be between 1 and 65535");
    }
    
    if (strlen(BACKEND_HOST) == 0) {
        logf("ERROR: BACKEND_HOST cannot be empty");
    }
    
    if (BATCH_INTERVAL_MS < 1000) {
        logf("WARNING: BATCH_INTERVAL_MS is very low (%d ms), may cause network congestion", BATCH_INTERVAL_MS);
    }
    
    if (MAX_DOMAINS_PER_BATCH > RING_CAPACITY) {
        logf("ERROR: MAX_DOMAINS_PER_BATCH (%d) cannot be larger than RING_CAPACITY (%d)", 
             MAX_DOMAINS_PER_BATCH, RING_CAPACITY);
    }
    
    logf("Config validation complete");
}