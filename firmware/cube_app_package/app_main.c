/** App main orchestration (Cube drop-in) */
#include <string.h>
#include <stdio.h>
#include "config.h"
#include "app_main.h"
#include "dns_batch.h"
#include "dns_capture.h"
#include "hmac_sha256.h"
#include "net_client.h"
#include "util.h"

extern void MX_LWIP_Process(void);
extern UART_HandleTypeDef huart1; /* Provided by Cube init */

static domain_ring_t ring;
static uint8_t secret[32];
static uint32_t last_batch_ms;
static int time_synced;
static domain_item_t batch_buf[MAX_DOMAINS_PER_BATCH];

static int hexval(char c){ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return 10+c-'a'; if(c>='A'&&c<='F') return 10+c-'A'; return -1; }
static void parse_secret(){ const char *h=DEVICE_SECRET_HEX; if(strlen(h)!=64){ logf("SECRET LEN ERR"); return;} for(int i=0;i<32;i++){ int hi=hexval(h[i*2]); int lo=hexval(h[i*2+1]); secret[i]=(uint8_t)((hi<<4)|lo);} }
static void seed_domains_once(){ 
    static int s=0; 
    if(s) return; 
    s=1; 
    
    /* Seed with realistic demo domains for testing */
    uint32_t ts = now_epoch_seconds();
    ring_push(&ring,"google.com", ts); 
    ring_push(&ring,"github.com", ts + 1); 
    ring_push(&ring,"stackoverflow.com", ts + 2);
    ring_push(&ring,"microsoft.com", ts + 3);
    ring_push(&ring,"amazon.com", ts + 4);
    ring_push(&ring,"cloudflare.com", ts + 5);
    
    logf("Seeded %d demo domains for testing", 6);
}
static void maybe_send(){ 
    if(!get_network_ready_status()) return; 
    
    uint32_t now = sys_now(); 
    if(now - last_batch_ms < BATCH_INTERVAL_MS) return; 
    last_batch_ms = now; 
    
    uint16_t n = ring_pop_batch(&ring, batch_buf, MAX_DOMAINS_PER_BATCH); 
    if(!n) return; 
    
    char json[2048]; 
    int jl = build_compact_json(batch_buf, n, json, sizeof json); 
    if(jl < 0){ 
        logf("JSON OVR"); 
        return;
    } 
    
    char ts[16]; 
    snprintf(ts, sizeof ts, "%lu", (unsigned long)now_epoch_seconds()); 
    
    char combo[2300]; 
    size_t bl = strlen(json), tl = strlen(ts); 
    if(bl + 1 + tl >= sizeof combo){ 
        logf("COMBO OVR"); 
        return;
    } 
    
    memcpy(combo, json, bl); 
    combo[bl] = '.'; 
    memcpy(combo + bl + 1, ts, tl); 
    combo[bl + 1 + tl] = '\0';  /* Ensure null termination */
    
    uint8_t mac[32]; 
    hmac_sha256(secret, sizeof secret, (uint8_t*)combo, bl + 1 + tl, mac); 
    
    char machex[65]; 
    to_hex(mac, 32, machex); 
    
    logf("POST n=%u", n); 
    int rc = http_post_ingest(BACKEND_HOST, BACKEND_PORT, BACKEND_INGEST_PATH, 
                              DEVICE_ID, ts, machex, json, 3000); 
    if(!rc) 
        logf("POST OK %u", n); 
    else 
        logf("POST FAIL rc=%d", rc);
} 

void APP_Init(void){ 
    ring_init(&ring); 
    config_validate();
    parse_secret(); 
    dns_capture_init(); 
    logf("FW v%s init", FW_VERSION); 
}
void APP_Loop(void){ 
    dns_capture_process(); 
    
    if(get_network_ready_status() && !time_synced){ 
        if(sync_time_with_server() == 0){ 
            time_synced = 1; 
            logf("Time synced"); 
        }
    } 
    
    seed_domains_once(); 
    maybe_send(); 
}
uint16_t APP_PendingDomains(void){ return ring.count; }
