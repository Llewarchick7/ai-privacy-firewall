#pragma once
#include <stdint.h>
#include "dns_batch.h"
#ifdef __cplusplus
extern "C" {
#endif
void APP_Init(void);
void APP_Loop(void);
uint16_t APP_PendingDomains(void);
#ifdef __cplusplus
}
#endif
