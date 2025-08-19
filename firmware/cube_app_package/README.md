# Cube Application Package

Copy this entire `cube_app_package/` folder contents into your CubeIDE project.
Recommended layout after copy:
```
YourCubeProject/
  Core/
  Drivers/
  Middlewares/
  app/        <-- create
    (place *.c / *.h from this package here)
  config/     <-- optional separate folder for config.h
```

## Files Provided
- app_main.c / app_main.h : High-level application init & loop
- dns_batch.c / dns_batch.h : Domain ring & JSON builder
- dns_capture.c / dns_capture.h : DNS capture stub (currently seeds sample domains)
- net_client.c / net_client.h : HTTP POST + time helper
- hmac_sha256.c / hmac_sha256.h : HMAC-SHA256 implementation
- util.c / util.h : Logging + helpers
- config.h : Central configuration (edit BACKEND_HOST, DEVICE_ID, DEVICE_SECRET_HEX)

Optional: lwip.c / lwip.h only if you are NOT using Cube's generated LwIP glue. If Cube generates `lwip.c`, prefer Cube’s version and omit these two.

## Integrate Steps (Recap)
1. Generate CubeMX project (ETH RMII, LwIP DHCP, USART1 @115200).
2. Copy package files into `app/` (and `config/` if you separate config.h).
3. Add include path (Project Properties > C/C++ Build > Includes) for `app`.
4. Edit `Core/Src/main.c`:
   ```c
   #include "app_main.h"
   ...
   int main(void){
     HAL_Init();
     SystemClock_Config();
     MX_GPIO_Init();
     MX_USART1_UART_Init();
     MX_LWIP_Init();
     APP_Init();
     while(1){
       MX_LWIP_Process();
       APP_Loop();
     }
   }
   ```
5. Implement `int uart_tx_char(char c)` (either in main.c or a new file) calling `HAL_UART_Transmit(&huart1,(uint8_t*)&c,1,10);`
6. Set correct backend IP in `config.h`.
7. Build & flash.
8. Monitor UART logs.

## Remove / Avoid Duplicates
Do NOT also copy any old `main.c`, MSP, IT, or clock init files from this repo—Cube owns those.

## Switching from Simulated to Real DNS
Remove `seed_domains_once()` call in `app_main.c` once real capture implemented.

## Minimal Time Sync
If `/api/time` endpoint not available, have `sync_time_with_server()` return 0 success or ignore; current code tolerates skew.

## Troubleshooting Quick Table
| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| No UART output | Missing uart_tx_char implementation | Add function as in step 5 |
| POST FAIL rc=-1 | DNS resolve fail (BACKEND_HOST) | Use raw IP or ensure DNS server via DHCP |
| POST FAIL rc=-2 | Non-200 HTTP | Check backend route & signature headers |
| No IP assigned | RMII wiring / no REF_CLK | Verify PHY wiring & Cube ETH config |

## License / Attribution
Internal project component. Adapt freely within this project.
