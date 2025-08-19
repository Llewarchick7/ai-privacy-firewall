# STM32F407VET6 + LAN8760 DNS Monitoring System Integration Guide

This guide provides step-by-step instructions for integrating the DNS monitoring firmware with STM32F407VET6 MCU and LAN8760 Ethernet PHY using STM32CubeMX and STM32CubeIDE.

## Hardware Requirements

- **MCU**: STM32F407VET6 (512KB Flash, 128KB RAM, 100-pin LQFP)
- **Ethernet PHY**: LAN8760 (RMII interface)
- **Debug Interface**: ST-Link v2/v3 or compatible
- **Power Supply**: 3.3V regulated supply
- **Crystal**: 25MHz for HSE (recommended for stable Ethernet timing)

## STM32CubeMX Configuration

### 1. Project Creation
1. Create new STM32CubeMX project
2. Select STM32F407VET6 part number
3. Set project name (e.g., "DNS_Monitor_F407")

### 2. Clock Configuration
```
HSE: 25MHz (external crystal)
PLL: 
  - PLL Source: HSE
  - PLLM: 25
  - PLLN: 336
  - PLLP: 2
  - PLLQ: 7
System Clock: 168MHz
APB1: 42MHz (for Ethernet)
APB2: 84MHz
```

### 3. Ethernet Configuration
```
Mode: RMII
Pins:
  - ETH_RMII_REF_CLK: PA1
  - ETH_RMII_MDIO: PA2
  - ETH_RMII_MDC: PC1
  - ETH_RMII_CRS_DV: PA7
  - ETH_RMII_RXD0: PC4
  - ETH_RMII_RXD1: PC5
  - ETH_RMII_TX_EN: PG11 (or PB11)
  - ETH_RMII_TXD0: PG13 (or PB12)
  - ETH_RMII_TXD1: PG14 (or PB13)

Additional:
  - PHY Reset: Configure a GPIO pin (e.g., PE2) for PHY reset
  - PHY Address: 0 (default for LAN8760)
```

### 4. LWIP Configuration
```
Mode: Enabled
Key Settings:
  - LWIP_DHCP: Enabled
  - LWIP_DNS: Enabled
  - MEMP_NUM_NETCONN: 8
  - MEMP_NUM_TCP_PCB: 5
  - TCP_MSS: 1460
  - TCP_SND_BUF: 2920
  - TCP_WND: 2920
  - PBUF_POOL_SIZE: 16
```

### 5. UART Configuration (for debug output)
```
USART1:
  - Mode: Asynchronous
  - Baud Rate: 115200
  - Word Length: 8 bits
  - Parity: None
  - Stop Bits: 1
  - TX Pin: PA9 (or PB6)
  - RX Pin: PA10 (or PB7)
```

### 6. GPIO Configuration
```
LED (optional): PC13 (onboard LED on many F407 boards)
PHY Reset: PE2 (GPIO_Output, initially High)
```

### 7. NVIC Configuration
```
Ethernet global interrupt: Enabled, Priority 5
USART1 global interrupt: Enabled, Priority 6
```

## CubeIDE Integration

### 1. Copy Firmware Files
```bash
# In your CubeIDE project directory:
mkdir -p Core/Src/app
mkdir -p Core/Inc/app

# Copy all files from cube_app_package:
cp firmware/cube_app_package/*.c Core/Src/app/
cp firmware/cube_app_package/*.h Core/Inc/app/
```

### 2. Project Settings
1. Right-click project → Properties
2. C/C++ Build → Settings → Tool Settings → MCU GCC Compiler → Include paths
3. Add: `../Core/Inc/app`

### 3. Modify main.c
Replace the main function in `Core/Src/main.c`:

```c
/* USER CODE BEGIN Includes */
#include "app_main.h"
/* USER CODE END Includes */

/* USER CODE BEGIN 2 */
// Initialize the application
APP_Init();
/* USER CODE END 2 */

/* Infinite loop */
/* USER CODE BEGIN WHILE */
while (1)
{
  /* USER CODE END WHILE */

  /* USER CODE BEGIN 3 */
  // Process LWIP stack
  MX_LWIP_Process();
  
  // Process DNS monitoring application
  APP_Loop();
}
/* USER CODE END 3 */
```

### 4. Add STM32 Defines
In Project Properties → C/C++ Build → Settings → MCU GCC Compiler → Preprocessor:
Add define: `STM32F407xx`

### 5. Memory Configuration
Ensure sufficient stack and heap in the linker script:
```
_Min_Heap_Size = 0x1000;   /* 4KB heap */
_Min_Stack_Size = 0x2000;  /* 8KB stack */
```

## Hardware Connections

### LAN8760 to STM32F407VET6 RMII Interface
```
LAN8760 Pin  | STM32 Pin | Signal
-------------|-----------|--------
REF_CLK (9)  | PA1       | ETH_RMII_REF_CLK
MDIO (18)    | PA2       | ETH_RMII_MDIO  
MDC (17)     | PC1       | ETH_RMII_MDC
CRS_DV (10)  | PA7       | ETH_RMII_CRS_DV
RXD0 (11)    | PC4       | ETH_RMII_RXD0
RXD1 (12)    | PC5       | ETH_RMII_RXD1
TX_EN (13)   | PG11      | ETH_RMII_TX_EN
TXD0 (14)    | PG13      | ETH_RMII_TXD0
TXD1 (15)    | PG14      | ETH_RMII_TXD1
nRST (16)    | PE2       | GPIO_Output
```

### Power Connections
```
VDD3A (19)   | 3.3V      | Analog supply
VDD1A (20)   | 3.3V      | Digital supply
VDD2A (21)   | 3.3V      | Digital supply
VSS (22)     | GND       | Ground
```

### Crystal Oscillator
```
XTAL1 (3)    | 25MHz Crystal
XTAL2 (4)    | 25MHz Crystal
```

## Configuration Customization

Edit `Core/Inc/app/config.h` for your network environment:

```c
#define FW_VERSION "1.0.0"
#define BACKEND_HOST "192.168.1.100"        // Your server IP
#define BACKEND_PORT 8000                    // Your server port
#define BACKEND_INGEST_PATH "/api/dns/ingest-lite"
#define DEVICE_ID "aa:bb:cc:dd:ee:ff"        // Unique device identifier
#define DEVICE_SECRET_HEX "your_64_char_hex_secret_here" // 256-bit secret
#define BATCH_INTERVAL_MS 3000               // Send every 3 seconds
#define MAX_DOMAINS_PER_BATCH 60             // Max domains per transmission
```

## Build and Flash

### Build Process
1. Clean project: Project → Clean
2. Build project: Project → Build All (Ctrl+B)
3. Resolve any compilation errors

### Flashing
1. Connect ST-Link to STM32F407VET6
2. Run → Debug As → STM32 MCU C/C++ Application
3. Or use Run → Run As → STM32 MCU C/C++ Application

### Monitoring
1. Open serial terminal (115200 baud, 8N1)
2. Connect to UART1 (PA9/PA10)
3. Reset the board
4. You should see initialization messages:

```
FW v1.0.0 init
Config validation complete
Network ready - DHCP assigned IP
Time synced
POST n=2
POST OK 2
```

## Troubleshooting

### Common Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| No UART output | Silent operation | Check UART pins, baud rate, and uart_tx_char implementation |
| Ethernet not working | No IP assignment | Verify RMII wiring, clock configuration, PHY reset |
| DNS resolution fails | POST FAIL rc=-1 | Check DHCP settings, DNS server assignment |
| Authentication fails | POST FAIL rc=-2 | Verify DEVICE_SECRET_HEX and backend authentication |
| Build errors | Compilation fails | Check include paths, STM32F407xx define, file locations |

### Debug Steps
1. **UART Output**: First ensure debug output works
2. **Ethernet Link**: Check if PHY indicates link up
3. **DHCP**: Verify IP address assignment
4. **DNS Resolution**: Test backend hostname resolution
5. **HTTP Communication**: Verify POST requests reach backend

### Performance Optimization
- Enable compiler optimization (O2 or O3)
- Use DMA for UART if high debug output volume
- Consider hardware crypto acceleration for HMAC-SHA256
- Adjust LWIP buffer sizes based on available RAM

## Security Considerations

1. **Secret Management**: Store DEVICE_SECRET_HEX securely
2. **Firmware Protection**: Enable read protection on STM32
3. **Network Security**: Use HTTPS if backend supports it
4. **Update Mechanism**: Plan for secure firmware updates

## Next Steps

1. Test the basic functionality with sample domains
2. Implement real DNS packet capture (replace seed_domains_once())
3. Add network packet filtering
4. Optimize for production deployment
5. Add error recovery and watchdog functionality

## Support

For hardware-specific issues:
- STM32F407VET6: Reference Manual RM0090
- LAN8760: Microchip datasheet
- CubeMX/CubeIDE: ST documentation

For firmware issues:
- Check the troubleshooting table above
- Verify configuration in config.h
- Monitor UART debug output for error messages