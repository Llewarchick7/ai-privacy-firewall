# 📦 Module Overview

This document provides a detailed breakdown of each module in the AI Privacy Firewall project, including their responsibilities, dependencies, and key files.

## Project Structure

```
ai-privacy-firewall/
├── ai/                     # AI/ML Module
├── backend/                # API Backend
├── dashboard/              # Web Interface
├── device/                 # Embedded Device Code
├── dns_monitor/            # High-Performance C++ DNS Monitoring
├── docs/                   # Documentation
├── tests/                  # Test Suite
└── data/                   # Sample Data & Models
```

## 🤖 AI Module (`ai/`)

**Purpose**: Contains all machine learning models, threat detection algorithms, and AI-related utilities.

### Structure
```
ai/
├── __init__.py
├── models/
│   ├── __init__.py
│   └── dns_classifier.py      # ML models for DNS threat detection
├── services/
│   ├── __init__.py
│   └── threat_detector.py     # Real-time threat analysis
└── utils/
    ├── __init__.py
    └── feature_extractor.py   # DNS feature engineering
```

### Key Components

#### `ai/models/dns_classifier.py`
- **Random Forest Classifier**: Domain-based threat detection
- **Isolation Forest**: Anomaly detection for unusual patterns
- **Model Training Pipeline**: Automated training and validation
- **Feature Engineering**: Domain length, TLD analysis, keyword detection

#### `ai/services/threat_detector.py`
- **Real-time Analysis**: Process DNS queries as they happen
- **Risk Scoring**: Calculate threat probability (0-100)
- **Pattern Recognition**: Identify DGA domains and DNS tunneling
- **Threat Intelligence**: Integration with external APIs

#### `ai/utils/feature_extractor.py`
- **Domain Features**: Length, entropy, character frequency
- **Network Features**: Query frequency, timing patterns
- **Device Features**: Device-specific behavioral patterns
- **Temporal Features**: Time-based analysis

### Dependencies
- `scikit-learn`: ML algorithms
- `pandas`: Data manipulation
- `numpy`: Numerical computing
- `joblib`: Model persistence

### Usage Examples
```python
from ai.models.dns_classifier import DNSClassifier
from ai.services.threat_detector import ThreatDetector

# Initialize models
classifier = DNSClassifier()
classifier.train()

# Detect threats
detector = ThreatDetector(classifier)
risk_score = detector.analyze_query("suspicious-domain.tk")
```

## 🔧 Backend Module (`backend/`)

**Purpose**: FastAPI-based REST API that handles authentication, data storage, and business logic.

### Structure
```
backend/
├── main.py                 # FastAPI application entry point
├── dependencies.py         # Dependency injection
├── database.py            # Database connection
├── config/
│   └── settings.py        # Configuration management
├── models/                # SQLAlchemy ORM models
│   ├── dns_models.py      # DNS-related models
│   ├── users.py           # User and organization models
│   └── audit_log.py       # Audit logging models
├── routes/                # API endpoints
│   ├── dns.py             # DNS monitoring endpoints
│   ├── privacy.py         # Privacy control endpoints
│   └── users.py           # User management endpoints
├── schemas/               # Pydantic models
│   ├── dns_schemas.py     # DNS request/response schemas
│   ├── user_schemas.py    # User-related schemas
│   └── token_schema.py    # Authentication schemas
└── services/              # Business logic
    ├── auth.py            # Authentication service
    ├── logger.py          # Logging service
    └── oauth.py           # OAuth integration
```

### Key Components

#### `backend/routes/dns.py`
- **Device Management**: Register and configure devices
- **Query Logging**: Store DNS queries and responses
- **Threat Detection**: Integrate with AI module for analysis
- **Analytics**: Generate network insights and reports

#### `backend/models/dns_models.py`
- **Device**: Represents firewall devices
- **DNSQuery**: Individual DNS requests
- **ThreatDetection**: Threat analysis results
- **DomainReputation**: Domain reputation cache
- **NetworkSettings**: Per-device configuration

#### `backend/services/auth.py`
- **JWT Authentication**: Token-based security
- **Role-based Access**: Admin, user, device roles
- **Two-factor Authentication**: Optional TOTP
- **Session Management**: Secure session handling

### API Endpoints

#### Device Management
- `POST /api/dns/devices` - Register new device
- `GET /api/dns/devices` - List user devices
- `PUT /api/dns/devices/{id}` - Update device settings
- `DELETE /api/dns/devices/{id}` - Remove device

#### DNS Monitoring
- `POST /api/dns/dns-queries` - Log DNS query
- `GET /api/dns/queries` - Retrieve query history
- `GET /api/dns/threats` - Get threat detections
- `GET /api/dns/analytics/network` - Network analytics

#### User Management
- `POST /api/users/register` - User registration
- `POST /api/users/login` - User authentication
- `GET /api/users/profile` - User profile
- `PUT /api/users/profile` - Update profile

## 🖥️ Dashboard Module (`dashboard/`)

**Purpose**: Web-based user interface for monitoring, configuration, and analytics.

### Structure
```
dashboard/
├── index.html             # Main dashboard page
├── css/
│   └── styles.css         # Dashboard styling
├── js/
│   ├── app.js             # Main application logic
│   ├── api.js             # API communication
│   ├── charts.js          # Data visualization
│   └── websocket.js       # Real-time updates
└── assets/
    ├── images/            # UI images and icons
    └── fonts/             # Custom fonts
```

### Key Features

#### Real-time Monitoring
- Live DNS query feed
- Threat detection alerts
- Device status indicators
- Network activity graphs

#### Analytics Dashboard
- Historical threat trends
- Device-specific insights
- Privacy scoring
- Custom time ranges

#### Configuration Interface
- Device settings management
- Privacy controls
- Alert preferences
- User account settings

### Technology Stack
- **Vanilla JavaScript**: No framework dependencies
- **Chart.js**: Data visualization
- **WebSockets**: Real-time updates
- **CSS Grid/Flexbox**: Responsive layout

## 📱 Device Module (`device/`)

**Purpose**: Embedded device software for network monitoring and DNS interception.

### Structure
```
device/
├── dns_monitor.py         # Main monitoring daemon
├── config.json.example    # Configuration template
├── install.sh             # Device setup script
└── systemd/
    └── dns-firewall.service  # Systemd service file
```

### Key Components

#### `device/dns_monitor.py`
- **Packet Capture**: Monitor network interface
- **DNS Parsing**: Extract DNS queries and responses
- **Local Analysis**: Basic threat detection
- **API Communication**: Send data to backend
- **Configuration Management**: Handle device settings

#### Configuration Options
- **Network Interface**: Which interface to monitor
- **API Endpoint**: Backend server connection
- **Local Blocklists**: Offline threat blocking
- **Logging Level**: Debug/info/warning/error
- **Performance Settings**: Buffer sizes, timeouts

### Deployment Targets
- **Raspberry Pi 4**: Recommended for home networks
- **Intel NUC**: High-performance option
- **Custom Hardware**: Specialized network appliances
- **VM Deployment**: Virtualized environments

## ⚡ DNS Monitor Module (`dns_monitor/`)

**Purpose**: High-performance C++ engine for packet capture and DNS parsing with Python bindings.

### Structure
```
dns_monitor/
├── BUILD.md               # Build instructions and dependencies
├── CMakeLists.txt         # CMake build configuration
├── dns_monitor.h          # C++ header with class definitions
├── dns_monitor.cpp        # Core C++ implementation
├── python_bindings.cpp    # pybind11 Python integration
└── main.cpp              # Standalone test executable
```

### Key Components

#### `dns_monitor.h` & `dns_monitor.cpp`
- **High-Speed Packet Capture**: libpcap-based capture (100K+ packets/sec)
- **DNS Parsing Engine**: Zero-copy DNS packet parsing
- **Multi-threaded Processing**: Separate capture and upload threads
- **Memory Efficient**: Ring buffers and static allocation
- **Real-time Analysis**: Sub-millisecond DNS query processing

#### `python_bindings.cpp`
- **pybind11 Integration**: Seamless C++/Python interface
- **Async Compatible**: Works with Python asyncio
- **Configuration Bridge**: JSON config to C++ struct mapping
- **Statistics Reporting**: Real-time performance metrics

#### `main.cpp`
- **Standalone Testing**: Independent C++ executable
- **Performance Benchmarking**: Measure packets/second rates
- **Debug Mode**: Verbose logging for troubleshooting
- **Signal Handling**: Graceful shutdown on interrupt

### Performance Characteristics
- **Throughput**: 100,000+ packets/second on modest hardware
- **Latency**: <1ms average processing time per packet
- **Memory**: <50MB RAM usage during operation
- **CPU**: <10% CPU usage at 10K packets/second
- **Scalability**: Linear performance scaling with CPU cores

### Dependencies
- **libpcap**: Low-level packet capture
- **libcurl**: HTTP API communication
- **jsoncpp**: JSON configuration parsing
- **pybind11**: Python binding generation
- **pthread**: Multi-threading support

### Build Process
```bash
cd dns_monitor
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Integration with Python
```python
import dns_monitor_cpp

# Create configuration
config = dns_monitor_cpp.DeviceConfig()
config.device_id = "device_001"
config.monitor_interface = "eth0"

# Start monitoring
monitor = dns_monitor_cpp.DNSMonitor(config)
monitor.initialize()
monitor.start()

# Get statistics
stats = monitor.get_statistics()
print(f"DNS packets: {stats.dns_packets}")
```

### Use Cases
- **Production Deployment**: Enterprise-grade packet processing
- **Embedded Systems**: Raspberry Pi and ARM-based devices
- **High-Frequency Networks**: ISP and data center monitoring
- **Real-time Analysis**: Immediate threat detection and blocking

## 📊 Tests Module (`tests/`)

**Purpose**: Comprehensive testing suite for all components.

### Structure
```
tests/
├── conftest.py            # Pytest configuration
├── test_ai/               # AI module tests
│   ├── test_models.py     # ML model tests
│   ├── test_services.py   # Threat detection tests
│   └── test_utils.py      # Utility function tests
├── test_backend/          # Backend API tests
│   ├── test_routes.py     # Endpoint tests
│   ├── test_models.py     # Database model tests
│   └── test_auth.py       # Authentication tests
├── test_device/           # Device module tests
│   └── test_monitor.py    # DNS monitor tests
└── test_integration/      # End-to-end tests
    ├── test_full_flow.py  # Complete workflow tests
    └── test_performance.py # Performance benchmarks
```

### Testing Strategy
- **Unit Tests**: Individual component testing
- **Integration Tests**: Multi-component workflows
- **Performance Tests**: Load and stress testing
- **Security Tests**: Authentication and authorization

## 📈 Data Module (`data/`)

**Purpose**: Sample data, trained models, and datasets for development and testing.

### Structure
```
data/
├── models/                # Trained ML models
│   ├── dns_classifier.pkl # Trained classifier
│   └── feature_scaler.pkl # Feature normalization
├── samples/               # Sample datasets
│   ├── dns_queries.csv    # Example DNS queries
│   ├── threats.json       # Threat examples
│   └── device_profiles.json # Device fingerprints
└── training/              # Training datasets
    ├── benign_domains.txt # Known good domains
    ├── malware_domains.txt # Known bad domains
    └── features.csv       # Extracted features
```

## 🔄 Module Interactions

### Data Flow Between Modules
```
Device Monitor → Backend API → AI Analysis → Database Storage
      ↓              ↓             ↓             ↓
   Network Data    REST API    Threat Scores   Persistence
      ↓              ↓             ↓             ↓
   Dashboard ← WebSocket ← Analytics ← Query Engine
```

### Dependency Graph
```
AI ←── Backend ←── Dashboard
↓         ↓          ↓
Device ←── Tests ←── Data
```

### Communication Protocols
- **HTTP/REST**: Backend ↔ Dashboard communication
- **WebSocket**: Real-time dashboard updates
- **TCP/UDP**: Device ↔ Backend communication
- **Database**: Backend ↔ PostgreSQL
- **File System**: AI ↔ Model storage

## 🛠️ Development Workflow

### Adding New Features
1. **AI Enhancement**: Update models in `ai/models/`
2. **API Changes**: Modify backend routes and schemas
3. **UI Updates**: Update dashboard components
4. **Device Logic**: Modify monitoring behavior
5. **Testing**: Add comprehensive tests
6. **Documentation**: Update relevant docs

### Best Practices
- **Separation of Concerns**: Keep modules focused
- **Dependency Injection**: Use for testability
- **Error Handling**: Comprehensive error management
- **Logging**: Structured logging throughout
- **Configuration**: Environment-based config
- **Security**: Security-first development

This modular architecture enables independent development, testing, and deployment of each component while maintaining clear interfaces and dependencies.
