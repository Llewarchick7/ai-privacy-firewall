# �️ AI Privacy Firewall

An embedded AI-powered DNS firewall device that plugs into household, company, or defense networks to parse DNS requests and flag anomalies, protecting users from suspicious and dangerous network activity.

## 🚀 Features

- **Real-time DNS Monitoring**: Intercepts and analyzes all DNS queries on your network
- **AI-Powered Threat Detection**: Uses machine learning to identify malicious domains, phishing attempts, and suspicious patterns
- **Multiple Detection Methods**:
  - Domain reputation checking
  - Heuristic analysis
  - DNS tunneling detection
  - Domain Generation Algorithm (DGA) detection
  - Behavioral pattern analysis
- **Embedded Device Support**: Runs on Raspberry Pi or similar embedded devices
- **Web Dashboard**: Beautiful real-time monitoring interface
- **User Management**: Multi-role authentication and user management
- **Device Management**: Support for multiple firewall devices per user
- **Threat Intelligence**: Integration with external threat intelligence APIs
- **Privacy-Focused**: Local processing with optional cloud analysis

## 🏗️ Architecture

```
[Network Traffic] → [Embedded Device] → [DNS Analysis] → [AI Threat Detection] → [Block/Allow Decision]
                                    ↓
[FastAPI Backend] → [Database] → [Web Dashboard]
```

### Components

- **Backend (FastAPI)**: Handles device registration, threat analysis, and user management
- **AI Service**: Machine learning models for threat detection and domain classification
- **Device Monitor**: Embedded script that captures and analyzes DNS traffic
- **Web Dashboard**: Real-time visualization of network security status
- **Database**: PostgreSQL for storing users, devices, queries, and threat data

## 🔧 Installation & Setup

### Prerequisites

- Python 3.10+
- PostgreSQL database
- Node.js (for dashboard development, optional)

### Backend Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd ai-privacy-firewall
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials and API keys
   ```

4. **Set up the database**:
   ```bash
   # Create PostgreSQL database
   createdb ai_privacy_firewall
   
   # Database tables will be created automatically on first run
   ```

5. **Start the backend server**:
   ```bash
   cd backend
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

### Device Setup (Raspberry Pi)

1. **Install on Raspberry Pi**:
   ```bash
   # Copy device files to Raspberry Pi
   scp -r device/ pi@your-pi-ip:/home/pi/dns-firewall/
   
   # SSH into Pi
   ssh pi@your-pi-ip
   cd /home/pi/dns-firewall
   ```

2. **Install dependencies on Pi**:
   ```bash
   sudo apt update
   sudo apt install python3-pip tcpdump
   pip3 install -r requirements.txt
   ```

3. **Configure device**:
   ```bash
   cp config.json.example config.json
   # Edit config.json with your backend API URL and device settings
   ```

4. **Run as systemd service** (optional):
   ```bash
   sudo cp dns-firewall.service /etc/systemd/system/
   sudo systemctl enable dns-firewall
   sudo systemctl start dns-firewall
   ```

### Dashboard Setup

1. **Open the dashboard**:
   - Navigate to `dashboard/index.html` in your web browser
   - Or serve it using a web server:
   ```bash
   cd dashboard
   python -m http.server 8080
   ```

2. **Access at**: `http://localhost:8080`

## 🤖 AI Models and Detection

### Network Traffic Analysis

Unlike traditional web scraping, this system performs **DNS/SNI/IP traffic analysis** at the network protocol level:

- **DNS Query Monitoring**: Captures all domain resolution requests (UDP port 53)
- **TLS SNI Extraction**: Reads domain names from TLS handshakes (even on encrypted HTTPS)
- **IP Metadata Analysis**: Tracks destination IPs, countries, and organizations
- **MAC Address Mapping**: Associates traffic with specific devices on the network
- **Behavioral Fingerprinting**: Creates traffic patterns unique to each device

### What We Can See Without Decrypting HTTPS

| Data Type | Description | Source |
|-----------|-------------|--------|
| DNS Queries | Domain names being resolved | UDP port 53 packets |
| TLS SNI | Server names in TLS handshakes | TLS ClientHello packets |
| Destination IPs | Target servers and geolocation | IP packet headers |
| Request Timing | Frequency and patterns | Packet timestamps |
| Device Identity | MAC addresses and device types | Ethernet frame headers |

### Threat Detection Methods

1. **Domain Reputation**: Checks domains against known threat intelligence feeds
2. **Heuristic Analysis**: Analyzes domain characteristics (length, TLD, keywords)
3. **DNS Tunneling Detection**: Identifies suspicious DNS query patterns
4. **DGA Detection**: Detects algorithmically generated domains used by malware
5. **Behavioral Analysis**: Monitors query patterns over time

### Model Training

Train your own models with:

```bash
cd ai/models
python dns_classifier.py
```

This creates a Random Forest classifier trained on domain features for threat detection. The AI module is separate from the backend for better organization and performance.

## 📚 API Documentation

### Authentication

All API endpoints require authentication. First, register a user and obtain a token:

```bash
# Register user
curl -X POST "http://localhost:8000/api/users/register" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Admin User",
    "email": "admin@example.com", 
    "password": "securepassword",
    "role": "org_admin"
  }'

# Login to get token
curl -X POST "http://localhost:8000/api/users/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@example.com&password=securepassword"
```

### Key Endpoints

- `POST /api/dns/devices` - Register a new firewall device
- `GET /api/dns/devices` - List user's devices
- `POST /api/dns/dns-queries` - Log DNS query (called by device)
- `GET /api/dns/threats` - Get threat detections
- `GET /api/dns/analytics/network` - Get network analytics
- `PUT /api/dns/devices/{id}/settings` - Update device settings

### Example Usage

```bash
# Register a device
curl -X POST "http://localhost:8000/api/dns/devices" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "device_001",
    "name": "Home Router",
    "ip_address": "192.168.1.1",
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "location": "Living Room"
  }'

# Log a DNS query
curl -X POST "http://localhost:8000/api/dns/dns-queries" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": 1,
    "query_name": "suspicious-domain.tk",
    "query_type": "A",
    "client_ip": "192.168.1.100"
  }'
```

## 🛠️ Configuration

### Device Configuration (`device/config.json`)

```json
{
    "device_id": "unique_device_identifier",
    "api_url": "http://your-backend-server.com:8000/api",
    "api_token": "device_authentication_token",
    "monitor_interface": "eth0",
    "log_level": "INFO",
    "local_blocklists": [
        "/etc/dns-firewall/blocklists/malware.txt"
    ]
}
```

### Environment Variables (`.env`)

```env
SECRET_KEY=your_super_secret_key
DATABASE_URL=postgresql://user:password@localhost/ai_privacy_firewall

# Optional: External API keys for enhanced threat intelligence
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SAFEBROWSING_API_KEY=your_google_safebrowsing_key
```

## 🔒 Security Features

- **JWT Authentication**: Secure API access with role-based permissions
- **Two-Factor Authentication**: Optional 2FA for enhanced security
- **Privacy Settings**: Granular control over data collection and sharing
- **Audit Logging**: Complete audit trail of all user actions
- **Encrypted Storage**: Sensitive data encrypted at rest
- **Rate Limiting**: Protection against API abuse

## 📊 Dashboard Features

- **Real-time Monitoring**: Live updates of network activity
- **Threat Visualization**: Charts and graphs of detected threats
- **Device Management**: Monitor and configure multiple devices
- **Alert System**: Immediate notifications of critical threats
- **Historical Analysis**: Trends and patterns over time
- **Export Capabilities**: Download reports and data

## 🚀 Deployment

### Production Deployment

1. **Use a production WSGI server**:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.main:app
   ```

2. **Set up reverse proxy** (nginx):
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. **Use PostgreSQL in production**:
   - Set up a dedicated PostgreSQL server
   - Update DATABASE_URL in production environment

### Hardware Requirements

**Minimum (Raspberry Pi 4)**:
- 2GB RAM
- 16GB SD card
- Ethernet connection

**Recommended (Mini PC)**:
- 4GB RAM
- 64GB storage
- Gigabit Ethernet
- Multiple network interfaces

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📧 Email: support@ai-privacy-firewall.com
- 💬 Discord: [Join our community](https://discord.gg/ai-privacy-firewall)
- 📖 Documentation: [Full documentation](https://docs.ai-privacy-firewall.com)
- 🐛 Issues: [GitHub Issues](https://github.com/your-repo/ai-privacy-firewall/issues)

## 🔮 Roadmap

- [ ] Advanced ML models (LSTM, Transformer-based)
- [ ] Integration with more threat intelligence APIs
- [ ] Mobile app for monitoring
- [ ] Hardware appliance versions
- [ ] Enterprise features (SIEM integration, compliance reporting)
- [ ] Zero-trust network architecture support
- [ ] IoT device classification and protection
