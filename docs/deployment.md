# 🚀 Deployment Guide

This guide covers deployment strategies for the AI Privacy Firewall across different environments, from home networks to enterprise and defense installations.

## 📋 Prerequisites

### Hardware Requirements

#### Minimum (Home Network)
- **Device**: Raspberry Pi 4 (4GB RAM)
- **Storage**: 32GB microSD card (Class 10)
- **Network**: Gigabit Ethernet
- **Power**: 5V 3A USB-C power supply
- **Optional**: Heat sink and fan

#### Recommended (Business Network)
- **Device**: Intel NUC or equivalent mini-PC
- **CPU**: Intel i5 or AMD Ryzen 5
- **RAM**: 8GB DDR4
- **Storage**: 256GB NVMe SSD
- **Network**: Dual Gigabit Ethernet ports
- **Backup**: UPS for power protection

#### Enterprise/Defense (High-Performance)
- **Device**: Rack-mount server or dedicated appliance
- **CPU**: Intel Xeon or AMD EPYC
- **RAM**: 32GB+ ECC memory
- **Storage**: RAID 1 SSDs (1TB+)
- **Network**: 10GbE interfaces
- **Security**: TPM 2.0, secure boot

### Software Requirements
- **OS**: Ubuntu 22.04 LTS (recommended) or Raspberry Pi OS
- **Python**: 3.10+
- **Database**: PostgreSQL 14+
- **Network**: Internet access for initial setup
- **Optional**: Docker and Docker Compose

## 🏠 Home Network Deployment

### Network Topology
```
Internet → Router → [AI Privacy Firewall] → Home Devices
              ↓
          WiFi Access Point
              ↓
          Mobile Devices
```

### Step 1: Raspberry Pi Setup

#### Initial OS Installation
```bash
# Flash Raspberry Pi OS Lite to SD card
# Enable SSH and configure WiFi if needed

# SSH into Pi
ssh pi@raspberrypi.local

# Update system
sudo apt update && sudo apt upgrade -y

# Install prerequisites
sudo apt install -y python3-pip python3-venv git postgresql postgresql-contrib
```

#### Network Configuration
```bash
# Configure network interfaces
sudo nano /etc/dhcpcd.conf

# Add static IP configuration
interface eth0
static ip_address=192.168.1.10/24
static routers=192.168.1.1
static domain_name_servers=8.8.8.8 8.8.4.4

# Enable packet forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
```

### Step 2: Application Installation

#### Clone and Setup
```bash
# Clone repository
git clone https://github.com/your-repo/ai-privacy-firewall.git
cd ai-privacy-firewall

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### Database Setup
```bash
# Create database
sudo -u postgres createdb ai_privacy_firewall
sudo -u postgres createuser --interactive ai_firewall

# Set password
sudo -u postgres psql -c "ALTER USER ai_firewall PASSWORD 'secure_password';"
```

#### Configuration
```bash
# Copy and edit configuration
cp device/config.json.example device/config.json
nano device/config.json
```

```json
{
    "device_id": "home_firewall_001",
    "api_url": "http://localhost:8000/api",
    "monitor_interface": "eth0",
    "log_level": "INFO",
    "database_url": "postgresql://ai_firewall:secure_password@localhost/ai_privacy_firewall"
}
```

### Step 3: Router Configuration

#### Bridge Mode Setup
```bash
# Configure router to use Pi as DNS server
# Router Admin Panel → DHCP Settings
# Primary DNS: 192.168.1.10 (Pi IP)
# Secondary DNS: 8.8.8.8
```

#### Traffic Mirroring (Advanced)
```bash
# For routers supporting port mirroring
# Mirror LAN traffic to Pi ethernet port
# Consult router documentation for specific steps
```

### Step 4: Service Installation

#### Systemd Service
```bash
# Copy service file
sudo cp systemd/ai-privacy-firewall.service /etc/systemd/system/

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable ai-privacy-firewall
sudo systemctl start ai-privacy-firewall

# Check status
sudo systemctl status ai-privacy-firewall
```

#### Service Configuration
```ini
# /etc/systemd/system/ai-privacy-firewall.service
[Unit]
Description=AI Privacy Firewall
After=network.target postgresql.service

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/ai-privacy-firewall
Environment=PATH=/home/pi/ai-privacy-firewall/venv/bin
ExecStart=/home/pi/ai-privacy-firewall/venv/bin/python device/dns_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 🏢 Business Network Deployment

### Network Architecture
```
Internet → Firewall → [AI Privacy Firewall Cluster] → Corporate Network
                              ↓
                      Central Management Server
                              ↓
                      SIEM Integration
```

### High Availability Setup

#### Load Balancer Configuration
```bash
# Install and configure nginx
sudo apt install nginx

# Load balancer config
sudo nano /etc/nginx/sites-available/ai-firewall
```

```nginx
upstream ai_firewall_backend {
    server 192.168.10.10:8000;
    server 192.168.10.11:8000;
    server 192.168.10.12:8000;
}

server {
    listen 80;
    server_name ai-firewall.company.com;
    
    location / {
        proxy_pass http://ai_firewall_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

#### Database Clustering
```bash
# PostgreSQL Primary-Replica setup
# Primary server (192.168.10.20)
sudo nano /etc/postgresql/14/main/postgresql.conf

# Enable replication
wal_level = replica
max_wal_senders = 3
archive_mode = on
archive_command = 'cp %p /var/lib/postgresql/archives/%f'
```

### Docker Deployment

#### Docker Compose Setup
```yaml
# docker-compose.yml
version: '3.8'

services:
  ai-firewall-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/ai_firewall
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - ./data:/app/data
    restart: unless-stopped

  db:
    image: postgres:14
    environment:
      POSTGRES_DB: ai_firewall
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
    depends_on:
      - ai-firewall-api
    restart: unless-stopped

volumes:
  postgres_data:
```

#### Container Deployment
```bash
# Build and deploy
docker-compose up -d

# Scale API instances
docker-compose up -d --scale ai-firewall-api=3

# Monitor logs
docker-compose logs -f ai-firewall-api
```

### SIEM Integration

#### Splunk Configuration
```bash
# Install Splunk Universal Forwarder
wget -O splunkforwarder.tgz 'https://download.splunk.com/...'
tar -xzf splunkforwarder.tgz
sudo mv splunkforwarder /opt/

# Configure inputs
sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
```

```ini
[monitor:///var/log/ai-firewall/*.log]
disabled = false
sourcetype = ai_firewall
index = security

[udp://514]
disabled = false
sourcetype = syslog
index = network
```

#### ELK Stack Integration
```yaml
# logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][log_type] == "ai_firewall" {
    json {
      source => "message"
    }
    
    mutate {
      add_field => { "event_type" => "dns_query" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "ai-firewall-%{+YYYY.MM.dd}"
  }
}
```

## 🛡️ Defense Network Deployment

### Security Requirements
- **Air-gapped Environment**: No internet connectivity
- **Hardened OS**: STIG compliance
- **Encrypted Storage**: FIPS 140-2 Level 3
- **Audit Logging**: Complete activity tracking
- **Physical Security**: Tamper-evident hardware

### Hardened Installation

#### OS Hardening
```bash
# Apply security benchmarks
sudo apt install -y aide lynis chkrootkit

# Configure mandatory access controls
sudo apt install apparmor-utils
sudo systemctl enable apparmor

# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable wifi
sudo systemctl disable cups
```

#### Firewall Configuration
```bash
# Configure iptables
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow SSH from management network only
sudo iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 22 -j ACCEPT

# Allow API access from authorized hosts
sudo iptables -A INPUT -s 10.0.2.0/24 -p tcp --dport 8000 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

#### Encryption Setup
```bash
# Full disk encryption (LUKS)
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb secure_data

# Create encrypted filesystem
sudo mkfs.ext4 /dev/mapper/secure_data
sudo mkdir /mnt/secure
sudo mount /dev/mapper/secure_data /mnt/secure
```

### Air-gapped Deployment

#### Offline Package Installation
```bash
# Download packages on connected system
apt-get download $(apt-cache depends --recurse --no-recommends \
  python3-pip postgresql-14 | grep "^\w" | sort -u)

# Transfer to air-gapped system via secure media
# Install packages offline
sudo dpkg -i *.deb
sudo apt-get install -f
```

#### Local Threat Intelligence
```bash
# Create local threat database
psql -d ai_firewall -c "CREATE TABLE local_threats (
  domain VARCHAR(255) PRIMARY KEY,
  threat_type VARCHAR(50),
  severity INTEGER,
  added_date TIMESTAMP DEFAULT NOW()
);"

# Import threat indicators
psql -d ai_firewall -c "COPY local_threats(domain, threat_type, severity) 
  FROM '/secure/threat_indicators.csv' DELIMITER ',' CSV HEADER;"
```

## 🔧 Configuration Management

### Environment Variables
```bash
# Production environment
export ENV=production
export SECRET_KEY=your_super_secret_production_key
export DATABASE_URL=postgresql://user:pass@localhost/ai_firewall
export REDIS_URL=redis://localhost:6379
export LOG_LEVEL=INFO

# Security settings
export JWT_ALGORITHM=HS256
export JWT_EXPIRE_MINUTES=30
export BCRYPT_ROUNDS=12

# AI model settings
export MODEL_PATH=/app/data/models
export FEATURE_CACHE_SIZE=10000
export THREAT_THRESHOLD=0.7
```

### Monitoring Configuration
```bash
# Prometheus metrics
pip install prometheus_client

# Health check endpoint
curl http://localhost:8000/health

# Metrics endpoint
curl http://localhost:8000/metrics
```

### Backup Strategy
```bash
# Database backup
pg_dump ai_firewall | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Model backup
tar -czf models_backup_$(date +%Y%m%d).tar.gz data/models/

# Configuration backup
tar -czf config_backup_$(date +%Y%m%d).tar.gz device/config.json backend/config/
```

## 📊 Performance Tuning

### Database Optimization
```sql
-- Optimize for time-series data
CREATE INDEX CONCURRENTLY idx_dns_queries_timestamp 
ON dns_queries(timestamp DESC);

-- Partition large tables
CREATE TABLE dns_queries_y2024m01 PARTITION OF dns_queries
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM dns_queries 
WHERE timestamp > NOW() - INTERVAL '1 hour';
```

### Application Tuning
```python
# FastAPI optimization
app = FastAPI(
    title="AI Privacy Firewall",
    docs_url=None,  # Disable in production
    redoc_url=None,
    debug=False
)

# Connection pooling
engine = create_async_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=0,
    pool_pre_ping=True
)
```

### System Optimization
```bash
# Network buffer tuning
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf

# CPU governor
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Apply changes
sudo sysctl -p
```

## 🔄 Maintenance

### Update Procedures
```bash
# Update application
git pull origin main
pip install -r requirements.txt --upgrade

# Database migrations
alembic upgrade head

# Restart services
sudo systemctl restart ai-privacy-firewall
```

### Log Rotation
```bash
# Configure logrotate
sudo nano /etc/logrotate.d/ai-firewall
```

```
/var/log/ai-firewall/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload ai-privacy-firewall
    endscript
}
```

### Health Monitoring
```bash
# System monitoring script
#!/bin/bash
# check_health.sh

# Check service status
if ! systemctl is-active --quiet ai-privacy-firewall; then
    echo "Service down, restarting..."
    sudo systemctl restart ai-privacy-firewall
fi

# Check disk space
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "Warning: Disk usage at ${DISK_USAGE}%"
fi

# Check memory usage
MEMORY_USAGE=$(free | awk '/Mem/ {printf "%.0f", $3/$2 * 100.0}')
if [ $MEMORY_USAGE -gt 85 ]; then
    echo "Warning: Memory usage at ${MEMORY_USAGE}%"
fi
```

This comprehensive deployment guide covers all major scenarios from home networks to high-security defense environments, with specific configurations for each use case.
