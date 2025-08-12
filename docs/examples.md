# 📝 Example Configurations

This document provides example configuration files and settings for different deployment scenarios of the AI Privacy Firewall.

## 🏠 Home Network Configuration

### Device Configuration (`device/config.json`)
```json
{
    "device_info": {
        "device_id": "home_firewall_001",
        "name": "Home Network Firewall",
        "location": "Living Room Router",
        "hardware_type": "raspberry_pi_4",
        "firmware_version": "1.0.0"
    },
    "network": {
        "monitor_interface": "eth0",
        "monitor_mode": "bridge",
        "ip_address": "192.168.1.10",
        "gateway": "192.168.1.1",
        "dns_servers": ["8.8.8.8", "8.8.4.4"],
        "capture_filter": "port 53 or (tcp and port 443)"
    },
    "api": {
        "base_url": "http://192.168.1.10:8000/api",
        "device_token": "your_device_authentication_token",
        "upload_interval": 30,
        "batch_size": 100,
        "timeout": 10
    },
    "detection": {
        "enable_local_analysis": true,
        "threat_threshold": 0.7,
        "anomaly_threshold": 0.8,
        "enable_real_time_blocking": true,
        "block_malware": true,
        "block_phishing": true,
        "block_dga": true,
        "whitelist_domains": [
            "*.google.com",
            "*.microsoft.com",
            "*.apple.com"
        ]
    },
    "privacy": {
        "log_queries": true,
        "log_responses": false,
        "anonymize_client_ips": false,
        "retention_days": 30,
        "share_threat_intelligence": true
    },
    "logging": {
        "level": "INFO",
        "file": "/var/log/ai-firewall/device.log",
        "max_size": "100MB",
        "backup_count": 5,
        "enable_syslog": false
    },
    "performance": {
        "packet_buffer_size": 1024,
        "worker_threads": 2,
        "memory_limit": "512MB",
        "cpu_limit": 80
    }
}
```

### Backend Environment (`.env`)
```bash
# Environment
ENV=production
DEBUG=false

# Security
SECRET_KEY=your_super_secret_key_here_minimum_32_characters
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
BCRYPT_ROUNDS=12

# Database
DATABASE_URL=postgresql://ai_firewall:secure_password@localhost:5432/ai_privacy_firewall
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=0

# Redis (for caching and sessions)
REDIS_URL=redis://localhost:6379/0
REDIS_MAX_CONNECTIONS=10

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
API_RELOAD=false

# AI Models
MODEL_PATH=/app/data/models
FEATURE_CACHE_SIZE=10000
THREAT_THRESHOLD=0.7
ANOMALY_THRESHOLD=0.8
MODEL_UPDATE_INTERVAL=3600

# External APIs (optional)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SAFEBROWSING_API_KEY=your_google_safebrowsing_key
ABUSE_CH_API_KEY=your_abuse_ch_api_key

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/ai-firewall/backend.log
LOG_MAX_SIZE=100MB
LOG_BACKUP_COUNT=10

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
HEALTH_CHECK_INTERVAL=30

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=1000
RATE_LIMIT_BURST=100
```

## 🏢 Business Network Configuration

### Enterprise Device Settings
```json
{
    "device_info": {
        "device_id": "corp_firewall_dc01",
        "name": "Data Center Firewall - Primary",
        "location": "DC1 Rack 15",
        "hardware_type": "intel_nuc",
        "organization_id": "acme_corp",
        "cluster_role": "primary"
    },
    "network": {
        "monitor_interface": "ens160",
        "monitor_mode": "span_port",
        "ip_address": "10.100.1.10",
        "gateway": "10.100.1.1",
        "dns_servers": ["10.100.1.2", "10.100.1.3"],
        "vlan_id": 100,
        "capture_filter": "port 53 or (tcp and (port 443 or port 80))",
        "high_availability": {
            "enable": true,
            "peer_ip": "10.100.1.11",
            "heartbeat_interval": 5,
            "failover_timeout": 30
        }
    },
    "api": {
        "base_url": "https://ai-firewall.corp.acme.com/api",
        "device_token": "enterprise_device_token_here",
        "upload_interval": 10,
        "batch_size": 500,
        "timeout": 30,
        "use_tls": true,
        "verify_certificate": true
    },
    "detection": {
        "enable_local_analysis": true,
        "threat_threshold": 0.6,
        "anomaly_threshold": 0.7,
        "enable_real_time_blocking": true,
        "detection_modes": ["malware", "phishing", "dga", "tunneling", "exfiltration"],
        "enterprise_rules": {
            "block_personal_email": true,
            "block_social_media": false,
            "block_file_sharing": true,
            "monitor_unusual_traffic": true
        },
        "compliance": {
            "log_all_queries": true,
            "data_loss_prevention": true,
            "insider_threat_detection": true
        }
    },
    "privacy": {
        "log_queries": true,
        "log_responses": true,
        "anonymize_client_ips": false,
        "retention_days": 365,
        "share_threat_intelligence": true,
        "comply_with_gdpr": true,
        "comply_with_hipaa": false
    },
    "siem_integration": {
        "enable": true,
        "siem_type": "splunk",
        "siem_endpoint": "https://splunk.corp.acme.com:8088/services/collector",
        "siem_token": "splunk_hec_token_here",
        "event_format": "cef",
        "send_all_events": false,
        "send_threats_only": true
    },
    "performance": {
        "packet_buffer_size": 4096,
        "worker_threads": 8,
        "memory_limit": "4GB",
        "cpu_limit": 90,
        "enable_gpu_acceleration": false
    }
}
```

### Docker Compose for Enterprise
```yaml
version: '3.8'

services:
  ai-firewall-api:
    image: ai-firewall:latest
    ports:
      - "8000:8000"
    environment:
      - ENV=production
      - DATABASE_URL=postgresql://ai_firewall:${DB_PASSWORD}@db:5432/ai_firewall
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - ai_models:/app/data/models
      - ai_logs:/var/log/ai-firewall
    depends_on:
      - db
      - redis
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        max_attempts: 3
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G

  db:
    image: postgres:14
    environment:
      POSTGRES_DB: ai_firewall
      POSTGRES_USER: ai_firewall
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql
    deploy:
      restart_policy:
        condition: on-failure
      resources:
        limits:
          memory: 8G
        reservations:
          memory: 4G

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    deploy:
      restart_policy:
        condition: on-failure

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
      - ai_logs:/var/log/ai-firewall
    depends_on:
      - ai-firewall-api
    deploy:
      restart_policy:
        condition: on-failure

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources

volumes:
  postgres_data:
  redis_data:
  ai_models:
  ai_logs:
  prometheus_data:
  grafana_data:

networks:
  default:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## 🛡️ Defense Network Configuration

### High-Security Deployment
```json
{
    "device_info": {
        "device_id": "defense_firewall_classified",
        "name": "Classified Network Firewall",
        "location": "Secure Facility - Room 401",
        "hardware_type": "hardened_appliance",
        "security_level": "top_secret",
        "compliance": ["fisma", "nist_800_53", "dod_8500"]
    },
    "network": {
        "monitor_interface": "ens192",
        "monitor_mode": "tap",
        "ip_address": "192.168.100.10",
        "gateway": "192.168.100.1",
        "dns_servers": ["192.168.100.2", "192.168.100.3"],
        "air_gapped": true,
        "encryption": {
            "enable_wire_encryption": true,
            "cipher_suite": "AES-256-GCM",
            "key_rotation_hours": 24
        }
    },
    "api": {
        "base_url": "https://192.168.100.10:8443/api",
        "device_token": "classified_token_with_tpm_binding",
        "upload_interval": 5,
        "batch_size": 1000,
        "timeout": 60,
        "mutual_tls": true,
        "certificate_path": "/secure/certs/device.crt",
        "private_key_path": "/secure/certs/device.key"
    },
    "detection": {
        "enable_local_analysis": true,
        "threat_threshold": 0.3,
        "anomaly_threshold": 0.4,
        "enable_real_time_blocking": true,
        "advanced_detection": {
            "insider_threat": true,
            "advanced_persistent_threat": true,
            "zero_day_detection": true,
            "behavioral_analysis": true,
            "machine_learning_ensemble": true
        },
        "defense_specific": {
            "classify_traffic": true,
            "detect_covert_channels": true,
            "monitor_data_exfiltration": true,
            "detect_nation_state_indicators": true
        }
    },
    "privacy": {
        "log_queries": true,
        "log_responses": true,
        "anonymize_client_ips": false,
        "retention_days": 2555,  # 7 years for defense requirements
        "share_threat_intelligence": false,
        "local_processing_only": true,
        "encryption_at_rest": "fips_140_2_level_3"
    },
    "security": {
        "enable_tamper_detection": true,
        "secure_boot": true,
        "tpm_binding": true,
        "hardware_security_module": true,
        "audit_all_access": true,
        "require_two_person_integrity": true,
        "self_destruct_on_tamper": false
    },
    "compliance": {
        "fisma_controls": true,
        "nist_800_53_controls": true,
        "dod_8500_compliance": true,
        "continuous_monitoring": true,
        "automated_reporting": true
    },
    "performance": {
        "packet_buffer_size": 8192,
        "worker_threads": 16,
        "memory_limit": "16GB",
        "cpu_limit": 95,
        "real_time_priority": true,
        "numa_optimization": true
    }
}
```

### Air-gapped Threat Intelligence
```json
{
    "local_threat_intelligence": {
        "enable": true,
        "database_path": "/secure/threat_intel/local.db",
        "update_mechanism": "manual_import",
        "sources": [
            {
                "name": "government_feed",
                "type": "csv",
                "path": "/secure/feeds/gov_threats.csv",
                "format": "domain,threat_type,severity,classification"
            },
            {
                "name": "internal_analysis",
                "type": "json",
                "path": "/secure/feeds/internal_threats.json",
                "auto_update": false
            }
        ],
        "custom_rules": [
            {
                "name": "suspicious_tld",
                "pattern": "\\.(tk|ml|ga|cf)$",
                "action": "flag_high_risk",
                "classification": "medium"
            },
            {
                "name": "dga_pattern",
                "pattern": "^[a-z]{8,20}\\.(com|net|org)$",
                "action": "analyze_further",
                "classification": "low"
            }
        ]
    }
}
```

## 📊 Monitoring and Alerting

### Prometheus Configuration (`monitoring/prometheus.yml`)
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'ai-firewall-api'
    static_configs:
      - targets: ['ai-firewall-api:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'ai-firewall-device'
    static_configs:
      - targets: ['device:9091']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Alert Rules (`monitoring/alert_rules.yml`)
```yaml
groups:
  - name: ai_firewall_alerts
    rules:
      - alert: HighThreatDetectionRate
        expr: rate(threats_detected_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High threat detection rate"
          description: "Threat detection rate is {{ $value }} threats/sec"

      - alert: DeviceOffline
        expr: up{job="ai-firewall-device"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "AI Firewall device is offline"
          description: "Device {{ $labels.instance }} has been offline for more than 1 minute"

      - alert: DatabaseConnectionFailure
        expr: postgresql_up == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "Database connection failure"
          description: "PostgreSQL database is not responding"

      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is above 90%"

      - alert: ModelAccuracyDrop
        expr: model_accuracy < 0.85
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "ML model accuracy dropped"
          description: "Model accuracy is {{ $value }}, below 85% threshold"
```

### Grafana Dashboard Configuration
```json
{
  "dashboard": {
    "title": "AI Privacy Firewall Overview",
    "panels": [
      {
        "title": "DNS Queries per Second",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(dns_queries_total[1m])",
            "legendFormat": "{{instance}}"
          }
        ]
      },
      {
        "title": "Threat Detection Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(threats_detected_total[1m])",
            "legendFormat": "Threats/sec"
          }
        ]
      },
      {
        "title": "Model Performance",
        "type": "stat",
        "targets": [
          {
            "expr": "model_accuracy",
            "legendFormat": "Accuracy"
          },
          {
            "expr": "avg(model_inference_duration_seconds)",
            "legendFormat": "Avg Inference Time"
          }
        ]
      },
      {
        "title": "System Resources",
        "type": "graph",
        "targets": [
          {
            "expr": "100 - (avg(rate(node_cpu_seconds_total{mode=\"idle\"}[1m])) * 100)",
            "legendFormat": "CPU Usage %"
          },
          {
            "expr": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100",
            "legendFormat": "Memory Usage %"
          }
        ]
      }
    ]
  }
}
```

These example configurations provide comprehensive starting points for deploying the AI Privacy Firewall in various environments, from simple home networks to complex enterprise and defense scenarios.
