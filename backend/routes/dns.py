"""
DNS monitoring and threat detection API routes.
Handles device management, DNS query logging, and threat analysis.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func, and_
from typing import List, Optional
from datetime import datetime, timedelta

from backend.database import get_db
from backend.config.settings import DEVICE_INGEST_TOKEN
from backend.dependencies import get_current_user, require_role
from backend.models.users import Users
from backend.models.dns_models import Device, DNSQuery, ThreatDetection, DomainReputation, NetworkSettings, Collector, Endpoint, DNSQueryStatus
from backend.services.auth import decode_access_token
import hmac, hashlib
from backend.services.scoring import compute_threat_score
from backend.services.stream import stream_manager
from prometheus_client import Counter

ingest_batches_total = Counter('dns_ingest_batches_total', 'Total DNS ingestion batches processed')
ingest_queries_total = Counter('dns_ingest_queries_total', 'Total DNS queries ingested (raw)')
ingest_queries_blocked_total = Counter('dns_ingest_queries_blocked_total', 'Total DNS queries blocked by heuristic scoring')
from backend.schemas.dns_schemas import (
    DeviceCreate, DeviceResponse, DeviceUpdate,
    DeviceEnrollmentRequest, DeviceEnrollmentCode, DeviceEnrollComplete, DeviceCredentialResponse,
    CollectorEnrollmentRequest, CollectorResponse,
    EndpointResponse, EndpointLabelUpdate,
    DNSQueryCreate, DNSQueryResponse, DNSQueryAnalysis,
    ThreatDetectionCreate, ThreatDetectionResponse, ThreatSummary,
    DomainReputationResponse, DomainAnalysisRequest,
    NetworkSettingsUpdate, NetworkSettingsResponse,
    DeviceStats, NetworkAnalytics, AlertResponse
)
from backend.utils.crypto import random_secret, random_code
import hashlib, time

# Initialize FASTAPI router for the /api/dns endpoint
router = APIRouter()

# --- Helper: endpoint identity resolution (MAC > hostname > IP) ---
def get_or_create_endpoint(db: Session, user_id: int, mac: str | None = None, hostname: str | None = None, ip: str | None = None) -> Endpoint:
    """Fetch or create endpoint using identity hierarchy.
    We always store something in mac_address (fallback pseudo key) because model requires non-null.
    """
    pseudo_mac = None
    key_mac = mac
    if not key_mac:
        # build deterministic fallback
        base = hostname or ip or "unknown"
        pseudo_mac = f"pseudo-{base}".replace(':','-')
        key_mac = pseudo_mac
    ep = db.query(Endpoint).filter(Endpoint.user_id == user_id, Endpoint.mac_address == key_mac).first()
    created = False
    if not ep:
        ep = Endpoint(
            user_id=user_id,
            mac_address=key_mac,
            ip_address=ip,
            hostname=hostname,
            status='observed'
        )
        db.add(ep)
        created = True
    # update mutable fields
    from datetime import datetime as _dt
    ep.last_seen = _dt.utcnow()
    if ip and ep.ip_address != ip:
        ep.ip_address = ip
    if hostname and ep.hostname != hostname:
        ep.hostname = hostname
    if created:
        db.flush()  # assign id without full commit yet
    return ep

# Device Management Endpoints...
@router.post("/devices", response_model=DeviceResponse)
def register_device(
    device: DeviceCreate,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Register a new firewall device for the current user"""
    
    # Check if device already exists
    existing_device = db.query(Device).filter(
        Device.device_id == device.device_id
    ).first()
    
    if existing_device:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device already registered"
        )
    
    # Create new device
    new_device = Device(
        device_id=device.device_id,
        name=device.name,
        ip_address=device.ip_address,
        mac_address=device.mac_address,
        location=device.location,
        user_id=current_user.id
    )
    
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    
    # Create default network settings
    default_settings = NetworkSettings(
        device_id=new_device.id,
        enable_malware_blocking=True,
        enable_phishing_blocking=True,
        ai_threat_threshold=0.7
    )
    
    db.add(default_settings)
    db.commit()
    
    return new_device

@router.get("/devices", response_model=List[DeviceResponse])
def get_user_devices(
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all devices for the current user"""
    devices = db.query(Device).filter(Device.user_id == current_user.id).all()
    return devices

@router.get("/devices/{device_id}", response_model=DeviceResponse)
def get_device(
    device_id: int,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific device details"""
    device = db.query(Device).filter(
        and_(Device.id == device_id, Device.user_id == current_user.id)
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    return device

# --- Enrollment Flow ---
@router.post("/devices/request-enrollment", response_model=DeviceEnrollmentCode)
def request_device_enrollment(
    req: DeviceEnrollmentRequest,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a placeholder device with an enrollment code the user can type on the Pi."""
    code = random_code()
    expires = datetime.utcnow() + timedelta(minutes=15)
    device = Device(
        device_id=f"pending-{random_code(6)}",
        name=req.name,
        ip_address="0.0.0.0",
        mac_address=f"pending-{random_code(6)}",
        location=req.location or "unknown",
        user_id=current_user.id,
        status="pending",
        enrollment_code=hashlib.sha256(code.encode()).hexdigest(),
        enrollment_expires_at=expires
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return DeviceEnrollmentCode(device_id=device.id, enrollment_code=code, expires_at=expires)

@router.post("/devices/complete-enrollment", response_model=DeviceCredentialResponse)
def complete_device_enrollment(
    comp: DeviceEnrollComplete,
    db: Session = Depends(get_db)
):
    """Finalize enrollment from Pi: exchange code + mac for device secret."""
    hashed = hashlib.sha256(comp.enrollment_code.encode()).hexdigest()
    device = db.query(Device).filter(
        and_(Device.enrollment_code == hashed, Device.status == "pending")
    ).first()
    if not device:
        raise HTTPException(status_code=400, detail="Invalid or already used enrollment code")
    if device.enrollment_expires_at and device.enrollment_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Enrollment code expired")
    # Set real identifiers
    device.device_id = comp.mac_address.lower()
    device.mac_address = comp.mac_address.lower()
    if comp.hostname:
        device.name = comp.hostname
    device.device_secret = random_secret(32)
    device.status = "active"
    device.enrollment_code = None
    device.enrollment_expires_at = None
    db.commit()
    db.refresh(device)
    return DeviceCredentialResponse(
        device_id=device.id,
        device_uuid=device.device_id,
        device_secret=device.device_secret,
        issued_at=datetime.utcnow()
    )

# --- Collector & Endpoint (new) ---
@router.get("/collectors", response_model=List[CollectorResponse])
def list_collectors(current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Collector).filter(Collector.user_id == current_user.id).all()
    return rows

@router.post("/collectors/enroll", response_model=CollectorResponse)
def enroll_collector(req: CollectorEnrollmentRequest, current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    # Simple creation (parallel to device enrollment, could merge later)
    col = Collector(
        user_id=current_user.id,
        name=req.name,
        uuid=f"col-{random_code(10).lower()}",
        secret=random_secret(32),
        status="active"
    )
    db.add(col)
    db.commit()
    db.refresh(col)
    return col

@router.get("/endpoints", response_model=List[EndpointResponse])
def list_endpoints(current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    eps = db.query(Endpoint).filter(Endpoint.user_id == current_user.id).all()
    return eps

@router.put("/endpoints/{endpoint_id}", response_model=EndpointResponse)
def label_endpoint(endpoint_id: int, upd: EndpointLabelUpdate, current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id, Endpoint.user_id == current_user.id).first()
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    if upd.friendly_name is not None:
        ep.friendly_name = upd.friendly_name
    if upd.status is not None:
        ep.status = upd.status
    db.commit()
    db.refresh(ep)
    return ep

@router.put("/devices/{device_id}", response_model=DeviceResponse)
def update_device(
    device_id: int,
    device_update: DeviceUpdate,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update device information"""
    device = db.query(Device).filter(
        and_(Device.id == device_id, Device.user_id == current_user.id)
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    # Update fields
    for field, value in device_update.dict(exclude_unset=True).items():
        setattr(device, field, value)
    
    db.commit()
    db.refresh(device)
    
    return device

# DNS Query Endpoints
@router.post("/dns-queries", response_model=DNSQueryResponse)
def log_dns_query(
    query: DNSQueryCreate,
    db: Session = Depends(get_db)
):
    """Log a DNS query from a device (called by the device itself)"""
    
    # Verify device exists
    device = db.query(Device).filter(Device.id == query.device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    # Create DNS query record
    dns_query = DNSQuery(
        device_id=query.device_id,
        query_name=query.query_name,
        query_type=query.query_type,
        client_ip=query.client_ip,
        response_code=query.response_code,
        response_ip=query.response_ip
    )
    
    db.add(dns_query)
    db.commit()
    db.refresh(dns_query)
    
    # Update device last_seen
    device.last_seen = datetime.utcnow()
    db.commit()
    
    return dns_query

@router.post("/dns-queries/batch")
def log_dns_queries_batch(
    queries: List[dict],
    request: Request,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(default=None, alias="X-Device-Token"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    h_device_id: str | None = Header(default=None, alias="X-Device-Id"),
    h_timestamp: str | None = Header(default=None, alias="X-Timestamp"),
    h_signature: str | None = Header(default=None, alias="X-Signature"),
):
    """
    Batch endpoint for high-performance DNS query logging from C++ monitor.
    Accepts raw JSON array of DNS queries for efficient bulk insertion.
    """
    try:
        MAX_BATCH = 2000
        if len(queries) > MAX_BATCH:
            raise HTTPException(status_code=413, detail=f"Batch too large (>{MAX_BATCH} queries)")
        processed_queries = []
        device_cache = {}
        owner_user_id = 1

        # HMAC path
        hmac_device = None
        if h_device_id and h_timestamp and h_signature:
            # Validate timestamp freshness (5 min window)
            try:
                ts_int = int(h_timestamp)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid timestamp")
            if abs(int(datetime.utcnow().timestamp()) - ts_int) > 300:
                raise HTTPException(status_code=401, detail="Stale timestamp")
            # Lookup device
            hmac_device = db.query(Device).filter(Device.device_id == h_device_id.lower()).first()
            if not hmac_device or not hmac_device.device_secret or hmac_device.status != "active":
                raise HTTPException(status_code=401, detail="Unknown or inactive device")
            # Reconstruct body for signature
            import json as _json
            body_bytes = _json.dumps(queries, separators=(",", ":")).encode()
            mac = hmac.new(hmac_device.device_secret.encode(), body_bytes + b"." + h_timestamp.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, h_signature.lower()):
                raise HTTPException(status_code=401, detail="Invalid signature")
            owner_user_id = hmac_device.user_id
        else:
            # Legacy dev token + Authorization fallback
            if DEVICE_INGEST_TOKEN and x_device_token != DEVICE_INGEST_TOKEN:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device token")
            try:
                if authorization and authorization.lower().startswith("bearer "):
                    token = authorization.split(" ", 1)[1].strip()
                    payload = decode_access_token(token)
                    if payload and payload.get("sub"):
                        user = db.query(Users).filter(Users.email == payload["sub"]).first()
                        if user:
                            owner_user_id = user.id
            except Exception:
                pass
        
        blocked_count = 0
        for query_data in queries:
            # Basic validation
            if not isinstance(query_data, dict):
                continue
            if not query_data.get("query_name"):
                continue
            device_string_id = query_data.get("device_id")  # collector or legacy device id
            mac_addr = (query_data.get("mac") or query_data.get("mac_address") or "").lower()
            ip_addr = query_data.get("client_ip")
            
            # Use cached device or lookup/create
            if device_string_id not in device_cache:
                device = db.query(Device).filter(Device.device_id == device_string_id.lower()).first()
                if not device:
                    if hmac_device:
                        raise HTTPException(status_code=404, detail=f"Unknown device {device_string_id}; enroll first")
                    device = Device(
                        device_id=device_string_id.lower(),
                        name=f"Auto-registered {device_string_id}",
                        ip_address=query_data.get("client_ip", "unknown"),
                        mac_address=device_string_id.lower(),
                        location="auto-detected",
                        user_id=owner_user_id,
                        status="active"
                    )
                    db.add(device)
                    db.flush()
                else:
                    # If the device exists but belongs to a different user and we have an owner, reassign for demo
                    if owner_user_id and getattr(device, "user_id", None) != owner_user_id:
                        device.user_id = owner_user_id
                
                device_cache[device_string_id] = device
            else:
                device = device_cache[device_string_id]
            
            # Endpoint identity hierarchy (MAC > hostname > IP)
            endpoint_id = None
            hostname = query_data.get("hostname")
            if mac_addr or hostname or ip_addr:
                ep = get_or_create_endpoint(
                    db,
                    owner_user_id,
                    mac=mac_addr or None,
                    hostname=hostname,
                    ip=ip_addr
                )
                endpoint_id = ep.id

            # Create DNS query record
            dns_query = DNSQuery(
                device_id=device.id,
                endpoint_id=endpoint_id,
                query_name=query_data.get("query_name"),
                query_type=query_data.get("query_type"),
                client_ip=ip_addr,
                response_code=query_data.get("response_code"),
                response_ip=query_data.get("response_ip"),
                timestamp=datetime.fromtimestamp(query_data.get("timestamp", 0)) if query_data.get("timestamp") else datetime.utcnow()
            )
            
            db.add(dns_query)
            processed_queries.append(dns_query)
            
            # Update device last_seen (batch update at end)
            device.last_seen = datetime.utcnow()
        
    # Commit initial inserts
        db.commit()

        # Heuristic scoring and threat detection (simple and fast)
        for dq in processed_queries:
            score, status = compute_threat_score(dq.query_name)
            dq.threat_score = score
            if score >= 0.7:
                dq.status = DNSQueryStatus.BLOCKED if status == 'blocked' else DNSQueryStatus.ALLOWED
                blocked_count += 1
                td = ThreatDetection(
                    device_id=dq.device_id,
                    dns_query_id=dq.id,
                    threat_type="heuristic",
                    threat_level="high",
                    confidence_score=float(score),
                    detected_by="heuristic",
                    description=f"Auto-scored domain {dq.query_name}",
                )
                db.add(td)
            else:
                dq.status = DNSQueryStatus.ALLOWED
            # Broadcast lightweight event
            try:
                import asyncio
                friendly_name = None
                if dq.endpoint_id:
                    ep = db.query(Endpoint).filter(Endpoint.id == dq.endpoint_id).first()
                    if ep and ep.friendly_name:
                        friendly_name = ep.friendly_name
                asyncio.create_task(stream_manager.broadcast({
                    "type": "dns", "id": dq.id, "domain": dq.query_name,
                    "status": dq.status.value if hasattr(dq.status, 'value') else dq.status,
                    "score": score, "device_id": dq.device_id,
                    "endpoint_id": dq.endpoint_id, "endpoint_name": friendly_name,
                    "timestamp": dq.timestamp.isoformat() + 'Z'
                }))
            except Exception:
                pass

        db.commit()
        ingest_batches_total.inc()
        ingest_queries_total.inc(len(processed_queries))
        if blocked_count:
            ingest_queries_blocked_total.inc(blocked_count)
        
        # Broadcast analytics delta (24h counters + active endpoints last hour)
        try:
            import anyio
            day_ago = datetime.utcnow() - timedelta(hours=24)
            total_q = db.query(DNSQuery).join(Device).filter(
                and_(Device.user_id == owner_user_id, DNSQuery.timestamp >= day_ago)
            ).count()
            blocked_q = db.query(DNSQuery).join(Device).filter(
                and_(Device.user_id == owner_user_id, DNSQuery.timestamp >= day_ago, DNSQuery.status == DNSQueryStatus.BLOCKED)
            ).count()
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            active_eps = db.query(Endpoint).filter(
                and_(Endpoint.user_id == owner_user_id, Endpoint.last_seen >= hour_ago)
            ).count()
            anyio.from_thread.run(stream_manager.broadcast, {
                "type": "analytics_delta",
                "total_queries_24h": total_q,
                "blocked_queries_24h": blocked_q,
                "active_devices": active_eps
            })
        except Exception:
            pass

        return {
            "status": "success",
            "processed": len(processed_queries),
            "blocked": blocked_count,
            "message": f"Successfully processed {len(processed_queries)} DNS queries (blocked {blocked_count})"
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process batch DNS queries: {str(e)}"
        )

@router.get("/dns-queries", response_model=List[DNSQueryResponse])
def get_dns_queries(
    device_id: Optional[int] = None,
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get DNS queries for user's devices"""
    
    # Base query - only user's devices
    query = db.query(DNSQuery).join(Device).filter(Device.user_id == current_user.id)
    
    # Apply filters
    if device_id:
        query = query.filter(DNSQuery.device_id == device_id)
    
    if start_time:
        query = query.filter(DNSQuery.timestamp >= start_time)
    
    if end_time:
        query = query.filter(DNSQuery.timestamp <= end_time)
    
    # Order by timestamp descending and apply pagination
    queries = query.order_by(desc(DNSQuery.timestamp)).offset(offset).limit(limit).all()
    
    return queries

# Threat Detection Endpoints
@router.post("/threats", response_model=ThreatDetectionResponse)
def create_threat_detection(
    threat: ThreatDetectionCreate,
    db: Session = Depends(get_db)
):
    """Create a new threat detection (called by AI analysis service)"""
    
    # Verify device exists
    device = db.query(Device).filter(Device.id == threat.device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    # Create threat detection
    threat_detection = ThreatDetection(
        device_id=threat.device_id,
        dns_query_id=threat.dns_query_id,
        threat_type=threat.threat_type,
        threat_level=threat.threat_level,
        confidence_score=threat.confidence_score,
        detected_by=threat.detected_by,
        model_version=threat.model_version,
        description=threat.description,
        indicators=str(threat.indicators) if threat.indicators else None
    )
    
    db.add(threat_detection)
    db.commit()
    db.refresh(threat_detection)
    
    return threat_detection

@router.get("/threats", response_model=List[ThreatDetectionResponse])
def get_threats(
    device_id: Optional[int] = None,
    threat_level: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get threat detections for user's devices"""
    
    # Base query - only user's devices
    query = db.query(ThreatDetection).join(Device).filter(Device.user_id == current_user.id)
    
    # Apply filters
    if device_id:
        query = query.filter(ThreatDetection.device_id == device_id)
    
    if threat_level:
        query = query.filter(ThreatDetection.threat_level == threat_level)
    
    # Order by timestamp descending
    threats = query.order_by(desc(ThreatDetection.timestamp)).offset(offset).limit(limit).all()
    
    return threats

@router.get("/threats/summary", response_model=ThreatSummary)
def get_threat_summary(
    device_id: Optional[int] = None,
    hours: int = Query(24, ge=1, le=168),  # Last 1-168 hours
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get threat summary for the last N hours"""
    
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Base query
    base_query = db.query(ThreatDetection).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            ThreatDetection.timestamp >= since
        )
    )
    
    if device_id:
        base_query = base_query.filter(ThreatDetection.device_id == device_id)
    
    # Count threats by level
    total_threats = base_query.count()
    critical_threats = base_query.filter(ThreatDetection.threat_level == "critical").count()
    high_threats = base_query.filter(ThreatDetection.threat_level == "high").count()
    medium_threats = base_query.filter(ThreatDetection.threat_level == "medium").count()
    low_threats = base_query.filter(ThreatDetection.threat_level == "low").count()
    
    # Count blocked queries
    from backend.models.dns_models import DNSQueryStatus as ModelDNSStatus
    blocked_queries = db.query(DNSQuery).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            DNSQuery.timestamp >= since,
            DNSQuery.status == ModelDNSStatus.BLOCKED
        )
    ).count()
    
    # Top threat types
    threat_types = db.query(
        ThreatDetection.threat_type,
        func.count(ThreatDetection.id).label("count")
    ).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            ThreatDetection.timestamp >= since
        )
    ).group_by(ThreatDetection.threat_type).all()
    
    top_threat_types = [{"type": t[0], "count": t[1]} for t in threat_types]
    
    return ThreatSummary(
        total_threats=total_threats,
        critical_threats=critical_threats,
        high_threats=high_threats,
        medium_threats=medium_threats,
        low_threats=low_threats,
        blocked_queries=blocked_queries,
        top_threat_types=top_threat_types
    )

# Domain Reputation Endpoints
@router.get("/domains/{domain}/reputation", response_model=DomainReputationResponse)
def get_domain_reputation(
    domain: str,
    db: Session = Depends(get_db)
):
    """Get domain reputation information"""
    
    reputation = db.query(DomainReputation).filter(
        DomainReputation.domain == domain
    ).first()
    
    if not reputation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain reputation not found"
        )
    
    return reputation

# Network Settings Endpoints
@router.get("/devices/{device_id}/settings", response_model=NetworkSettingsResponse)
def get_network_settings(
    device_id: int,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get network settings for a device"""
    
    # Verify device ownership
    device = db.query(Device).filter(
        and_(Device.id == device_id, Device.user_id == current_user.id)
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    settings = db.query(NetworkSettings).filter(
        NetworkSettings.device_id == device_id
    ).first()
    
    if not settings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Network settings not found"
        )
    
    return settings

@router.put("/devices/{device_id}/settings", response_model=NetworkSettingsResponse)
def update_network_settings(
    device_id: int,
    settings_update: NetworkSettingsUpdate,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update network settings for a device"""
    
    # Verify device ownership
    device = db.query(Device).filter(
        and_(Device.id == device_id, Device.user_id == current_user.id)
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    settings = db.query(NetworkSettings).filter(
        NetworkSettings.device_id == device_id
    ).first()
    
    if not settings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Network settings not found"
        )
    
    # Update settings
    for field, value in settings_update.dict(exclude_unset=True).items():
        setattr(settings, field, value)
    
    db.commit()
    db.refresh(settings)
    
    return settings

# Analytics Endpoints
@router.get("/analytics/network", response_model=NetworkAnalytics)
def get_network_analytics(
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get network analytics overview"""
    
    # Total logical devices (collectors) for reference
    total_devices = db.query(Device).filter(Device.user_id == current_user.id).count()

    # Active endpoints (identity hierarchy) in last hour
    hour_ago = datetime.utcnow() - timedelta(hours=1)
    active_devices = db.query(Endpoint).filter(
        and_(
            Endpoint.user_id == current_user.id,
            Endpoint.last_seen >= hour_ago
        )
    ).count()

    # 24h window
    day_ago = datetime.utcnow() - timedelta(hours=24)

    total_queries_24h = db.query(DNSQuery).join(Device).filter(
        and_(Device.user_id == current_user.id, DNSQuery.timestamp >= day_ago)
    ).count()

    blocked_queries_24h = db.query(DNSQuery).join(Device).filter(
        and_(Device.user_id == current_user.id, DNSQuery.timestamp >= day_ago, DNSQuery.status == DNSQueryStatus.BLOCKED)
    ).count()

    threats_detected_24h = db.query(ThreatDetection).join(Device).filter(
        and_(Device.user_id == current_user.id, ThreatDetection.timestamp >= day_ago)
    ).count()

    # Top blocked domains (only BLOCKED) with counts
    top_blocked_rows = db.query(
        DNSQuery.query_name, func.count(DNSQuery.id).label('c')
    ).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            DNSQuery.timestamp >= day_ago,
            DNSQuery.status == DNSQueryStatus.BLOCKED
        )
    ).group_by(DNSQuery.query_name).order_by(desc('c')).limit(5).all()
    top_blocked_domains = [
        {"domain": r[0], "count": r[1]} for r in top_blocked_rows
    ]

    # Threat timeline: per-hour counts (last 12h)
    hours = 12
    timeline = []
    now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    for i in range(hours - 1, -1, -1):
        start = now - timedelta(hours=i)
        end = start + timedelta(hours=1)
        cnt = db.query(ThreatDetection).join(Device).filter(
            and_(
                Device.user_id == current_user.id,
                ThreatDetection.timestamp >= start,
                ThreatDetection.timestamp < end
            )
        ).count()
        timeline.append({
            "time": start.isoformat() + 'Z',
            "threats": cnt
        })

    return NetworkAnalytics(
        total_devices=total_devices,
        active_devices=active_devices,
        total_queries_24h=total_queries_24h,
        blocked_queries_24h=blocked_queries_24h,
        threats_detected_24h=threats_detected_24h,
        top_blocked_domains=top_blocked_domains,
        threat_timeline=timeline
    )



######################################################################
# Test endpoint for quickly generating DNS data
# For testing purposes only ...
@router.get("/test-ingest")
def test_ingest(
    count: int = Query(10, ge=1, le=50),
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate test DNS data with the specified number of queries (some malicious)."""
    # Sample domains with varied risk levels 
    sample_domains = [
        "google.com", "microsoft.com", "amazon.com", "facebook.com", "twitter.com",
        "malware.example.test", "phishing-site.tk", "ransomware.example.com",
        "scam.test.cf", "malicious.malware.ml", "legitsite.com", "news.yahoo.com"
    ]
    # Generate random data
    import random
    from datetime import datetime
    
    # Create a test device if none exists
    device = db.query(Device).filter(Device.user_id == current_user.id).first()
    if not device:
        device = Device(
            device_id="test_device",
            name="Test Device",
            ip_address="192.168.1.100",
            mac_address="00:11:22:33:44:55",
            location="Test Location",
            user_id=current_user.id,
            status="active"
        )
        db.add(device)
        db.commit()
        db.refresh(device)
    
    # Create DNS queries
    blocked = 0
    queries = []
    for i in range(count):
        domain = random.choice(sample_domains)
        query = DNSQuery(
            device_id=device.id,
            query_name=domain,
            query_type="A",
            client_ip="192.168.1.100",
            response_code="NOERROR",
            response_ip="1.2.3.4",
            timestamp=datetime.utcnow()
        )
        db.add(query)
        queries.append(query)
    
    db.commit()
    
    # Score and process
    # Process + broadcast (thread-safe async invocation)
    # Simulate multiple client endpoints (simulate MAC + IP diversity)
    simulated_endpoints = [
        {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.101", "host": "laptop"},
        {"mac": "AA:BB:CC:DD:EE:02", "ip": "192.168.1.102", "host": "phone"},
        {"mac": "AA:BB:CC:DD:EE:03", "ip": "192.168.1.103", "host": "tv"},
    ]
    import random as _rand

    for dq in queries:
        score, computed_status = compute_threat_score(dq.query_name)
        dq.threat_score = score
        if score >= 0.7:
            dq.status = DNSQueryStatus.BLOCKED if computed_status == "blocked" else DNSQueryStatus.ALLOWED
            blocked += 1
            td = ThreatDetection(
                device_id=dq.device_id,
                dns_query_id=dq.id,
                threat_type="heuristic",
                threat_level="high",
                confidence_score=float(score),
                detected_by="heuristic",
                description=f"Auto-scored domain {dq.query_name}",
            )
            db.add(td)
        else:
            dq.status = DNSQueryStatus.ALLOWED

        # Assign an endpoint (simulate which client generated query)
        ep_meta = _rand.choice(simulated_endpoints)
        ep = get_or_create_endpoint(db, current_user.id, mac=ep_meta["mac"], hostname=ep_meta["host"], ip=ep_meta["ip"])
        dq.endpoint_id = ep.id

        # Safe broadcast from threadpool using anyio
        try:
            import anyio
            anyio.from_thread.run(stream_manager.broadcast, {
                "type": "dns",
                "id": dq.id,
                "domain": dq.query_name,
                "status": dq.status.value,
                "score": score,
                "device_id": dq.device_id,
                "timestamp": dq.timestamp.isoformat() + 'Z'
            })
        except Exception:
            pass
    
    db.commit()
    ingest_batches_total.inc()
    ingest_queries_total.inc(len(queries))
    if blocked:
        ingest_queries_blocked_total.inc(blocked)
    # Prepare quick aggregate for immediate dashboard update
    try:
        import anyio
        day_ago = datetime.utcnow() - timedelta(hours=24)
        total_q = db.query(DNSQuery).join(Device).filter(
            and_(Device.user_id == current_user.id, DNSQuery.timestamp >= day_ago)
        ).count()
        blocked_q = db.query(DNSQuery).join(Device).filter(
            and_(Device.user_id == current_user.id, DNSQuery.timestamp >= day_ago, DNSQuery.status == DNSQueryStatus.BLOCKED)
        ).count()
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        active_eps = db.query(Endpoint).filter(
            and_(Endpoint.user_id == current_user.id, Endpoint.last_seen >= hour_ago)
        ).count()
        anyio.from_thread.run(stream_manager.broadcast, {
            "type": "analytics_delta",
            "total_queries_24h": total_q,
            "blocked_queries_24h": blocked_q,
            "active_devices": active_eps
        })
    except Exception:
        pass

    return {
        "message": f"Generated {count} test queries, {blocked} blocked",
        "blocked": blocked,
        "processed": count,
        "blocked_domains": [q.query_name for q in queries if getattr(q, 'status', None) == DNSQueryStatus.BLOCKED]
    }
    
    # 24h statistics
    day_ago = datetime.utcnow() - timedelta(hours=24)
    
    total_queries_24h = db.query(DNSQuery).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            DNSQuery.timestamp >= day_ago
        )
    ).count()
    
    blocked_queries_24h = db.query(DNSQuery).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            DNSQuery.timestamp >= day_ago,
            DNSQuery.status == "blocked"
        )
    ).count()
    
    threats_detected_24h = db.query(ThreatDetection).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            ThreatDetection.timestamp >= day_ago
        )
    ).count()
    
    # Top blocked domains
    top_blocked = db.query(
        DNSQuery.query_name,
        func.count(DNSQuery.id).label("count")
    ).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            DNSQuery.timestamp >= day_ago,
            DNSQuery.status == "blocked"
        )
    ).group_by(DNSQuery.query_name).order_by(desc("count")).limit(10).all()
    
    top_blocked_domains = [{"domain": d[0], "count": d[1]} for d in top_blocked]
    
    # Build hourly timeline for last 24h (DB-agnostic, in-Python aggregation)
    # Fetch relevant events once
    queries_24h = db.query(DNSQuery.timestamp, DNSQuery.status).join(Device).filter(
        and_(Device.user_id == current_user.id, DNSQuery.timestamp >= day_ago)
    ).all()
    threats_24h = db.query(ThreatDetection.timestamp).join(Device).filter(
        and_(Device.user_id == current_user.id, ThreatDetection.timestamp >= day_ago)
    ).all()

    # Helper to floor to the top of the hour
    def hour_bucket(dt: datetime) -> datetime:
        return dt.replace(minute=0, second=0, microsecond=0)

    # Initialize 24 buckets
    now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    buckets = {}
    for i in range(23, -1, -1):
        t = now - timedelta(hours=i)
        buckets[t] = {"time": t.isoformat() + "Z", "queries": 0, "blocked": 0, "threats": 0}

    # Aggregate queries
    for ts, status in queries_24h:
        hb = hour_bucket(ts)
        if hb in buckets:
            buckets[hb]["queries"] += 1
            if str(status) == "DNSQueryStatus.BLOCKED" or str(status).endswith("blocked"):
                buckets[hb]["blocked"] += 1

    # Aggregate threats
    for (ts,) in threats_24h:
        hb = hour_bucket(ts)
        if hb in buckets:
            buckets[hb]["threats"] += 1

    threat_timeline = list(buckets.values())

    return NetworkAnalytics(
        total_devices=total_devices,
        active_devices=active_devices,
        total_queries_24h=total_queries_24h,
        blocked_queries_24h=blocked_queries_24h,
        threats_detected_24h=threats_detected_24h,
        top_blocked_domains=top_blocked_domains,
        threat_timeline=threat_timeline
    )
