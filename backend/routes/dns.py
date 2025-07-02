"""
DNS monitoring and threat detection API routes.
Handles device management, DNS query logging, and threat analysis.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func, and_
from typing import List, Optional
from datetime import datetime, timedelta

from database import get_db
from dependencies import get_current_user, require_role
from models.users import Users
from models.dns_models import Device, DNSQuery, ThreatDetection, DomainReputation, NetworkSettings
from schemas.dns_schemas import (
    DeviceCreate, DeviceResponse, DeviceUpdate,
    DNSQueryCreate, DNSQueryResponse, DNSQueryAnalysis,
    ThreatDetectionCreate, ThreatDetectionResponse, ThreatSummary,
    DomainReputationResponse, DomainAnalysisRequest,
    NetworkSettingsUpdate, NetworkSettingsResponse,
    DeviceStats, NetworkAnalytics, AlertResponse
)

router = APIRouter()

# Device Management Endpoints
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
    blocked_queries = db.query(DNSQuery).join(Device).filter(
        and_(
            Device.user_id == current_user.id,
            DNSQuery.timestamp >= since,
            DNSQuery.status == "blocked"
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
    
    # Count devices
    total_devices = db.query(Device).filter(Device.user_id == current_user.id).count()
    
    # Active devices (seen in last hour)
    hour_ago = datetime.utcnow() - timedelta(hours=1)
    active_devices = db.query(Device).filter(
        and_(
            Device.user_id == current_user.id,
            Device.last_seen >= hour_ago,
            Device.is_active == True
        )
    ).count()
    
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
    
    return NetworkAnalytics(
        total_devices=total_devices,
        active_devices=active_devices,
        total_queries_24h=total_queries_24h,
        blocked_queries_24h=blocked_queries_24h,
        threats_detected_24h=threats_detected_24h,
        top_blocked_domains=top_blocked_domains,
        threat_timeline=[]  # TODO: Implement timeline data
    )
