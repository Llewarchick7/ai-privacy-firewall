#!/usr/bin/env python3
"""
Database Initialization Script
=============================

This script initializes the database with required tables and sample data
for testing the DNS monitoring data pipeline.

Usage:
    cd backend
    python3 init_database.py
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import engine, SessionLocal, Base
from backend.models.users import Users
from backend.models.dns_models import Device, DNSQuery
from sqlalchemy.orm import Session
import hashlib

def create_tables():
    """Create all database tables"""
    print("🔧 Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully")

def create_test_user():
    """Create a test user for development"""
    db = SessionLocal()
    try:
        # Check if test user already exists
        existing_user = db.query(Users).filter(Users.email == "test@example.com").first()
        if existing_user:
            print("✅ Test user already exists")
            return existing_user
        
        # Create test user
        hashed_password = hashlib.sha256("testpassword".encode()).hexdigest()
        test_user = Users(
            username="testuser",
            email="test@example.com",
            hashed_password=hashed_password,
            role="admin",
            is_active=True
        )
        
        db.add(test_user)
        db.commit()
        db.refresh(test_user)
        
        print("✅ Test user created:")
        print(f"   Email: test@example.com")
        print(f"   Password: testpassword")
        print(f"   Role: admin")
        
        return test_user
        
    except Exception as e:
        print(f"❌ Failed to create test user: {e}")
        db.rollback()
        return None
    finally:
        db.close()

def verify_database():
    """Verify database setup is working"""
    db = SessionLocal()
    try:
        # Test queries
        users_count = db.query(Users).count()
        devices_count = db.query(Device).count()
        queries_count = db.query(DNSQuery).count()
        
        print("\n📊 Database Status:")
        print(f"   Users: {users_count}")
        print(f"   Devices: {devices_count}") 
        print(f"   DNS Queries: {queries_count}")
        
        return True
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False
    finally:
        db.close()

def main():
    """Main initialization process"""
    print("=" * 50)
    print("🚀 DNS MONITORING DATABASE INITIALIZATION")
    print("=" * 50)
    
    try:
        # Step 1: Create tables
        create_tables()
        
        # Step 2: Create test user
        test_user = create_test_user()
        if not test_user:
            print("❌ Failed to create test user - exiting")
            return
        
        # Step 3: Verify setup
        if verify_database():
            print("\n🎉 Database initialization completed successfully!")
            print("\n✨ Next steps:")
            print("   1. Start FastAPI: uvicorn backend.main:app --reload")
            print("   2. Run pipeline test: python3 dns_monitoring/test_data_pipeline.py")
            print("   3. Test C++ integration: sudo ./dns_monitoring/build/bin/dns_monitor_test")
        else:
            print("❌ Database verification failed")
            
    except Exception as e:
        print(f"❌ Initialization failed: {e}")

if __name__ == "__main__":
    main()
