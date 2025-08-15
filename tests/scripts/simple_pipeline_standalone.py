#!/usr/bin/env python3
"""
Simple Pipeline Test Without Dependencies
========================================

This script tests the basic data pipeline logic without requiring
FastAPI installation. It simulates the complete flow.
"""

import json
import sqlite3
import time
from datetime import datetime

def test_database_schema():
    """Test if the database exists and has the right structure"""
    print("🔍 Testing database schema...")
    
    try:
        conn = sqlite3.connect('ai_firewall.db')
        cursor = conn.cursor()
        
        # Check if required tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        required_tables = ['users', 'devices', 'dns_queries']
        missing_tables = [table for table in required_tables if table not in tables]
        
        if missing_tables:
            print(f"❌ Missing tables: {missing_tables}")
            print("📋 Available tables:", tables)
            return False
        else:
            print("✅ All required tables exist")
            return True
            
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def simulate_dns_data_insertion():
    """Simulate inserting DNS data directly into database"""
    print("\n📊 Testing DNS data insertion...")
    
    try:
        conn = sqlite3.connect('ai_firewall.db')
        cursor = conn.cursor()
        
        # Create a test device if it doesn't exist
        cursor.execute("""
            INSERT OR IGNORE INTO devices 
            (device_id, name, ip_address, mac_address, location, user_id) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("test_device_001", "Test Device", "192.168.1.100", "aa:bb:cc:dd:ee:ff", "test_lab", 1))
        
        # Get the device ID
        cursor.execute("SELECT id FROM devices WHERE device_id = ?", ("test_device_001",))
        device_row = cursor.fetchone()
        if not device_row:
            print("❌ Failed to create/find test device")
            return False
        
        device_id = device_row[0]
        
        # Insert test DNS queries
        test_queries = [
            ("google.com", "A", "192.168.1.100", "NOERROR", "142.250.191.14"),
            ("facebook.com", "A", "192.168.1.101", "NOERROR", "157.240.241.35"),
            ("github.com", "A", "192.168.1.102", "NOERROR", "140.82.113.4"),
        ]
        
        for query_name, query_type, client_ip, response_code, response_ip in test_queries:
            cursor.execute("""
                INSERT INTO dns_queries 
                (device_id, query_name, query_type, client_ip, response_code, response_ip, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (device_id, query_name, query_type, client_ip, response_code, response_ip, datetime.now()))
        
        conn.commit()
        
        # Verify insertion
        cursor.execute("SELECT COUNT(*) FROM dns_queries WHERE device_id = ?", (device_id,))
        count = cursor.fetchone()[0]
        
        print(f"✅ Inserted {len(test_queries)} DNS queries, found {count} in database")
        return True
        
    except Exception as e:
        print(f"❌ DNS data insertion failed: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def test_c_plus_plus_data_format():
    """Test if the data format from C++ matches what we expect"""
    print("\n🔧 Testing C++ data format compatibility...")
    
    # Simulate the format that C++ DNS monitor would send
    sample_cpp_data = [
        {
            "device_id": "cpp_test_device",
            "query_name": "example.com",
            "query_type": "A",
            "client_ip": "192.168.1.200",
            "server_ip": "8.8.8.8",
            "timestamp": int(time.time()),
            "is_response": False,
            "response_code": "",
            "response_ip": ""
        },
        {
            "device_id": "cpp_test_device", 
            "query_name": "example.com",
            "query_type": "A",
            "client_ip": "192.168.1.200",
            "server_ip": "8.8.8.8",
            "timestamp": int(time.time()),
            "is_response": True,
            "response_code": "NOERROR",
            "response_ip": "93.184.216.34"
        }
    ]
    
    try:
        conn = sqlite3.connect('ai_firewall.db')
        cursor = conn.cursor()
        
        # Process the data like our API would
        for query_data in sample_cpp_data:
            # Create device if it doesn't exist
            cursor.execute("""
                INSERT OR IGNORE INTO devices 
                (device_id, name, ip_address, mac_address, location, user_id) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                query_data["device_id"], 
                f"Auto-registered {query_data['device_id']}", 
                query_data["client_ip"], 
                query_data["device_id"], 
                "auto-detected", 
                1
            ))
            
            # Get device ID
            cursor.execute("SELECT id FROM devices WHERE device_id = ?", (query_data["device_id"],))
            device_id = cursor.fetchone()[0]
            
            # Insert DNS query
            cursor.execute("""
                INSERT INTO dns_queries 
                (device_id, query_name, query_type, client_ip, response_code, response_ip, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                device_id,
                query_data["query_name"],
                query_data["query_type"], 
                query_data["client_ip"],
                query_data["response_code"],
                query_data["response_ip"],
                datetime.fromtimestamp(query_data["timestamp"])
            ))
        
        conn.commit()
        print("✅ C++ data format compatibility test passed")
        return True
        
    except Exception as e:
        print(f"❌ C++ format test failed: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def show_data_summary():
    """Show summary of data in the database"""
    print("\n📈 Database Summary:")
    
    try:
        conn = sqlite3.connect('ai_firewall.db')
        cursor = conn.cursor()
        
        # Count records
        cursor.execute("SELECT COUNT(*) FROM devices")
        devices_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM dns_queries")
        queries_count = cursor.fetchone()[0]
        
        print(f"   📱 Devices: {devices_count}")
        print(f"   🔍 DNS Queries: {queries_count}")
        
        # Show recent queries
        cursor.execute("""
            SELECT d.device_id, q.query_name, q.query_type, q.client_ip, q.timestamp
            FROM dns_queries q
            JOIN devices d ON q.device_id = d.id
            ORDER BY q.timestamp DESC
            LIMIT 5
        """)
        
        print("\n📋 Recent DNS Queries:")
        for row in cursor.fetchall():
            device_id, query_name, query_type, client_ip, timestamp = row
            print(f"   {query_name} ({query_type}) from {device_id} @ {client_ip}")
        
    except Exception as e:
        print(f"❌ Summary failed: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

def main():
    """Run the complete pipeline test"""
    print("=" * 60)
    print("🧪 SIMPLE DATA PIPELINE TEST")
    print("=" * 60)
    
    tests = [
        ("Database Schema", test_database_schema),
        ("DNS Data Insertion", simulate_dns_data_insertion),
        ("C++ Format Compatibility", test_c_plus_plus_data_format),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 Running: {test_name}")
        if test_func():
            passed += 1
    
    show_data_summary()
    
    print("\n" + "=" * 60)
    print("📋 TEST RESULTS")
    print("=" * 60)
    print(f"🎯 Passed: {passed}/{total} tests")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED!")
        print("\n✨ Your data pipeline is working correctly!")
        print("\n🚀 Next steps:")
        print("   1. Install FastAPI: pip install fastapi uvicorn")
        print("   2. Start backend: uvicorn backend.main:app --reload")
        print("   3. Build C++ monitor: cd dns_monitoring && mkdir build && cd build && cmake .. && make")
        print("   4. Test complete pipeline: sudo ./dns_monitoring/build/bin/dns_monitor_test")
    else:
        print("⚠️  Some tests failed. Check database setup.")

if __name__ == "__main__":
    main()
