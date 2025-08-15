#!/usr/bin/env python3
"""
Moved from dns_monitoring/test_data_pipeline.py to keep all tests under /tests.
This file remains a script-style integration check and is executed by
tests/integration/test_run_data_pipeline_script.py.
"""

import asyncio
import aiohttp
import sqlite3
import json
import time
from datetime import datetime
from typing import List, Dict
import os

# Test configuration
API_BASE_URL = "http://localhost:8000/api"
# Resolve DB path relative to repo root to match .env (sqlite:///./ai_firewall.db)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
DATABASE_PATH = os.path.join(REPO_ROOT, "ai_firewall.db")

class DataPipelineTest:
    def __init__(self):
        self.session = None
        self.test_results = []
    
    async def setup(self):
        """Initialize HTTP session for API calls"""
        self.session = aiohttp.ClientSession()
        print("🔧 Setting up data pipeline test...")
    
    async def cleanup(self):
        """Clean up HTTP session"""
        if self.session:
            await self.session.close()
        print("🧹 Cleanup completed")
    
    def create_sample_dns_data(self, count: int = 5) -> List[Dict]:
        """Generate sample DNS query data matching C++ format"""
        sample_domains = [
            "google.com", "facebook.com", "github.com", 
            "stackoverflow.com", "reddit.com"
        ]
        
        queries = []
        base_timestamp = int(time.time())
        
        for i in range(count):
            query = {
                "device_id": "test_device_001",
                "query_name": sample_domains[i % len(sample_domains)],
                "query_type": "A",
                "client_ip": f"192.168.1.{100 + i}",
                "server_ip": "8.8.8.8",
                "timestamp": base_timestamp + i,
                "is_response": i % 2 == 1,  # Mix queries and responses
                "response_code": "NOERROR" if i % 2 == 1 else "",
                "response_ip": f"142.250.{i}.{i}" if i % 2 == 1 else ""
            }
            queries.append(query)
        
        return queries
    
    async def test_api_health(self) -> bool:
        """Test if FastAPI backend is running"""
        try:
            async with self.session.get(f"{API_BASE_URL}/health") as response:
                if response.status == 200:
                    print("✅ FastAPI backend is running")
                    return True
                else:
                    print(f"❌ FastAPI backend returned status {response.status}")
                    return False
        except Exception as e:
            print(f"❌ Failed to connect to FastAPI backend: {e}")
            print("💡 Make sure to start the backend: uvicorn backend.main:app --reload")
            return False
    
    async def test_batch_endpoint(self) -> bool:
        """Test the batch DNS queries endpoint"""
        print("\n📡 Testing batch DNS endpoint...")
        
        # Create sample data
        sample_queries = self.create_sample_dns_data(3)
        print(f"📝 Created {len(sample_queries)} sample DNS queries")
        
        try:
            async with self.session.post(
                f"{API_BASE_URL}/dns/dns-queries/batch",
                json=sample_queries,
                headers={"Content-Type": "application/json"}
            ) as response:
                
                if response.status == 200:
                    result = await response.json()
                    print(f"✅ Batch endpoint successful: {result}")
                    return True
                else:
                    error_text = await response.text()
                    print(f"❌ Batch endpoint failed (status {response.status}): {error_text}")
                    return False
                    
        except Exception as e:
            print(f"❌ Batch endpoint error: {e}")
            return False
    
    def test_database_storage(self) -> bool:
        """Verify data was actually stored in the database"""
        print("\n💾 Testing database storage...")
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Check if tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            if 'devices' not in tables or 'dns_queries' not in tables:
                print("❌ Required database tables not found")
                print(f"📋 Available tables: {tables}")
                return False
            
            # Check if our test data was inserted
            cursor.execute("""
                SELECT COUNT(*) FROM dns_queries 
                WHERE query_name IN ('google.com', 'facebook.com', 'github.com')
            """)
            count = cursor.fetchone()[0]
            
            if count > 0:
                print(f"✅ Found {count} DNS queries in database")
                
                # Show sample of stored data
                cursor.execute("""
                    SELECT device_id, query_name, query_type, client_ip, timestamp 
                    FROM dns_queries 
                    ORDER BY timestamp DESC 
                    LIMIT 3
                """)
                
                print("📊 Sample stored data:")
                for row in cursor.fetchall():
                    print(f"   {row}")
                
                return True
            else:
                print("❌ No test DNS queries found in database")
                return False
                
        except Exception as e:
            print(f"❌ Database test error: {e}")
            return False
        finally:
            if 'conn' in locals():
                conn.close()
    
    async def test_device_auto_registration(self) -> bool:
        """Test that devices are auto-registered when they send data"""
        print("\n🔄 Testing device auto-registration...")
        
        # Create query from new device
        new_device_query = [{
            "device_id": "auto_test_device_002", 
            "query_name": "example.com",
            "query_type": "A",
            "client_ip": "192.168.1.200",
            "server_ip": "1.1.1.1",
            "timestamp": int(time.time()),
            "is_response": False
        }]
        
        try:
            async with self.session.post(
                f"{API_BASE_URL}/dns/dns-queries/batch",
                json=new_device_query
            ) as response:
                
                if response.status == 200:
                    print("✅ Auto-registration endpoint successful")
                    
                    # Verify device was created in database
                    conn = sqlite3.connect(DATABASE_PATH)
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM devices WHERE device_id = ?", ("auto_test_device_002",))
                    device = cursor.fetchone()
                    conn.close()
                    
                    if device:
                        print("✅ Device auto-registered successfully")
                        return True
                    else:
                        print("❌ Device not found in database after auto-registration")
                        return False
                else:
                    print(f"❌ Auto-registration failed (status {response.status})")
                    return False
                    
        except Exception as e:
            print(f"❌ Auto-registration test error: {e}")
            return False
    
    async def test_performance(self) -> bool:
        """Test performance with larger batch sizes"""
        print("\n⚡ Testing performance with larger batches...")
        
        # Create larger dataset
        large_batch = self.create_sample_dns_data(100)
        
        start_time = time.time()
        
        try:
            async with self.session.post(
                f"{API_BASE_URL}/dns/dns-queries/batch",
                json=large_batch
            ) as response:
                
                end_time = time.time()
                duration = end_time - start_time
                
                if response.status == 200:
                    result = await response.json()
                    throughput = len(large_batch) / duration
                    print(f"✅ Performance test successful:")
                    print(f"   📊 Processed {len(large_batch)} queries in {duration:.2f} seconds")
                    print(f"   🚀 Throughput: {throughput:.1f} queries/second")
                    return True
                else:
                    print(f"❌ Performance test failed (status {response.status})")
                    return False
                    
        except Exception as e:
            print(f"❌ Performance test error: {e}")
            return False
    
    async def run_all_tests(self):
        """Run the complete test suite"""
        print("=" * 50)
        print("🧪 DATA PIPELINE INTEGRATION TEST")
        print("=" * 50)
        
        tests = [
            ("API Health Check", self.test_api_health),
            ("Batch Endpoint", self.test_batch_endpoint),
            ("Database Storage", self.test_database_storage),
            ("Device Auto-Registration", self.test_device_auto_registration),
            ("Performance Test", self.test_performance),
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🔍 Running: {test_name}")
            try:
                if asyncio.iscoroutinefunction(test_func):
                    result = await test_func()
                else:
                    result = test_func()
                
                if result:
                    passed += 1
                    self.test_results.append(f"✅ {test_name}")
                else:
                    self.test_results.append(f"❌ {test_name}")
            except Exception as e:
                print(f"❌ {test_name} threw exception: {e}")
                self.test_results.append(f"❌ {test_name} (exception)")
        
        # Final report
        print("\n" + "=" * 50)
        print("📋 TEST RESULTS SUMMARY")
        print("=" * 50)
        
        for result in self.test_results:
            print(result)
        
        print(f"\n🎯 SCORE: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 ALL TESTS PASSED! Data pipeline is working correctly.")
            print("\n✨ Next steps:")
            print("   1. Deploy C++ DNS monitor to test with real packets")
            print("   2. Set up AI threat detection pipeline")
            print("   3. Create monitoring dashboard")
        else:
            print("⚠️  Some tests failed. Check the errors above.")
            print("\n🔧 Troubleshooting:")
            print("   1. Ensure FastAPI backend is running: uvicorn backend.main:app --reload")
            print("   2. Check database permissions and path")
            print("   3. Verify API endpoint URLs match")

async def main():
    """Main test execution"""
    test_runner = DataPipelineTest()
    
    try:
        await test_runner.setup()
        await test_runner.run_all_tests()
    finally:
        await test_runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
