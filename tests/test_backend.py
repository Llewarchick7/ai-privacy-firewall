#!/usr/bin/env python3
"""
Test script for the AI Privacy Firewall backend API
"""

import requests
import json
import sys

BASE_URL = "http://localhost:8000"

def test_endpoint(method, endpoint, data=None, expected_status=200):
    """Test an API endpoint"""
    url = f"{BASE_URL}{endpoint}"
    try:
        if method.upper() == "GET":
            response = requests.get(url)
        elif method.upper() == "POST":
            response = requests.post(url, json=data)
        
        print(f"{'✅' if response.status_code == expected_status else '❌'} {method} {endpoint}")
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            try:
                print(f"   Response: {response.json()}")
            except:
                print(f"   Response: {response.text[:100]}...")
        elif response.status_code == 422:
            print(f"   Validation Error (Expected): {response.json()}")
        else:
            print(f"   Error: {response.text[:100]}...")
        print()
        
    except Exception as e:
        print(f"❌ {method} {endpoint}")
        print(f"   Error: {e}")
        print()

def main():
    """Run API tests"""
    print("🧪 Testing AI Privacy Firewall Backend API")
    print("=" * 50)
    
    # Test basic endpoints
    test_endpoint("GET", "/")
    test_endpoint("GET", "/docs")
    
    # Test API endpoints (expect validation errors without data)
    test_endpoint("POST", "/api/users/register", expected_status=422)
    test_endpoint("GET", "/api/dns/devices")
    test_endpoint("POST", "/api/dns/devices", expected_status=422)
    
    print("🏁 Backend API testing complete!")

if __name__ == "__main__":
    main()
