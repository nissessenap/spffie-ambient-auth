#!/usr/bin/env python3
"""
Test script to get user tokens from Authentik and test service authentication
"""

import requests
import json
import sys
import os

def get_user_token(username, password):
    """Get an access token for a user using OAuth2 Resource Owner Password Credentials Grant"""
    
    authentik_url = "http://localhost:9000"
    
    # OAuth2 token endpoint
    token_url = f"{authentik_url}/application/o/token/"
    
    # For the SPIFFE application we created
    client_id = "spiffe://example.org/service-b"
    
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": client_id,
        "scope": "openid profile email"
    }
    
    try:
        response = requests.post(token_url, data=data)
        
        if response.status_code == 200:
            token_data = response.json()
            print(f"✅ Successfully got token for user: {username}")
            print(f"Access Token: {token_data.get('access_token', 'N/A')[:50]}...")
            print(f"ID Token: {token_data.get('id_token', 'N/A')[:50]}...")
            print(f"Token Type: {token_data.get('token_type', 'N/A')}")
            print(f"Expires In: {token_data.get('expires_in', 'N/A')} seconds")
            return token_data.get('access_token')
        else:
            print(f"❌ Failed to get token for {username}: {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return None

def test_service_with_token(token):
    """Test calling service-a with a user token"""
    
    if not token:
        print("❌ No token to test with")
        return
    
    # Test calling service-a plain HTTP endpoint (for testing)
    service_url = "http://localhost:8081/hello"  # Plain HTTP port for testing
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        print(f"\n🧪 Testing service call with user token...")
        response = requests.get(service_url, headers=headers)
        
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ Service call successful!")
        else:
            print("❌ Service call failed")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Service call failed: {e}")

if __name__ == "__main__":
    print("🧪 Testing OIDC User Authentication Flow")
    print("=" * 50)
    
    # Test users we created earlier
    test_users = [
        {"username": "alice", "password": "testpassword123"},
        {"username": "bob", "password": "testpassword123"}
    ]
    
    for user in test_users:
        print(f"\n📝 Testing authentication for user: {user['username']}")
        token = get_user_token(user['username'], user['password'])
        
        if token:
            # Test calling service with the token
            test_service_with_token(token)
        
        print("-" * 30)
    
    print("\n📋 Next steps:")
    print("1. Ensure SPIFFE OIDC application is created in Authentik")
    print("2. Start service-a and service-b with SPIRE")
    print("3. Test end-to-end authentication flow")
    print("4. Verify token validation in service-b")
