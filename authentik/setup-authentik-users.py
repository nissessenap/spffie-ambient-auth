#!/usr/bin/env python3
"""
Authentik User Setup Script (Token-based)

This script creates test users in Authentik via the API using a pre-created API token.
This is the most reliable method for API access.

Prerequisites:
1. Authentik running and accessible (kubectl port-forward -n authentik svc/authentik-server 9000:80)
2. Create an API token in Authentik web UI:
   - Go to http://localhost:9000/if/admin/#/core/tokens
   - Login with akadmin/test
   - Create new token with identifier "api-setup" 
   - Copy the token value

Usage:
    export AUTHENTIK_TOKEN="your-token-here"
    python3 setup-authentik-users-token.py
"""

import requests
import json
import sys
import os
from typing import List, Dict, Any

# Configuration
AUTHENTIK_BASE_URL = "http://localhost:9000"
AUTHENTIK_TOKEN = os.getenv("AUTHENTIK_TOKEN")

class AuthentikAPIClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        self._test_connection()
    
    def _test_connection(self):
        """Test API connection"""
        print(f"[+] Testing connection to Authentik at {self.base_url}...")
        response = self.session.get(f"{self.base_url}/api/v3/core/users/")
        if response.status_code != 200:
            raise Exception(f"API connection failed: {response.status_code} - {response.text}")
        print("[+] Successfully connected to Authentik API")
    
    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user in Authentik"""
        print(f"[+] Creating user: {user_data['username']}")
        
        response = self.session.post(f"{self.base_url}/api/v3/core/users/", json=user_data)
        
        if response.status_code == 201:
            user = response.json()
            print(f"[✓] User {user_data['username']} created successfully (ID: {user['pk']})")
            return user
        elif response.status_code == 400 and "username" in response.text:
            print(f"[!] User {user_data['username']} already exists, skipping...")
            # Try to get existing user
            existing_response = self.session.get(f"{self.base_url}/api/v3/core/users/?username={user_data['username']}")
            if existing_response.status_code == 200:
                results = existing_response.json().get('results', [])
                if results:
                    return results[0]
            return None
        else:
            print(f"[✗] Failed to create user {user_data['username']}: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    
    def create_group(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new group in Authentik"""
        print(f"[+] Creating group: {group_data['name']}")
        
        response = self.session.post(f"{self.base_url}/api/v3/core/groups/", json=group_data)
        
        if response.status_code == 201:
            group = response.json()
            print(f"[✓] Group {group_data['name']} created successfully (ID: {group['pk']})")
            return group
        elif response.status_code == 400 and "name" in response.text:
            print(f"[!] Group {group_data['name']} already exists, fetching existing...")
            # Get existing group
            existing = self.session.get(f"{self.base_url}/api/v3/core/groups/?name={group_data['name']}")
            if existing.status_code == 200 and existing.json()['results']:
                return existing.json()['results'][0]
            return None
        else:
            print(f"[✗] Failed to create group {group_data['name']}: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    
    def add_user_to_group(self, user_id: str, group_id: str):
        """Add user to a group"""
        # Get current user data first
        user_response = self.session.get(f"{self.base_url}/api/v3/core/users/{user_id}/")
        if user_response.status_code != 200:
            print(f"[✗] Failed to get user data: {user_response.status_code}")
            return
        
        user_data = user_response.json()
        current_groups = user_data.get('groups', [])
        
        # Add group if not already present
        if group_id not in current_groups:
            current_groups.append(group_id)
            update_data = {"groups": current_groups}
            
            response = self.session.patch(f"{self.base_url}/api/v3/core/users/{user_id}/", json=update_data)
            
            if response.status_code == 200:
                print(f"[✓] User {user_id} added to group {group_id}")
            else:
                print(f"[✗] Failed to add user to group: {response.status_code}")
                print(f"Response: {response.text}")
        else:
            print(f"[!] User {user_id} already in group {group_id}")

def create_test_users():
    """Create a set of test users for OIDC testing"""
    
    if not AUTHENTIK_TOKEN:
        print("[✗] AUTHENTIK_TOKEN environment variable not set")
        print("Please create an API token in Authentik and set it:")
        print("1. Go to http://localhost:9000/if/admin/#/core/tokens")
        print("2. Login with akadmin/test")
        print("3. Create new token with identifier 'api-setup'")
        print("4. Copy the token and run: export AUTHENTIK_TOKEN='your-token-here'")
        sys.exit(1)
    
    # Test groups
    test_groups = [
        {
            "name": "admin",
            "is_superuser": False,
            "attributes": {
                "role": "admin",
                "permissions": ["read", "write", "delete", "manage"]
            }
        },
        {
            "name": "manager", 
            "is_superuser": False,
            "attributes": {
                "role": "manager",
                "permissions": ["read", "write", "manage_team"]
            }
        },
        {
            "name": "user",
            "is_superuser": False,
            "attributes": {
                "role": "user", 
                "permissions": ["read"]
            }
        }
    ]
    
    # Test users with different roles/permissions
    test_users = [
        {
            "username": "alice",
            "email": "alice@example.com",
            "name": "Alice Johnson",
            "is_active": True,
            "password": "testpassword123",
            "groups": ["admin"]
        },
        {
            "username": "bob",
            "email": "bob@example.com", 
            "name": "Bob Smith",
            "is_active": True,
            "password": "testpassword123",
            "groups": ["user"]
        },
        {
            "username": "charlie",
            "email": "charlie@example.com",
            "name": "Charlie Brown",
            "is_active": True,
            "password": "testpassword123",
            "groups": ["user"]
        },
        {
            "username": "dana",
            "email": "dana@example.com",
            "name": "Dana Wilson",
            "is_active": True,
            "password": "testpassword123",
            "groups": ["manager"]
        }
    ]
    
    try:
        # Initialize API client
        client = AuthentikAPIClient(AUTHENTIK_BASE_URL, AUTHENTIK_TOKEN)
        
        # Create groups first
        created_groups = {}
        for group_data in test_groups:
            group = client.create_group(group_data)
            if group:
                created_groups[group_data['name']] = group['pk']
        
        # Create users and assign to groups
        created_users = []
        for user_data in test_users:
            user_groups = user_data.pop('groups', [])
            
            user = client.create_user(user_data)
            if user:
                created_users.append(user_data['username'])
                for group_name in user_groups:
                    if group_name in created_groups:
                        client.add_user_to_group(user['pk'], created_groups[group_name])
        
        print("\n[✓] Setup completed!")
        print("\nCreated/verified users:")
        for username in created_users:
            print(f"  - {username} (password: testpassword123)")
        
        print(f"\nAuthentik available at: {AUTHENTIK_BASE_URL}")
        print("You can now test the OIDC flow with these users.")
        
    except Exception as e:
        print(f"[✗] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("Authentik User Setup Script (Token-based)")
    print("=" * 50)
    
    # Check if Authentik is accessible
    try:
        response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/", timeout=5)
        if response.status_code != 200:
            print(f"[✗] Authentik is not accessible at {AUTHENTIK_BASE_URL}")
            print("Make sure to run: kubectl port-forward -n authentik svc/authentik-server 9000:80")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"[✗] Cannot connect to Authentik at {AUTHENTIK_BASE_URL}")
        print("Make sure to run: kubectl port-forward -n authentik svc/authentik-server 9000:80")
        sys.exit(1)
    
    create_test_users()
