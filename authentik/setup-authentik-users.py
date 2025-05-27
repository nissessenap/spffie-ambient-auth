#!/usr/bin/env python3
"""
Authentik User Setup Script

This script creates test users in Authentik via the API for testing OIDC flows
in the microservices architecture.

Prerequisites:
- Authentik running and accessible (kubectl port-forward -n authentik svc/authentik-server 8080:80)
- Admin credentials (akadmin/test based on your config)

Usage:
    python3 setup-authentik-users.py
"""

import requests
import json
import sys
from typing import List, Dict, Any

# Configuration
AUTHENTIK_BASE_URL = "http://localhost:8080"
ADMIN_USERNAME = "akadmin"
ADMIN_PASSWORD = "test"  # From your authentik-values.yaml bootstrap_password

class AuthentikAPIClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        self._authenticate(username, password)
    
    def _authenticate(self, username: str, password: str):
        """Authenticate with Authentik and get session cookies"""
        print(f"[+] Authenticating with Authentik at {self.base_url}...")
        
        # Get CSRF token first
        response = self.session.get(f"{self.base_url}/api/v3/")
        if response.status_code != 200:
            raise Exception(f"Failed to connect to Authentik: {response.status_code}")
        
        # Login via API
        login_data = {
            "username": username,
            "password": password
        }
        
        response = self.session.post(f"{self.base_url}/api/v3/flows/executor/default-authentication-flow/", 
                                   json=login_data)
        
        if response.status_code not in [200, 302]:
            # Try alternative authentication method
            auth_response = self.session.post(f"{self.base_url}/api/v3/auth/login/", json=login_data)
            if auth_response.status_code not in [200, 204]:
                print(f"Authentication failed: {auth_response.status_code}")
                print(f"Response: {auth_response.text}")
                raise Exception("Failed to authenticate with Authentik")
        
        print("[+] Successfully authenticated with Authentik")
    
    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user in Authentik"""
        print(f"[+] Creating user: {user_data['username']}")
        
        response = self.session.post(f"{self.base_url}/api/v3/core/users/", json=user_data)
        
        if response.status_code == 201:
            user = response.json()
            print(f"[✓] User {user_data['username']} created successfully (ID: {user['pk']})")
            return user
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
        else:
            print(f"[✗] Failed to create group {group_data['name']}: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    
    def add_user_to_group(self, user_id: str, group_id: str):
        """Add user to a group"""
        user_data = {"groups": [group_id]}
        response = self.session.patch(f"{self.base_url}/api/v3/core/users/{user_id}/", json=user_data)
        
        if response.status_code == 200:
            print(f"[✓] User {user_id} added to group {group_id}")
        else:
            print(f"[✗] Failed to add user to group: {response.status_code}")
            print(f"Response: {response.text}")
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List all users"""
        response = self.session.get(f"{self.base_url}/api/v3/core/users/")
        if response.status_code == 200:
            return response.json()['results']
        else:
            print(f"Failed to list users: {response.status_code}")
            return []

def create_test_users():
    """Create a set of test users for OIDC testing"""
    
    # Test users with different roles/permissions
    test_users = [
        {
            "username": "alice",
            "email": "alice@example.com",
            "name": "Alice Johnson",
            "is_active": True,
            "groups": ["admin"]
        },
        {
            "username": "bob",
            "email": "bob@example.com", 
            "name": "Bob Smith",
            "is_active": True,
            "groups": ["user"]
        },
        {
            "username": "charlie",
            "email": "charlie@example.com",
            "name": "Charlie Brown",
            "is_active": True,
            "groups": ["user"]
        },
        {
            "username": "dana",
            "email": "dana@example.com",
            "name": "Dana Wilson",
            "is_active": True,
            "groups": ["manager"]
        }
    ]
    
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
    
    try:
        # Initialize API client
        client = AuthentikAPIClient(AUTHENTIK_BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD)
        
        # Create groups first
        created_groups = {}
        for group_data in test_groups:
            group = client.create_group(group_data)
            if group:
                created_groups[group_data['name']] = group['pk']
        
        # Create users and assign to groups
        for user_data in test_users:
            user_groups = user_data.pop('groups', [])
            # Set a default password for testing
            user_data['password'] = 'testpassword123'
            
            user = client.create_user(user_data)
            if user and user_groups:
                for group_name in user_groups:
                    if group_name in created_groups:
                        client.add_user_to_group(user['pk'], created_groups[group_name])
        
        print("\n[✓] All test users and groups created successfully!")
        print("\nTest Users:")
        for user in test_users:
            print(f"  - {user['username']} (password: testpassword123)")
        
        print("\nYou can now test the OIDC flow with these users.")
        
    except Exception as e:
        print(f"[✗] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("Authentik User Setup Script")
    print("=" * 40)
    
    # Check if Authentik is accessible
    try:
        response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/", timeout=5)
        if response.status_code != 200:
            print(f"[✗] Authentik is not accessible at {AUTHENTIK_BASE_URL}")
            print("Make sure to run: kubectl port-forward -n authentik svc/authentik-server 8080:80")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"[✗] Cannot connect to Authentik at {AUTHENTIK_BASE_URL}")
        print("Make sure to run: kubectl port-forward -n authentik svc/authentik-server 8080:80")
        sys.exit(1)
    
    create_test_users()
