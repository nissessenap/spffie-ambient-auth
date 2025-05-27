#!/usr/bin/env python3
"""
Setup OIDC application in Authentik for service-b using token-based authentication
"""

import requests
import json
import sys
import os

def setup_oidc_application():
    # Authentik configuration
    authentik_url = "http://localhost:9000"  # Changed to match port-forward
    authentik_token = os.getenv("AUTHENTIK_TOKEN")
    
    if not authentik_token:
        print("[✗] AUTHENTIK_TOKEN environment variable not set")
        print("Please create an API token in Authentik and set it:")
        print("1. Go to http://localhost:9000/if/admin/#/core/tokens")
        print("2. Login with akadmin/test")
        print("3. Create new token with identifier 'api-setup'")
        print("4. Copy the token and run: export AUTHENTIK_TOKEN='your-token-here'")
        return False
    
    # Create session with token authentication
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {authentik_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    })
    
    print(f"[+] Testing connection to Authentik at {authentik_url}...")
    
    try:
        # Test API connection
        response = session.get(f"{authentik_url}/api/v3/core/users/")
        if response.status_code != 200:
            print(f"[✗] API connection failed: {response.status_code} - {response.text}")
            return False
        print("[+] Successfully connected to Authentik API")
        
        # First, get the default authorization flow UUID
        flows_response = session.get(f"{authentik_url}/api/v3/flows/instances/")
        if flows_response.status_code != 200:
            print(f"[✗] Failed to get flows: {flows_response.status_code}")
            return False
        
        flows = flows_response.json()
        auth_flow_uuid = None
        invalidation_flow_uuid = None
        
        for flow in flows.get('results', []):
            if flow.get('slug') == 'default-provider-authorization-explicit-consent':
                auth_flow_uuid = flow['pk']
            elif flow.get('slug') == 'default-provider-invalidation-flow':
                invalidation_flow_uuid = flow['pk']
        
        if not auth_flow_uuid:
            print("[!] Could not find default authorization flow, using first available...")
            for flow in flows.get('results', []):
                if 'authorization' in flow.get('slug', '').lower():
                    auth_flow_uuid = flow['pk']
                    break
        
        if not invalidation_flow_uuid:
            print("[!] Could not find invalidation flow, using first available...")
            for flow in flows.get('results', []):
                if 'invalidation' in flow.get('slug', '').lower():
                    invalidation_flow_uuid = flow['pk']
                    break
        
        print(f"Using authorization flow: {auth_flow_uuid}")
        print(f"Using invalidation flow: {invalidation_flow_uuid}")
        
        # Create provider with empty redirect URIs first
        provider_data = {
            "name": "service-b-provider",
            "authorization_flow": auth_flow_uuid,
            "invalidation_flow": invalidation_flow_uuid,
            "client_type": "confidential", 
            "client_id": "service-b",
            "client_secret": "service-b-secret-key",
            "redirect_uris": []
        }
        
        print("Creating OAuth2/OpenID provider...")
        provider_response = session.post(
            f"{authentik_url}/api/v3/providers/oauth2/",
            json=provider_data
        )
        
        if provider_response.status_code == 201:
            provider = provider_response.json()
            provider_id = provider['pk']
            print(f"Created provider with ID: {provider_id}")
        else:
            print(f"Failed to create provider: {provider_response.status_code}")
            print(f"Response: {provider_response.text}")
            return False
        
        # Create application
        app_data = {
            "name": "service-b",
            "slug": "service-b",
            "provider": provider_id,
            "meta_launch_url": "",
            "meta_description": "Service B OIDC Application",
            "meta_publisher": "SpiffieAuth Demo",
            "policy_engine_mode": "any",
            "group": ""
        }
        
        print("Creating application...")
        app_response = session.post(
            f"{authentik_url}/api/v3/core/applications/",
            json=app_data
        )
        
        if app_response.status_code == 201:
            app = app_response.json()
            print(f"Successfully created application: {app['name']}")
            print(f"Application slug: {app['slug']}")
            print(f"Provider ID: {provider_id}")
            print(f"Client ID: service-b")
            print(f"Client Secret: service-b-secret-key")
            print("\nOIDC Configuration:")
            print(f"Issuer URL: {authentik_url}/application/o/service-b/")
            print(f"Authorization URL: {authentik_url}/application/o/authorize/")
            print(f"Token URL: {authentik_url}/application/o/token/")
            print(f"UserInfo URL: {authentik_url}/application/o/userinfo/")
            print(f"JWKS URL: {authentik_url}/application/o/service-b/jwks/")
            return True
        else:
            print(f"Failed to create application: {app_response.status_code}")
            print(f"Response: {app_response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return False

if __name__ == "__main__":
    print("Setting up OIDC application in Authentik...")
    
    # Check if Authentik is accessible
    try:
        response = requests.get("http://localhost:9000/api/v3/", timeout=5)
        if response.status_code != 200:
            print(f"[✗] Authentik is not accessible at http://localhost:9000")
            print("Make sure to run: kubectl port-forward -n authentik svc/authentik-server 9000:80")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"[✗] Cannot connect to Authentik at http://localhost:9000")
        print("Make sure to run: kubectl port-forward -n authentik svc/authentik-server 9000:80")
        sys.exit(1)
    
    success = setup_oidc_application()
    if success:
        print("\n✅ OIDC application setup completed successfully!")
        print("\nNext steps:")
        print("1. Test token retrieval from Authentik")
        print("2. Update service-a to forward Bearer tokens")
        print("3. Test end-to-end authentication flow")
    else:
        print("\n❌ Failed to setup OIDC application")
        sys.exit(1)
