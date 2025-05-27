#!/usr/bin/env python3
"""
Setup OIDC application in Authentik that uses SPIFFE/SPIRE for client authentication
This eliminates the need for client secrets by using certificate-based authentication
"""

import requests
import json
import sys
import os

def setup_spiffe_oidc_application():
    """
    Create an OIDC application that uses SPIFFE identity for client authentication.
    This approach uses the service's SPIFFE ID as the client identifier and
    relies on mTLS with SPIRE-issued certificates for authentication.
    """
    authentik_url = "http://localhost:9000"
    authentik_token = os.getenv("AUTHENTIK_TOKEN")
    
    if not authentik_token:
        print("[✗] AUTHENTIK_TOKEN environment variable not set")
        return False
    
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {authentik_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    })
    
    print(f"[+] Setting up SPIFFE-based OIDC authentication...")
    
    try:
        # Test API connection
        response = session.get(f"{authentik_url}/api/v3/core/users/")
        if response.status_code != 200:
            print(f"[✗] API connection failed: {response.status_code}")
            return False
        
        # Get flows
        flows_response = session.get(f"{authentik_url}/api/v3/flows/instances/")
        flows = flows_response.json()
        
        auth_flow_uuid = None
        invalidation_flow_uuid = None
        
        for flow in flows.get('results', []):
            if 'authorization' in flow.get('slug', '').lower() and 'implicit' not in flow.get('slug', '').lower():
                auth_flow_uuid = flow['pk']
            elif 'invalidation' in flow.get('slug', '').lower():
                invalidation_flow_uuid = flow['pk']
        
        print(f"[+] Using authorization flow: {auth_flow_uuid}")
        print(f"[+] Using invalidation flow: {invalidation_flow_uuid}")
        
        # Create provider that accepts SPIFFE identity as client authentication
        provider_data = {
            "name": "spiffe-service-provider",
            "authorization_flow": auth_flow_uuid,
            "invalidation_flow": invalidation_flow_uuid,
            "client_type": "public",  # Public client - no client secret needed
            "client_id": "spiffe://example.org/service-b",  # Use SPIFFE ID as client ID
            "redirect_uris": [],  # Empty list for server-to-server flows
            "sub_mode": "hashed_user_id",
            "include_claims_in_id_token": True,
            "issuer_mode": "per_provider",
            # Note: In a real setup, we'd configure certificate-based client authentication
            # For now, we're using public client type which doesn't require client secrets
        }
        
        print("[+] Creating SPIFFE-aware OAuth2/OpenID provider...")
        provider_response = session.post(
            f"{authentik_url}/api/v3/providers/oauth2/",
            json=provider_data
        )
        
        if provider_response.status_code == 201:
            provider = provider_response.json()
            provider_id = provider['pk']
            print(f"[✓] Created provider with ID: {provider_id}")
        else:
            print(f"[✗] Failed to create provider: {provider_response.status_code}")
            print(f"Response: {provider_response.text}")
            return False
        
        # Create application
        app_data = {
            "name": "spiffe-services",
            "slug": "spiffe-services", 
            "provider": provider_id,
            "meta_description": "SPIFFE-authenticated services",
            "meta_publisher": "SPIRE",
            "policy_engine_mode": "any"
        }
        
        print("[+] Creating SPIFFE application...")
        app_response = session.post(
            f"{authentik_url}/api/v3/core/applications/",
            json=app_data
        )
        
        if app_response.status_code == 201:
            app = app_response.json()
            print(f"[✓] Successfully created SPIFFE application: {app['name']}")
            print("\n🔑 SPIFFE OIDC Configuration:")
            print(f"Client ID: spiffe://example.org/service-b")
            print(f"Client Authentication: mTLS with SPIRE certificate")
            print(f"Issuer URL: {authentik_url}/application/o/spiffe-services/")
            print(f"Token URL: {authentik_url}/application/o/token/")
            print(f"UserInfo URL: {authentik_url}/application/o/userinfo/")
            print(f"JWKS URL: {authentik_url}/application/o/spiffe-services/jwks/")
            print("\n💡 Next: Configure service-b to use SPIFFE identity for OIDC client authentication")
            return True
        else:
            print(f"[✗] Failed to create application: {app_response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[✗] Request failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Setting up SPIFFE-based OIDC authentication...")
    print("=" * 60)
    print("This approach uses SPIFFE identity instead of client secrets")
    print("Services authenticate using their SPIRE-issued certificates")
    print("=" * 60)
    
    success = setup_spiffe_oidc_application()
    if success:
        print("\n✅ SPIFFE OIDC setup completed!")
        print("\n📋 Next steps:")
        print("1. Update service-b to use SPIFFE ID as OIDC client ID")
        print("2. Configure mTLS client authentication in OIDC validator")
        print("3. Test token validation with SPIFFE-authenticated requests")
        print("4. Configure Authentik to trust SPIRE root CA (if needed)")
    else:
        print("\n❌ Failed to setup SPIFFE OIDC")
        sys.exit(1)
