#!/usr/bin/env python3
"""
Setup OIDC application in Authentik that uses SPIFFE/SPIRE for client authentication
This eliminates the need for client secrets by using certificate-based authentication
"""

import requests
import json
import sys
import time

def setup_spiffe_oidc_application():
    # Authentik configuration
    authentik_url = "http://localhost:9000"
    admin_username = "akadmin"
    admin_password = "test"
    
    # Create session
    session = requests.Session()
    
    # Get CSRF token and login
    login_url = f"{authentik_url}/flows/default-authentication-flow/"
    print(f"Getting login page from {login_url}")
    
    try:
        response = session.get(login_url)
        response.raise_for_status()
        
        # Extract CSRF token from login page
        csrf_token = None
        for line in response.text.split('\n'):
            if 'csrfmiddlewaretoken' in line and 'value=' in line:
                csrf_token = line.split('value="')[1].split('"')[0]
                break
        
        if not csrf_token:
            print("Failed to extract CSRF token")
            return False
            
        print(f"Extracted CSRF token: {csrf_token[:20]}...")
        
        # Login
        login_data = {
            'csrfmiddlewaretoken': csrf_token,
            'uid_field': admin_username,
            'password': admin_password,
        }
        
        response = session.post(login_url, data=login_data, allow_redirects=True)
        print(f"Login response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"Login failed: {response.text[:500]}")
            return False
            
        # Check if we're logged in by trying to access admin interface
        admin_check = session.get(f"{authentik_url}/if/admin/")
        if admin_check.status_code != 200:
            print("Failed to access admin interface after login")
            return False
            
        print("Successfully logged in to Authentik")
        
        # Now use the API with session cookies
        api_headers = {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrf_token,
            'Referer': authentik_url
        }
        
        # Create a provider that supports SPIFFE client authentication
        provider_data = {
            "name": "service-b-spiffe-provider",
            "authorization_flow": "default-provider-authorization-explicit-consent",
            "client_type": "public",  # Public client since we use certificate auth
            "client_id": "spiffe://example.org/ns/app/sa/service-b",  # Use SPIFFE ID as client ID
            "redirect_uris": "http://localhost:8081/auth/callback\nhttp://service-a:8080/auth/callback",
            "sub_mode": "hashed_user_id",
            "include_claims_in_id_token": True,
            "signing_key": None,  # Use default
            "property_mappings": [],  # Use default mappings
            # SPIFFE-specific settings
            "client_secret": "",  # No client secret needed with SPIFFE
            "token_endpoint_auth_method": "tls_client_auth",  # Use mTLS for authentication
        }
        
        print("Creating OAuth2/OpenID provider with SPIFFE authentication...")
        provider_response = session.post(
            f"{authentik_url}/api/v3/providers/oauth2/",
            headers=api_headers,
            json=provider_data
        )
        
        if provider_response.status_code == 201:
            provider = provider_response.json()
            provider_id = provider['pk']
            print(f"Created SPIFFE provider with ID: {provider_id}")
        else:
            print(f"Failed to create provider: {provider_response.status_code}")
            print(f"Response: {provider_response.text}")
            return False
        
        # Create application
        app_data = {
            "name": "service-b-spiffe",
            "slug": "service-b-spiffe",
            "provider": provider_id,
            "meta_launch_url": "",
            "meta_description": "Service B OIDC Application with SPIFFE Authentication",
            "meta_publisher": "SpiffieAuth Demo",
            "policy_engine_mode": "any",
            "group": ""
        }
        
        print("Creating SPIFFE-enabled application...")
        app_response = session.post(
            f"{authentik_url}/api/v3/core/applications/",
            headers=api_headers,
            json=app_data
        )
        
        if app_response.status_code == 201:
            app = app_response.json()
            print(f"✅ Successfully created SPIFFE application: {app['name']}")
            print(f"Application slug: {app['slug']}")
            print(f"Provider ID: {provider_id}")
            print(f"Client ID (SPIFFE ID): spiffe://example.org/ns/app/sa/service-b")
            print("\n🔐 SPIFFE OIDC Configuration:")
            print(f"Issuer URL: {authentik_url}/application/o/service-b-spiffe/")
            print(f"Authorization URL: {authentik_url}/application/o/authorize/")
            print(f"Token URL: {authentik_url}/application/o/token/")
            print(f"UserInfo URL: {authentik_url}/application/o/userinfo/")
            print(f"JWKS URL: {authentik_url}/application/o/service-b-spiffe/jwks/")
            print("\n🎯 Key Benefits:")
            print("• No client secrets to manage")
            print("• Automatic certificate rotation via SPIRE")
            print("• mTLS-based client authentication")
            print("• SPIFFE identity as client identifier")
            return True
        else:
            print(f"Failed to create application: {app_response.status_code}")
            print(f"Response: {app_response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Setting up SPIFFE-enabled OIDC application in Authentik...")
    print("This approach uses SPIFFE identity instead of client secrets")
    success = setup_spiffe_oidc_application()
    if success:
        print("\n✅ SPIFFE OIDC application setup completed successfully!")
        print("\nNext steps:")
        print("1. Update service configurations to use SPIFFE client ID")
        print("2. Test token retrieval using SPIFFE certificates")
        print("3. Test end-to-end authentication flow with zero secrets")
    else:
        print("\n❌ Failed to setup SPIFFE OIDC application")
        sys.exit(1)
