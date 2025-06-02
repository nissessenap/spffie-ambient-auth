#!/usr/bin/env python3
"""
Clean setup script for OIDC Authorization Code Flow with PKCE
Creates a new OAuth2/OIDC provider in Authentik specifically designed for:
- Authorization Code Flow with PKCE (RFC 7636)
- Public clients (no client secrets)
- SPIFFE service authentication
"""

import requests
import os
import json
import sys


def setup_pkce_oidc_provider():
    """
    Create a fresh OIDC provider configured for Authorization Code Flow with PKCE
    """
    authentik_url = "http://localhost:9000"
    authentik_token = os.getenv("AUTHENTIK_TOKEN")
    
    if not authentik_token:
        print("[✗] AUTHENTIK_TOKEN environment variable not set")
        print("Please set it with: export AUTHENTIK_TOKEN=your_token_here")
        return False
    
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {authentik_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    })
    
    print(f"[+] Setting up PKCE OIDC provider...")
    
    try:
        # Test API connection
        response = session.get(f"{authentik_url}/api/v3/core/users/")
        if response.status_code != 200:
            print(f"[✗] API connection failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
        
        print("[✓] Connected to Authentik API")
        
        # Get required flows
        flows_response = session.get(f"{authentik_url}/api/v3/flows/instances/")
        if flows_response.status_code != 200:
            print(f"[✗] Failed to get flows: {flows_response.status_code}")
            return False
            
        flows = flows_response.json()
        
        auth_flow_uuid = None
        invalidation_flow_uuid = None
        
        for flow in flows.get('results', []):
            slug = flow.get('slug', '').lower()
            if 'authorization' in slug and 'implicit' not in slug:
                auth_flow_uuid = flow['pk']
                print(f"[+] Found authorization flow: {flow['name']} ({auth_flow_uuid})")
            elif 'invalidation' in slug:
                invalidation_flow_uuid = flow['pk']
                print(f"[+] Found invalidation flow: {flow['name']} ({invalidation_flow_uuid})")
        
        if not auth_flow_uuid or not invalidation_flow_uuid:
            print("[✗] Required flows not found")
            return False
        
        # Create a unique provider name
        provider_name = "spiffe-pkce-provider"
        client_id = "spiffe-pkce-client"
        
        # Check if provider already exists
        providers_response = session.get(f"{authentik_url}/api/v3/providers/oauth2/")
        if providers_response.status_code != 200:
            print(f"[✗] Failed to get providers: {providers_response.status_code}")
            return False
            
        providers = providers_response.json()
        
        # Delete existing provider if it exists
        for provider in providers.get('results', []):
            if provider.get('name') == provider_name:
                print(f"[+] Deleting existing provider: {provider_name}")
                delete_response = session.delete(f"{authentik_url}/api/v3/providers/oauth2/{provider['pk']}/")
                if delete_response.status_code == 204:
                    print("[✓] Existing provider deleted")
                else:
                    print(f"[!] Warning: Failed to delete provider: {delete_response.status_code}")
                break
        
        # Handle property mappings for groups - use a simpler approach
        # In Authentik, built-in scope mappings are often sufficient
        print("[+] Configuring OIDC scopes and claims...")
        
        # We'll rely on Authentik's built-in scope mappings and ensure the provider
        # includes claims in both access tokens and ID tokens
        scope_mapping_ids = []
        
        # Check if there are any existing property mappings we can use
        try:
            # Try to get any existing OAuth2 property mappings
            mappings_response = session.get(f"{authentik_url}/api/v3/propertymappings/oauth2/")
            if mappings_response.status_code == 200:
                mappings = mappings_response.json()
                for mapping in mappings.get('results', []):
                    scope_mapping_ids.append(mapping['pk'])
                    print(f"[+] Found property mapping: {mapping.get('name', 'Unknown')}")
            else:
                print(f"[+] OAuth2 property mappings endpoint returned {mappings_response.status_code}")
        except Exception as e:
            print(f"[+] Property mappings check skipped: {e}")
        
        print(f"[+] Will configure provider with {len(scope_mapping_ids)} property mappings")
        
        # Get available RSA signing keys for JWT signing (required for RS256)
        print("[+] Looking for RSA signing keys...")
        keys_response = session.get(f"{authentik_url}/api/v3/crypto/certificatekeypairs/")
        signing_key_id = None
        
        if keys_response.status_code == 200:
            keys = keys_response.json()
            for key in keys.get('results', []):
                key_name = key.get('name', '').lower()
                # Look for RSA keys that can be used for signing
                if 'rsa' in key_name or 'signing' in key_name or 'authentik' in key_name:
                    signing_key_id = key['pk']
                    print(f"[+] Found RSA signing key: {key['name']} (ID: {signing_key_id})")
                    break
            
            if not signing_key_id and keys.get('results'):
                # If no specifically named RSA key, use the first available key
                signing_key_id = keys['results'][0]['pk']
                print(f"[+] Using default signing key: {keys['results'][0]['name']} (ID: {signing_key_id})")
        else:
            print(f"[!] Warning: Could not get signing keys: {keys_response.status_code}")
            print("[+] Will use default signing (may cause HS256 vs RS256 issues)")
        
        if signing_key_id:
            print(f"[✓] Will use RSA signing key ID: {signing_key_id}")
        else:
            print("[!] Warning: No RSA signing key found - tokens may use HS256 instead of RS256")
        
        # Create new PKCE-enabled OAuth2 provider
        provider_data = {
            "name": provider_name,
            "authorization_flow": auth_flow_uuid,
            "invalidation_flow": invalidation_flow_uuid,
            "client_type": "public",  # Public client - no client secret required
            "client_id": client_id,
            "redirect_uris": [
                {
                    "matching_mode": "strict",
                    "url": "http://localhost:8081/callback"
                },
                {
                    "matching_mode": "strict", 
                    "url": "https://service-a:8080/callback"
                },
                {
                    "matching_mode": "strict",
                    "url": "http://localhost:3000/callback"
                }
            ],
            "sub_mode": "hashed_user_id",
            "include_claims_in_id_token": True,
            "issuer_mode": "per_provider",
            "access_code_validity": "minutes=10",  # Authorization codes valid for 10 minutes
            "access_token_validity": "hours=1",    # Access tokens valid for 1 hour
            "refresh_token_validity": "days=30",   # Refresh tokens valid for 30 days
            # Enable groups in tokens - these settings help ensure group claims are included
            "include_claims_in_id_token": True,
        }
        
        # Add RSA signing key if found (this forces RS256 instead of HS256)
        if signing_key_id:
            provider_data["signing_key"] = signing_key_id
        
        # Add scope mappings if we found any
        if scope_mapping_ids:
            provider_data["property_mappings"] = scope_mapping_ids
        
        print("[+] Creating PKCE OAuth2 provider...")
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
        app_name = "spiffe-pkce-app"
        app_slug = "spiffe-pkce-app-v2"  # Use unique slug to avoid conflicts
        
        # Check if application already exists
        apps_response = session.get(f"{authentik_url}/api/v3/core/applications/")
        if apps_response.status_code != 200:
            print(f"[✗] Failed to get applications: {apps_response.status_code}")
            return False
            
        apps = apps_response.json()
        
        # Delete existing application if it exists
        for app in apps.get('results', []):
            if app.get('name') == app_name or app.get('slug') == app_slug:
                print(f"[+] Deleting existing application: {app_name}")
                delete_response = session.delete(f"{authentik_url}/api/v3/core/applications/{app['pk']}/")
                if delete_response.status_code == 204:
                    print("[✓] Existing application deleted")
                else:
                    print(f"[!] Warning: Failed to delete application: {delete_response.status_code}")
                break
        
        app_data = {
            "name": app_name,
            "slug": app_slug,
            "provider": provider_id,
            "meta_description": "SPIFFE services using PKCE authentication",
            "meta_publisher": "SPIRE/SPIFFE",
            "policy_engine_mode": "any"
        }
        
        print("[+] Creating PKCE application...")
        app_response = session.post(
            f"{authentik_url}/api/v3/core/applications/",
            json=app_data
        )
        
        if app_response.status_code == 201:
            app = app_response.json()
            print(f"[✓] Successfully created application: {app['name']}")
            
            # Print configuration details
            print("\n" + "="*60)
            print("🔑 PKCE OIDC Configuration Summary")
            print("="*60)
            print(f"Provider Name: {provider_name}")
            print(f"Application Name: {app_name}")
            print(f"Client ID: {client_id}")
            print(f"Client Type: public (no client secret)")
            print("")
            print("🌐 OIDC Endpoints:")
            print(f"Issuer URL: {authentik_url}/application/o/{app_slug}/")
            print(f"Authorization URL: {authentik_url}/application/o/authorize/")
            print(f"Token URL: {authentik_url}/application/o/token/")
            print(f"UserInfo URL: {authentik_url}/application/o/userinfo/")
            print(f"JWKS URL: {authentik_url}/application/o/{app_slug}/jwks/")
            print("")
            print("🔄 Redirect URIs:")
            for uri_obj in provider_data["redirect_uris"]:
                print(f"  - {uri_obj['url']}")
            print("")
            print("⚙️  Flow Configuration:")
            print("  - Grant Type: authorization_code")
            print("  - PKCE: Required (code_challenge_method=S256)")
            print("  - Client Authentication: None (public client)")
            print("  - Scopes: openid profile email groups offline_access")
            print("  - Scope mappings configured for user profile data")
            print("")
            print("📋 Usage in service-a:")
            print(f"  - Update getOIDCConfig() to use client_id: '{client_id}'")
            print(f"  - Update issuer URL to: '{authentik_url}/application/o/{app_slug}/'")
            print("  - Ensure scopes include: 'openid profile email groups offline_access'")
            print("")
            print("✅ Ready for Authorization Code Flow with PKCE!")
            return True
        else:
            print(f"[✗] Failed to create application: {app_response.status_code}")
            print(f"Response: {app_response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[✗] Request failed: {e}")
        return False


if __name__ == "__main__":
    print("🚀 Setting up Authorization Code Flow with PKCE")
    print("=" * 50)
    print("This creates a clean OIDC provider configured for:")
    print("- Authorization Code Flow with PKCE (RFC 7636)")
    print("- Public clients (no client secrets)")
    print("- SPIFFE service integration")
    print("=" * 50)
    
    success = setup_pkce_oidc_provider()
    if success:
        print("\n✅ PKCE OIDC setup completed successfully!")
        print("\n📝 Next steps:")
        print("1. Update service-a configuration with new client_id")
        print("2. Test the authorization flow: /login endpoint")
        print("3. Verify token validation in service-b")
        print("4. Test end-to-end document access with user authentication")
    else:
        print("\n❌ Failed to setup PKCE OIDC provider")
        sys.exit(1)
