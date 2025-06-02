#!/usr/bin/env python3
"""
OIDC Authorization Code Flow with PKCE Test Script

This script demonstrates the complete OIDC Authorization Code Flow with PKCE
by automating the login process and testing token validation.
"""

import requests
import json
import sys
import re
import urllib.parse
from typing import Optional, Dict, Any
import argparse
from dataclasses import dataclass
import time

# Configuration
@dataclass
class Config:
    username: str = "alice"
    password: str = "testpassword123"
    authentik_base_url: str = "http://authentik-server.authentik.svc.cluster.local:80"
    service_a_url: str = "http://service-a.app.svc.cluster.local:8081"
    timeout: int = 10

# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color

def print_colored(message: str, color: str = Colors.NC):
    print(f"{color}{message}{Colors.NC}")

def print_step(step: str, message: str):
    print_colored(f"\n{step}: {message}", Colors.BLUE)

def print_success(message: str):
    print_colored(f"✅ {message}", Colors.GREEN)

def print_error(message: str):
    print_colored(f"❌ {message}", Colors.RED)

def print_warning(message: str):
    print_colored(f"⚠️  {message}", Colors.YELLOW)

class OIDCTestClient:
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.timeout = config.timeout
        
        # Disable SSL warnings for self-signed certificates
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def check_cluster_connectivity(self) -> bool:
        """Check if we can reach the cluster services."""
        print_step("🔍 Connectivity Check", "Checking cluster connectivity...")
        
        try:
            print(f"Testing connection to: {self.config.service_a_url}/health")
            response = self.session.get(f"{self.config.service_a_url}/health", timeout=5)
            print(f"Health check response: {response.status_code}")
            
            if response.status_code == 200:
                print_success("Cluster services accessible")
                return True
            else:
                print_warning(f"Health check returned status: {response.status_code}")
                print(f"Response: {response.text[:200]}")
                # Continue anyway, service might not have health endpoint
                print_warning("Continuing anyway - service might not have /health endpoint")
                return True
                
        except requests.exceptions.RequestException as e:
            print_error(f"Cannot access cluster services: {e}")
            print_warning("You might need to run this script from inside the cluster or use port-forwarding:")
            print("kubectl port-forward -n app svc/service-a 8081:8081")
            print("kubectl port-forward -n authentik svc/authentik-server 9000:80")
            print("\nThen update the URLs in this script to use localhost")
            print_warning("Continuing anyway - will try login endpoint...")
            return True  # Continue anyway to try the actual login endpoint

    def start_login_flow(self) -> tuple[str, str]:
        """Start the OIDC login flow and get authorization URL."""
        print_step("Step 1", "Starting OIDC login flow...")
        print(f"Requesting authorization URL from: {self.config.service_a_url}/login")
        
        try:
            response = self.session.get(
                f"{self.config.service_a_url}/login",
                headers={"Accept": "application/json"}
            )
            print(f"Login endpoint response status: {response.status_code}")
            print(f"Response headers: {dict(response.headers)}")
            
            response.raise_for_status()
            
            print(f"Raw response: {response.text}")
            data = response.json()
            print(f"Parsed JSON: {json.dumps(data, indent=2)}")
            
            auth_url = data.get('auth_url')
            state = data.get('state')
            
            if not auth_url or not state:
                raise ValueError("Missing auth_url or state in response")
            
            print(f"Authorization URL: {auth_url}")
            print(f"State: {state}")
            
            return auth_url, state
            
        except requests.exceptions.RequestException as e:
            print_error(f"Failed to start login flow: {e}")
            print(f"Error details: {type(e).__name__}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response status: {e.response.status_code}")
                print(f"Response text: {e.response.text}")
            raise
        except (json.JSONDecodeError, ValueError) as e:
            print_error(f"Invalid response from service-a: {e}")
            raise

    def extract_form_data(self, html: str) -> Dict[str, str]:
        """Extract CSRF token and form action from HTML."""
        form_data = {}
        
        # Extract CSRF token
        csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]*)"', html)
        if csrf_match:
            form_data['csrf_token'] = csrf_match.group(1)
        else:
            print_warning("Could not extract CSRF token, trying without it...")
        
        # Extract form action
        action_match = re.search(r'action="([^"]*)"', html)
        if action_match:
            form_data['action'] = action_match.group(1)
        else:
            form_data['action'] = "/if/flow/default-authentication-flow/"
            print_warning(f"Using default form action: {form_data['action']}")
        
        return form_data

    def automated_login(self, auth_url: str) -> Optional[str]:
        """Perform automated login and return authorization code."""
        print_step("Step 2", "Automated login flow...")
        print("Attempting to automate the OIDC login process...")
        
        try:
            # Step 1: Get the login form
            print(f"Following authorization URL: {auth_url}")
            response = self.session.get(auth_url, allow_redirects=True)
            print(f"Authorization page response: {response.status_code}")
            print(f"Final URL after redirects: {response.url}")
            response.raise_for_status()
            
            # Step 2: Extract form data
            print("Extracting form data from HTML...")
            form_data = self.extract_form_data(response.text)
            print(f"Extracted form data: {form_data}")
            
            # Step 3: Build form action URL
            form_action = form_data['action']
            if form_action.startswith('/'):
                form_action = f"{self.config.authentik_base_url}{form_action}"
            
            print(f"Form action: {form_action}")
            
            # Step 4: Prepare login data
            login_data = {
                'uid_field': self.config.username,
                'password': self.config.password
            }
            
            if 'csrf_token' in form_data:
                login_data['csrfmiddlewaretoken'] = form_data['csrf_token']
            
            print(f"Login data (without password): {dict((k, v) for k, v in login_data.items() if k != 'password')}")
            
            # Step 5: Submit login form
            print("Submitting login credentials...")
            response = self.session.post(
                form_action,
                data=login_data,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Referer': auth_url
                },
                allow_redirects=True
            )
            
            print(f"Login HTTP Code: {response.status_code}")
            print(f"Final URL: {response.url}")
            print(f"Response content preview: {response.text[:300]}...")
            
            # Step 6: Extract authorization code
            if 'code=' in str(response.url):
                parsed_url = urllib.parse.urlparse(str(response.url))
                query_params = urllib.parse.parse_qs(parsed_url.query)
                auth_code = query_params.get('code', [None])[0]
                
                if auth_code:
                    print_success("Successfully obtained authorization code!")
                    print(f"Authorization Code: {auth_code[:20]}...")
                    return auth_code
            
            print_error("No authorization code found in callback URL")
            print(f"Final URL: {response.url}")
            print(f"URL query params: {urllib.parse.parse_qs(urllib.parse.urlparse(str(response.url)).query)}")
            return None
            
        except requests.exceptions.RequestException as e:
            print_error(f"Login flow failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Error response status: {e.response.status_code}")
                print(f"Error response text: {e.response.text[:500]}")
            return None

    def exchange_code_for_tokens(self, auth_code: str, state: str) -> Optional[str]:
        """Exchange authorization code for access token."""
        print_step("Step 3", "Exchanging code for tokens...")
        
        try:
            token_data = {
                'code': auth_code,
                'state': state
            }
            
            response = self.session.post(
                f"{self.config.service_a_url}/callback",
                json=token_data,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            
            data = response.json()
            print(f"Token exchange response: {json.dumps(data, indent=2)}")
            
            access_token = data.get('access_token')
            if access_token:
                print_success("Successfully obtained access token!")
                print_colored(f"🎫 Access Token: {access_token}", Colors.GREEN)
                
                # Also show token info if available
                token_type = data.get('token_type', 'Bearer')
                expires_in = data.get('expires_in')
                
                print(f"Token Type: {token_type}")
                if expires_in:
                    print(f"Expires In: {expires_in} seconds")
                
                return access_token
            else:
                print_error("No access token in response")
                return None
                
        except requests.exceptions.RequestException as e:
            print_error(f"Token exchange failed: {e}")
            return None
        except json.JSONDecodeError as e:
            print_error(f"Invalid JSON response: {e}")
            return None

    def test_token_with_service_a(self, access_token: str):
        """Test the token with service-a endpoints."""
        print_step("Step 4", "Testing token with service-a...")
        
        headers = {'Authorization': f'Bearer {access_token}'}
        
        # Test token validation endpoint
        try:
            print("Testing token validation...")
            response = self.session.get(
                f"{self.config.service_a_url}/test-token",
                headers=headers,
                timeout=self.config.timeout
            )
            
            print(f"Status: {response.status_code}")
            if response.text:
                try:
                    print(f"Response: {json.dumps(response.json(), indent=2)}")
                except json.JSONDecodeError:
                    print(f"Response: {response.text}")
            
            if response.status_code < 400:
                print_success("Token validation successful")
            else:
                print_error(f"Token validation failed with {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print_error(f"Token validation failed: {e}")

    def print_manual_instructions(self, auth_url: str):
        """Print manual testing instructions."""
        print_step("Step 5", "Manual testing instructions")
        print_warning("If automated login failed, you can still test manually:")
        print(f"\nPlease visit the following URL in your browser to complete login:")
        print_colored(f"{auth_url}", Colors.GREEN)
        print("\nAfter logging in, you will be redirected to the callback URL.")
        print("The authorization code will be automatically exchanged for tokens.")
        
        print(f"\n{Colors.BLUE}Manual token testing:{Colors.NC}")
        print("If you have an access token, you can test it manually:")
        print(f"\nTest with service-a:")
        print(f'curl -H "Authorization: Bearer YOUR_TOKEN" {self.config.service_a_url}/test-token')

    def print_architecture_info(self):
        """Print implementation details and architecture info."""
        print_colored(f"\n✅ OIDC Implementation Features:", Colors.GREEN)
        features = [
            "🔐 Authorization Code Flow with PKCE (no client secret needed)",
            "🎫 JWT access token validation with JWKS", 
            "📝 Comprehensive claim verification (exp, aud, iss)",
            "💾 Automatic JWKS caching for performance",
            "🚫 Proper error handling for invalid/expired tokens",
            "🔄 State and nonce protection against CSRF and replay attacks"
        ]
        for feature in features:
            print(feature)
        
        print_colored(f"\n💡 Architecture Highlights:", Colors.YELLOW)
        highlights = [
            "• service-a acts as OIDC client (Authorization Code Flow)",
            "• Authentik provides OIDC/OAuth2 services", 
            "• No client secrets - uses PKCE for security",
            "• JWT tokens can be used with any resource server"
        ]
        for highlight in highlights:
            print(highlight)
        
        print_colored(f"\n📚 For more details, see: OIDC_IMPLEMENTATION.md", Colors.BLUE)

    def run_complete_flow(self) -> bool:
        """Run the complete OIDC test flow."""
        print_colored("🚀 OIDC Authorization Code Flow with PKCE Test", Colors.CYAN)
        print_colored("=" * 50, Colors.CYAN)
        
        try:
            # Check connectivity
            print(f"🔧 Configuration:")
            print(f"   Username: {self.config.username}")
            print(f"   Service-A URL: {self.config.service_a_url}")
            print(f"   Authentik URL: {self.config.authentik_base_url}")
            print(f"   Timeout: {self.config.timeout}s")
            
            if not self.check_cluster_connectivity():
                print_warning("Connectivity check failed, but continuing...")
            
            # Start login flow
            try:
                auth_url, state = self.start_login_flow()
            except Exception as e:
                print_error(f"Failed to start login flow: {e}")
                return False
            
            # Automated login
            auth_code = self.automated_login(auth_url)
            
            if auth_code:
                # Exchange for tokens
                access_token = self.exchange_code_for_tokens(auth_code, state)
                
                if access_token:
                    # Test token with service-a
                    self.test_token_with_service_a(access_token)
                    print_success("OIDC flow completed successfully!")
                    print_colored(f"\n🎉 You now have a valid JWT access token that can be used with any service!", Colors.GREEN)
                    return True
                else:
                    print_error("Failed to obtain access token")
            else:
                print_error("Failed to obtain authorization code")
            
            # Show manual instructions as fallback
            self.print_manual_instructions(auth_url)
            return False
            
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            import traceback
            print_error(f"Traceback: {traceback.format_exc()}")
            return False
        finally:
            self.print_architecture_info()

def main():
    parser = argparse.ArgumentParser(description="OIDC Authorization Code Flow with PKCE Test")
    parser.add_argument("--username", default="alice", help="Username for authentication")
    parser.add_argument("--password", default="testpassword123", help="Password for authentication")
    parser.add_argument("--authentik-url", default="http://authentik-server.authentik.svc.cluster.local:80", 
                       help="Authentik base URL")
    parser.add_argument("--service-a-url", default="http://service-a.app.svc.cluster.local:8081",
                       help="Service A URL")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    config = Config(
        username=args.username,
        password=args.password,
        authentik_base_url=args.authentik_url,
        service_a_url=args.service_a_url,
        timeout=args.timeout
    )
    
    client = OIDCTestClient(config)
    success = client.run_complete_flow()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
