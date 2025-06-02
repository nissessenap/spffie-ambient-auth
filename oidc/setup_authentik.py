#!/usr/bin/env python3

import requests
import json
import time
import os
from typing import Dict, List, Optional


class AuthentikSetup:
    def __init__(self, base_url: str, admin_token: str):
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token
        self.headers = {
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        }
        print(f"Initialized with base URL: {self.base_url}")

    def test_connection(self) -> bool:
        """Test the connection to Authentik API"""
        try:
            # Try to access a simple endpoint first
            response = requests.get(
                f"{self.base_url}/api/v3/core/applications/", headers=self.headers
            )
            print(f"API test response status: {response.status_code}")
            if response.status_code == 200:
                print("Successfully connected to Authentik API")
                return True
            else:
                print(f"API test failed: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"Connection test failed: {str(e)}")
            return False

    def wait_for_authentik(self, max_retries: int = 30, delay: int = 5) -> bool:
        """Wait for Authentik to be ready"""
        for i in range(max_retries):
            try:
                response = requests.get(
                    f"{self.base_url}/api/v3/core/applications/", headers=self.headers
                )
                if response.status_code == 200:
                    print("Authentik is ready!")
                    return True
            except requests.exceptions.RequestException:
                pass
            print(f"Waiting for Authentik to be ready... ({i+1}/{max_retries})")
            time.sleep(delay)
        return False

    def get_group(self, name: str) -> Optional[Dict]:
        """Get a group by name"""
        response = requests.get(
            f"{self.base_url}/api/v3/core/groups/?name={name}", headers=self.headers
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("results") and len(data["results"]) > 0:
                return data["results"][0]
        return None

    def get_user(self, username: str) -> Optional[Dict]:
        """Get a user by username"""
        response = requests.get(
            f"{self.base_url}/api/v3/core/users/?username={username}",
            headers=self.headers,
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("results") and len(data["results"]) > 0:
                return data["results"][0]
        return None

    def get_oidc_provider(self, name: str) -> Optional[Dict]:
        """Get an OIDC provider by name"""
        response = requests.get(
            f"{self.base_url}/api/v3/providers/oauth2/?name={name}",
            headers=self.headers,
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("results") and len(data["results"]) > 0:
                return data["results"][0]
        return None

    def get_authorization_flow(self) -> Optional[str]:
        """Get the default authorization flow UUID"""
        response = requests.get(
            f"{self.base_url}/api/v3/flows/instances/",
            headers=self.headers,
            params={"designation": "authorization"},
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("results") and len(data["results"]) > 0:
                return data["results"][0]["pk"]
        return None

    def get_invalidation_flow(self) -> Optional[str]:
        """Get the default invalidation flow UUID"""
        response = requests.get(
            f"{self.base_url}/api/v3/flows/instances/",
            headers=self.headers,
            params={"designation": "invalidation"},
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("results") and len(data["results"]) > 0:
                return data["results"][0]["pk"]
        return None

    def discover_api_endpoints(self) -> Dict:
        """Discover available API endpoints"""
        try:
            response = requests.get(f"{self.base_url}/api/v3/", headers=self.headers)
            print(f"API discovery response status: {response.status_code}")
            if response.status_code == 200:
                print("Successfully discovered API endpoints")
                return response.json()
            else:
                print(f"Failed to discover API endpoints: {response.text[:200]}...")
                return {}
        except Exception as e:
            print(f"Error discovering API endpoints: {str(e)}")
            return {}

    def get_builtin_property_mappings(self) -> List[str]:
        """Get the built-in OIDC property mapping UUIDs"""
        mappings = []
        required_mappings = [
            "openid",  # Matches the available 'openid' scope
            "email",  # Matches the available 'email' scope
            "profile",  # Matches the available 'profile' scope
            "offline_access",  # Using offline_access instead of groups for now
        ]

        try:
            url = f"{self.base_url}/api/v3/propertymappings/provider/scope/"
            print(f"\nTrying endpoint: {url}")

            response = requests.get(url, headers=self.headers)

            print(f"Response status: {response.status_code}")
            if response.status_code == 200:
                print("Found working endpoint!")
                data = response.json()
                results = data.get("results", [])
                print(f"Found {len(results)} total property mappings")

                if not results:
                    print("No property mappings found in response")
                    return []

                # Print all available mappings
                print("\nAvailable property mappings:")
                for mapping in results:
                    print(f"- {mapping.get('scope_name')} (pk: {mapping.get('pk')})")

                # Find the built-in mappings
                for mapping in results:
                    if mapping.get("scope_name") in required_mappings:
                        print(f"\nFound built-in mapping for {mapping['scope_name']}")
                        mappings.append(mapping["pk"])

                if len(mappings) != len(required_mappings):
                    print(
                        f"\nWarning: Found {len(mappings)} mappings, expected {len(required_mappings)}"
                    )
                    missing = set(required_mappings) - set(
                        m["scope_name"] for m in results
                    )
                    print(f"Missing mappings: {missing}")
                else:
                    print("\nFound all required mappings!")
                    return mappings
            else:
                print(
                    f"Error response: {response.text[:200]}..."
                )  # Print first 200 chars of error

        except requests.exceptions.RequestException as e:
            print(f"Request failed: {str(e)}")
        except json.JSONDecodeError as e:
            print(f"Failed to parse response as JSON: {str(e)}")
            print(
                f"Response content: {response.text[:200]}..."
            )  # Print first 200 chars of response

        print("\nFailed to get property mappings")
        return []

    def create_or_get_group(self, name: str, description: str = "") -> Optional[Dict]:
        """Create a group if it doesn't exist, or get existing one"""
        # Check if group exists
        existing_group = self.get_group(name)
        if existing_group:
            print(f"Group {name} already exists")
            return existing_group

        # Create new group
        group_data = {"name": name, "description": description}
        response = requests.post(
            f"{self.base_url}/api/v3/core/groups/",
            headers=self.headers,
            json=group_data,
        )

        if response.status_code == 201:
            print(f"Created group: {name}")
            return response.json()
        elif response.status_code == 400 and "unique" in response.text.lower():
            # If creation failed due to uniqueness constraint, try to get the group again
            existing_group = self.get_group(name)
            if existing_group:
                print(f"Group {name} already exists (retrieved after creation attempt)")
                return existing_group
            print(f"Failed to create group {name}: {response.text}")
            return None
        else:
            print(f"Failed to create group {name}: {response.text}")
            return None

    def create_or_get_user(
        self, username: str, email: str, password: str, groups: List[str] = None
    ) -> Optional[Dict]:
        """Create a user if it doesn't exist, or get existing one"""
        # Check if user exists
        existing_user = self.get_user(username)
        if existing_user:
            print(f"User {username} already exists")
            return existing_user

        # Create new user
        user_data = {
            "username": username,
            "email": email,
            "password": password,
            "name": username,
            "groups": groups or [],
        }

        response = requests.post(
            f"{self.base_url}/api/v3/core/users/",
            headers=self.headers,
            json=user_data,
        )

        if response.status_code == 201:
            print(f"Created user: {username}")
            return response.json()
        elif response.status_code == 400 and "unique" in response.text.lower():
            # If creation failed due to uniqueness constraint, try to get the user again
            existing_user = self.get_user(username)
            if existing_user:
                print(
                    f"User {username} already exists (retrieved after creation attempt)"
                )
                return existing_user
            print(f"Failed to create user {username}: {response.text}")
            return None
        else:
            print(f"Failed to create user {username}: {response.text}")
            return None

    def create_or_get_oidc_provider(
        self, name: str, client_id: str, redirect_uris: List[str]
    ) -> Optional[Dict]:
        """Create an OIDC provider if it doesn't exist, or get existing one"""
        # Check if provider exists
        existing_provider = self.get_oidc_provider(name)
        if existing_provider:
            print(f"OIDC provider {name} already exists")
            return existing_provider

        # Get required UUIDs
        auth_flow = self.get_authorization_flow()
        if not auth_flow:
            print("Failed to get authorization flow UUID")
            return None

        invalidation_flow = self.get_invalidation_flow()
        if not invalidation_flow:
            print("Failed to get invalidation flow UUID")
            return None

        property_mappings = self.get_builtin_property_mappings()
        if not property_mappings:
            print("Failed to get property mapping UUIDs")
            return None

        # Format redirect URIs with matching mode
        formatted_uris = [
            {"url": uri, "matching_mode": "regex"} for uri in redirect_uris
        ]

        # Create new provider
        provider_data = {
            "name": name,
            "client_id": client_id,
            "client_type": "public",
            "authorization_flow": auth_flow,
            "invalidation_flow": invalidation_flow,
            "property_mappings": property_mappings,
            "redirect_uris": formatted_uris,
            "include_groups": True,
            "include_group_membership": True,
            "sub_mode": "user_username",
            "issuer_mode": "per_provider",
            "jwks_sources": [],
            "access_token_validity": "minutes=5",
            "refresh_token_validity": "days=30",
        }

        response = requests.post(
            f"{self.base_url}/api/v3/providers/oauth2/",
            headers=self.headers,
            json=provider_data,
        )

        if response.status_code == 201:
            print(f"Created OIDC provider: {name}")
            return response.json()
        elif response.status_code == 400 and "unique" in response.text.lower():
            # If creation failed due to uniqueness constraint, try to get the provider again
            existing_provider = self.get_oidc_provider(name)
            if existing_provider:
                print(
                    f"OIDC provider {name} already exists (retrieved after creation attempt)"
                )
                return existing_provider
            print(f"Failed to create OIDC provider {name}: {response.text}")
            return None
        else:
            print(f"Failed to create OIDC provider {name}: {response.text}")
            return None


def main():
    # Configuration
    base_url = os.getenv("AUTHENTIK_URL", "http://localhost:9000")
    admin_token = os.getenv("AUTHENTIK_TOKEN", "test")

    print(f"Using Authentik URL: {base_url}")
    print(f"Token: {admin_token}")

    setup = AuthentikSetup(base_url, admin_token)

    # Test connection first
    if not setup.test_connection():
        print("Failed to connect to Authentik API")
        return

    # Wait for Authentik to be ready
    if not setup.wait_for_authentik():
        print("Failed to connect to Authentik")
        return

    # Create or get test groups
    admin_group = setup.create_or_get_group("admin", "Administrator group")
    user_group = setup.create_or_get_group("users", "Regular users group")

    if not admin_group or not user_group:
        print("Failed to get or create groups")
        return

    # Create or get test users
    admin_user = setup.create_or_get_user(
        username="admin",
        email="admin@example.com",
        password="admin123",  # In production, use a secure password
        groups=[admin_group["pk"]],
    )

    regular_user = setup.create_or_get_user(
        username="user",
        email="user@example.com",
        password="user123",  # In production, use a secure password
        groups=[user_group["pk"]],
    )

    # Create or get OIDC provider
    oidc_provider = setup.create_or_get_oidc_provider(
        name="service-a",
        client_id="service-a",
        redirect_uris=[
            "http://localhost:8080/callback",
            "https://service-a:8080/callback",
        ],
    )

    if oidc_provider:
        print("\nOIDC Provider Configuration:")
        print(f"Client ID: {oidc_provider['client_id']}")
        print(f"Authorization URL: {base_url}/application/o/authorize/")
        print(f"Token URL: {base_url}/application/o/token/")
        print(f"User Info URL: {base_url}/application/o/userinfo/")
        print(f"JWKS URL: {base_url}/application/o/jwks/")


if __name__ == "__main__":
    main()
