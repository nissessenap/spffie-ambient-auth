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

        # Create new provider
        provider_data = {
            "name": name,
            "client_id": client_id,
            "client_type": "public",
            "authorization_flow": "default-provider-authorization-implicit-consent",
            "property_mappings": [
                "goauthentik.io/providers/oauth2/scope-openid",
                "goauthentik.io/providers/oauth2/scope-email",
                "goauthentik.io/providers/oauth2/scope-profile",
                "goauthentik.io/providers/oauth2/scope-groups",
            ],
            "redirect_uris": redirect_uris,
            "include_groups": True,
            "include_group_membership": True,
        }

        response = requests.post(
            f"{self.base_url}/api/v3/providers/oauth2/",
            headers=self.headers,
            json=provider_data,
        )

        if response.status_code == 201:
            print(f"Created OIDC provider: {name}")
            return response.json()
        else:
            print(f"Failed to create OIDC provider {name}: {response.text}")
            return None


def main():
    # Configuration
    base_url = os.getenv("AUTHENTIK_URL", "http://localhost:9000")
    admin_token = os.getenv(
        "AUTHENTIK_TOKEN", "test"
    )  # Use the bootstrap token from values.yaml

    print(f"token: {admin_token}")
    setup = AuthentikSetup(base_url, admin_token)

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
