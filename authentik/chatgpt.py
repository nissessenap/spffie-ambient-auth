import requests
import os

# === CONFIG ===
BASE_URL = "http://localhost:9000"
authentik_token = os.getenv("AUTHENTIK_TOKEN")


HEADERS = {
    "Authorization": f"Bearer {authentik_token}",
    "Content-Type": "application/json",
}

def find_resource(url, search_key):
    resp = requests.get(f"{url}?search={search_key}", headers=HEADERS)
    if resp.status_code != 200:
        raise Exception(f"❌ Failed to search {url}: {resp.text}")
    results = resp.json().get("results", [])
    return results[0] if results else None

def create_or_update(url, search_key, payload, label):
    existing = find_resource(url, search_key)
    if existing:
        resource_id = existing["pk"]
        resp = requests.patch(f"{url}{resource_id}/", headers=HEADERS, json=payload)
        if resp.status_code not in (200, 204):
            raise Exception(f"❌ Failed to update {label}: {resp.text}")
        print(f"🛠️ Updated {label}")
        return existing
    else:
        resp = requests.post(url, headers=HEADERS, json=payload)
        if resp.status_code not in (200, 201):
            raise Exception(f"❌ Failed to create {label}: {resp.text}")
        print(f"✅ Created {label}")
        return resp.json()

# === Step 1: Groups ===
group_ids = {}
for group in ["admin", "engineer"]:
    result = create_or_update(
        f"{BASE_URL}/api/v3/core/groups/",
        group,
        {"name": group},
        f"group '{group}'"
    )
    group_ids[group] = result["pk"]

# === Step 2: Users ===
users = [
    {"username": "alice", "password": "alice123", "groups": [group_ids["admin"]]},
    {"username": "bob", "password": "bob123", "groups": [group_ids["engineer"]]},
]
for user in users:
    create_or_update(
        f"{BASE_URL}/api/v3/core/users/",
        user["username"],
        {
            "username": user["username"],
            "name": user["username"].capitalize(),
            "password": user["password"],
            "is_active": True,
            "groups": user["groups"],
        },
        f"user '{user['username']}'"
    )

# === Step 3: Property Mapping (OAuth2 group claim) ===
mapping = create_or_update(
    f"{BASE_URL}/api/v3/propertymappings/source/oauth/",
    "user_groups",
    {
        "name": "user_groups",
        "expression": "[g.name for g in user.groups.all()]",
        "claim": "groups",
        "mapping_type": "oidc",
    },
    "property mapping"
)
mapping_id = mapping["pk"]

# === Step 4: Find required flows ===
def get_flow_by_slug(slug):
    flow = find_resource(f"{BASE_URL}/api/v3/flows/instances/", slug)
    if not flow:
        raise Exception(f"❌ Could not find flow with slug '{slug}'")
    return flow["pk"]

auth_flow_id = get_flow_by_slug("default-source-authentication-flow")
invalidation_flow_id = get_flow_by_slug("default-invalidation-flow")

# === Step 5: Create OIDC Provider ===
provider = create_or_update(
    f"{BASE_URL}/api/v3/providers/oauth2/",
    "my-public-oidc-provider",
    {
        "name": "my-public-oidc-provider",
        "authorization_flow": auth_flow_id,
        "invalidation_flow": invalidation_flow_id,
        "client_type": "public",
        "redirect_uris": [{"matching_mode": "strict", "url": "http://localhost:3000/callback"}],
        "property_mappings": [mapping_id],
        "sub_mode": "user_username",
        "issuer_mode": "inherit",
    },
    "OIDC provider"
)
provider_id = provider["pk"]

# === Step 6: Create Application ===
create_or_update(
    f"{BASE_URL}/api/v3/applications/",
    "my-test-app",
    {
        "name": "My Test App",
        "slug": "my-test-app",
        "provider": provider_id,
        "meta_launch_url": "http://localhost:3000",
    },
    "application"
)

print("\n🎉 All resources created or updated successfully.")
