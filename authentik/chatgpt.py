import requests
import os

# === CONFIG ===
BASE_URL = "http://localhost:9000"  # 🔁 Replace with your Authentik URL
AUTHENTIK_TOKEN = os.getenv("AUTHENTIK_TOKEN")
HEADERS = {
    "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
    "Content-Type": "application/json",
}

def find_resource(url, search_key):
    """
    Find a resource by name/slug/username. Returns the first match or None.
    """
    resp = requests.get(f"{url}?search={search_key}", headers=HEADERS)
    if resp.status_code != 200:
        raise Exception(f"❌ Failed to search {url}: {resp.text}")
    results = resp.json().get("results", [])
    return results[0] if results else None

def create_or_update(url, search_key, payload, label):
    """
    If a resource with name/slug/username == search_key exists, PATCH it; otherwise, POST it.
    Returns the JSON body of the existing/newly created resource.
    """
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

# === STEP 1: Groups ===
group_ids = {}
for group_name in ["admin", "engineer"]:
    payload = {"name": group_name}
    group = create_or_update(
        f"{BASE_URL}/api/v3/core/groups/",
        group_name,
        payload,
        f"group '{group_name}'"
    )
    group_ids[group_name] = group["pk"]

# === STEP 2: Users ===
users = [
    {"username": "alice", "password": "alice123", "groups": [group_ids["admin"]]},
    {"username": "bob", "password": "bob123", "groups": [group_ids["engineer"]]},
]
for user in users:
    payload = {
        "username": user["username"],
        "name": user["username"].capitalize(),
        "password": user["password"],
        "is_active": True,
        "groups": user["groups"],
    }
    create_or_update(
        f"{BASE_URL}/api/v3/core/users/",
        user["username"],
        payload,
        f"user '{user['username']}'"
    )

# === STEP 3: Property Mapping (groups) ===
# ⇨ NOTE THE CORRECT ENDPOINT HERE:
mapping_url = f"{BASE_URL}/api/v3/propertymappings/source/oauth/"

mapping_payload = {
    "name": "user_groups",
    "expression": "[g.name for g in user.groups.all()]",
    "claim": "groups",
    "mapping_type": "oidc",
}
mapping = create_or_update(
    mapping_url,
    "user_groups",
    mapping_payload,
    "property mapping"
)
mapping_id = mapping["pk"]

# === STEP 4: OIDC Provider (PKCE Public) ===
provider_payload = {
    "name": "my-public-oidc-provider",
    "authorization_flow": "default-source-authorization-flow",
    "redirect_uris": ["http://localhost:3000/callback"],
    "client_type": "public",
    "client_id": "my-public-client-id",
    "property_mappings": [mapping_id],
}
provider = create_or_update(
    f"{BASE_URL}/api/v3/providers/oidc/",
    "my-public-oidc-provider",
    provider_payload,
    "OIDC provider"
)
provider_id = provider["pk"]

# === STEP 5: Application ===
app_payload = {
    "name": "My Test App",
    "slug": "my-test-app",
    "provider": provider_id,
    "meta_launch_url": "http://localhost:3000",
}
create_or_update(
    f"{BASE_URL}/api/v3/applications/",
    "my-test-app",
    app_payload,
    "Application"
)

print("\n🎉 All resources created or updated successfully.")
