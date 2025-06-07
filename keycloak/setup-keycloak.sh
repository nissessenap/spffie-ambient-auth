#!/bin/bash
set -euo pipefail

# Get admin access token
echo "[*] Getting admin access token..."
ADMIN_TOKEN=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  "http://localhost:8080/realms/master/protocol/openid-connect/token" | \
  jq -r '.access_token')

echo "[*] Creating realm 'myapp'..."
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "myapp",
    "displayName": "My Application Realm",
    "enabled": true,
    "accessTokenLifespan": 3600,
    "ssoSessionMaxLifespan": 86400
  }' \
  "http://localhost:8080/admin/realms" || echo "Realm might already exist"

# Get admin token for the new realm
echo "[*] Getting admin token for myapp realm..."
REALM_ADMIN_TOKEN=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  "http://localhost:8080/realms/master/protocol/openid-connect/token" | \
  jq -r '.access_token')

echo "[*] Creating groups..."
# Create admin group
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "admin", "path": "/admin"}' \
  "http://localhost:8080/admin/realms/myapp/groups"

# Create editors group  
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "editors", "path": "/editors"}' \
  "http://localhost:8080/admin/realms/myapp/groups"

# Create viewers group
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "viewers", "path": "/viewers"}' \
  "http://localhost:8080/admin/realms/myapp/groups"

echo "[*] Getting group IDs..."
ADMIN_GROUP_ID=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/groups" | \
  jq -r '.[] | select(.name=="admin") | .id')

EDITORS_GROUP_ID=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/groups" | \
  jq -r '.[] | select(.name=="editors") | .id')

VIEWERS_GROUP_ID=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/groups" | \
  jq -r '.[] | select(.name=="viewers") | .id')

echo "[*] Creating users..."
# Create edvin (admin)
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "edvin",
    "email": "edvin@example.com",
    "firstName": "Edvin",
    "lastName": "Admin",
    "enabled": true,
    "credentials": [{
      "type": "password",
      "value": "password123",
      "temporary": false
    }]
  }' \
  "http://localhost:8080/admin/realms/myapp/users"

# Create alice (editor)
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com", 
    "firstName": "Alice",
    "lastName": "Editor",
    "enabled": true,
    "credentials": [{
      "type": "password",
      "value": "password123",
      "temporary": false
    }]
  }' \
  "http://localhost:8080/admin/realms/myapp/users"

# Create bob (viewer)
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "bob",
    "email": "bob@example.com",
    "firstName": "Bob", 
    "lastName": "Viewer",
    "enabled": true,
    "credentials": [{
      "type": "password",
      "value": "password123",
      "temporary": false
    }]
  }' \
  "http://localhost:8080/admin/realms/myapp/users"

echo "[*] Getting user IDs..."
EDVIN_USER_ID=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/users?username=edvin" | \
  jq -r '.[0].id')

ALICE_USER_ID=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/users?username=alice" | \
  jq -r '.[0].id')

BOB_USER_ID=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/users?username=bob" | \
  jq -r '.[0].id')

echo "[*] Adding users to groups..."
# Add edvin to admin group
kubectl exec -n keycloak keycloak-0 -- curl -s -X PUT \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/users/$EDVIN_USER_ID/groups/$ADMIN_GROUP_ID"

# Add alice to editors group  
kubectl exec -n keycloak keycloak-0 -- curl -s -X PUT \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/users/$ALICE_USER_ID/groups/$EDITORS_GROUP_ID"

# Add bob to viewers group
kubectl exec -n keycloak keycloak-0 -- curl -s -X PUT \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/myapp/users/$BOB_USER_ID/groups/$VIEWERS_GROUP_ID"

echo "[*] Creating OIDC client with PKCE..."
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $REALM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "myapp-client",
    "name": "My Application Client", 
    "description": "OIDC Public Client with PKCE",
    "enabled": true,
    "publicClient": true,
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "redirectUris": ["http://localhost:3000/callback", "http://localhost:8090/callback"],
    "postLogoutRedirectUris": ["http://localhost:3000", "http://localhost:8090"],
    "webOrigins": ["http://localhost:3000", "http://localhost:8090"],
    "attributes": {
      "pkce.code.challenge.method": "S256"
    },
    "protocolMappers": [
      {
        "name": "groups",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-group-membership-mapper",
        "consentRequired": false,
        "config": {
          "full.path": "false",
          "id.token.claim": "true",
          "access.token.claim": "true",
          "claim.name": "groups",
          "userinfo.token.claim": "true"
        }
      }
    ]
  }' \
  "http://localhost:8080/admin/realms/myapp/clients"

echo "[*] Keycloak setup complete!"
echo "    Realm: myapp"
echo "    Users: edvin (admin), alice (editors), bob (viewers)"
echo "    Client ID: myapp-client"
echo "    All passwords: password123"
