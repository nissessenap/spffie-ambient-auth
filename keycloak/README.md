# keycloak

## Install

First, add the Bitnami Helm repository:

```shell
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
```

Then install Keycloak:

```shell
helm install keycloak bitnami/keycloak \
  --namespace keycloak \
  --create-namespace \
  --set auth.adminUser=admin \
  --set auth.adminPassword=admin \
  --set service.type=ClusterIP
```

## Access Keycloak

Port-forward to access the Keycloak admin console:

```shell
kubectl port-forward -n keycloak svc/keycloak 8080:80
```

Then access: <http://localhost:8080>

- Username: `admin`
- Password: `admin`

## Setup OIDC Client with PKCE (Public Client)

### Option 1: Using Keycloak Admin Console (GUI)

1. **Access Admin Console**: Go to <http://localhost:8080> and login
2. **Create/Select Realm**:
   - Use "master" realm or create a new one (Recommended: create "myapp" realm)
3. **Create Client**:
   - Go to `Clients` → `Create client`
   - **Client ID**: `myapp-client`
   - **Client Type**: `OpenID Connect`
   - Click `Next`
4. **Capability Config**:
   - ✅ **Client authentication**: `OFF` (This makes it a public client)
   - ✅ **Authorization**: `OFF`
   - ✅ **Authentication flow**: Enable `Standard flow`
   - ✅ **Direct access grants**: `ON` (optional)
   - Click `Next`
5. **Login Settings**:
   - **Valid redirect URIs**: `http://localhost:3000/callback` (adjust for your app)
   - **Valid post logout redirect URIs**: `http://localhost:3000`
   - **Web origins**: `http://localhost:3000`
   - Click `Save`
6. **Advanced Settings** (Important for PKCE):
   - Go to the client → `Advanced` tab
   - **Proof Key for Code Exchange Code Challenge Method**: `S256`
   - Click `Save`

### Option 2: Using kubectl and Keycloak REST API

Create the client programmatically:

```shell
# Get admin access token
ADMIN_TOKEN=$(kubectl exec -n keycloak keycloak-0 -- curl -s \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  "http://localhost:8080/realms/master/protocol/openid-connect/token" | \
  jq -r '.access_token')

# Create the OIDC client with PKCE
kubectl exec -n keycloak keycloak-0 -- curl -s \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "myapp-client",
    "name": "My Application Client",
    "description": "OIDC Public Client with PKCE",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "publicClient": true,
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "redirectUris": ["http://localhost:3000/callback"],
    "postLogoutRedirectUris": ["http://localhost:3000"],
    "webOrigins": ["http://localhost:3000"],
    "attributes": {
      "pkce.code.challenge.method": "S256"
    }
  }' \
  "http://localhost:8080/admin/realms/master/clients"
```

## Client Configuration Summary

Your OIDC client will have these settings:

- **Client ID**: `myapp-client`
- **Client Type**: Public (no client secret required)
- **PKCE**: Enabled with S256 method
- **Grant Types**: Authorization Code with PKCE
- **Redirect URI**: `http://localhost:3000/callback`

## Testing the OIDC Flow

You can test the OIDC flow with PKCE using these endpoints:

- **Authorization Endpoint**: `http://localhost:8080/realms/master/protocol/openid-connect/auth`
- **Token Endpoint**: `http://localhost:8080/realms/master/protocol/openid-connect/token`
- **UserInfo Endpoint**: `http://localhost:8080/realms/master/protocol/openid-connect/userinfo`

Example authorization URL:

```
http://localhost:8080/realms/master/protocol/openid-connect/auth?client_id=myapp-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid profile email&code_challenge=CHALLENGE&code_challenge_method=S256&state=STATE
```
