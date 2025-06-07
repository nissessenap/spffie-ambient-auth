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

### Option 2: Using kubectl and Keycloak REST API (Recommended for PoC)

Complete setup script for Keycloak configuration:

See [setup-keycloak.sh](setup-keycloak.sh)

## Client Configuration Summary

Your OIDC client will have these settings:

- **Realm**: `myapp` (instead of master for better isolation)
- **Client ID**: `myapp-client`
- **Client Type**: Public (no client secret required)
- **PKCE**: Enabled with S256 method
- **Grant Types**: Authorization Code with PKCE
- **Redirect URIs**: `http://localhost:3000/callback`, `http://localhost:8090/callback`
- **Groups Claim**: Included in JWT tokens for authorization

## Test Users and Groups

| Username | Password    | Group   | Permissions |
|----------|-------------|---------|-------------|
| edvin    | password123 | admin   | Full access (view, edit, delete) |
| alice    | password123 | editors | View and edit documents |
| bob      | password123 | viewers | View documents only |

## Testing the OIDC Flow

You can test the OIDC flow with PKCE using these endpoints:

- **Authorization Endpoint**: `http://localhost:8080/realms/myapp/protocol/openid-connect/auth`
- **Token Endpoint**: `http://localhost:8080/realms/myapp/protocol/openid-connect/token`
- **UserInfo Endpoint**: `http://localhost:8080/realms/myapp/protocol/openid-connect/userinfo`
- **JWKS Endpoint**: `http://localhost:8080/realms/myapp/protocol/openid-connect/certs`

Example authorization URL:

```
http://localhost:8080/realms/myapp/protocol/openid-connect/auth?client_id=myapp-client&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid profile email groups&code_challenge=CHALLENGE&code_challenge_method=S256&state=STATE
```

## JWT Token Structure

The JWT tokens will include:

```json
{
  "sub": "edvin",
  "email": "edvin@example.com", 
  "given_name": "Edvin",
  "family_name": "Admin",
  "groups": ["admin"],
  "iss": "http://localhost:8080/realms/myapp",
  "aud": "myapp-client"
}
```

## Integration with Services

**Service-A (Frontend)**:

- Port-forward: `kubectl port-forward -n app svc/service-a 8090:8080`
- Handles OIDC login flow
- Forwards JWT tokens to Service-B

**Service-B (Authorization)**:

- Validates JWT against Keycloak JWKS endpoint
- Extracts `sub` (username) and `groups` claims
- Maps to SpiceDB: `keycloak:user:{sub}` in `keycloak:group:{group}`
- Checks permissions via SpiceDB

**Security Flow**:

1. User authenticates with Keycloak via Service-A
2. Service-A forwards JWT to Service-B over SPIFFE mTLS
3. Service-B validates JWT signature against Keycloak
4. Service-B authorizes via SpiceDB using JWT claims
