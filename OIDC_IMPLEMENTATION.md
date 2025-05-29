# OIDC Implementation Guide

This document explains the OIDC (OpenID Connect) implementation for secure authentication between services using SPIFFE/SPIRE and Authentik.

## Overview

We've implemented a complete OIDC solution that addresses both tasks from the prompt:

### 🎯 Task 1: Authorization Code Flow with PKCE (service-a)

- **No client secret required** - Uses PKCE for security
- **Redirects to Authentik login page** - Proper OAuth2 Authorization Code Flow
- **Token exchange** - Exchanges authorization code for access/ID tokens
- **JWT validation** - Validates returned tokens

### 🎯 Task 2: Backend Token Validation (service-b)

- **Bearer token support** - Accepts `Authorization: Bearer <token>` headers
- **JWT validation without client secret** - Uses JWKS for signature verification
- **JWKS caching** - Automatic caching via OIDC library
- **Comprehensive claim verification** - Validates exp, aud, iss, etc.
- **Error handling** - Proper handling of invalid/expired tokens

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  service-a  │    │  Authentik  │    │  service-b  │
│   (Client)  │    │   (OIDC)    │    │  (Resource) │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       │ 1. Start login    │                   │
       ├──────────────────►│                   │
       │                   │                   │
       │ 2. Auth URL       │                   │
       │◄──────────────────┤                   │
       │                   │                   │
       │ 3. User login     │                   │
       ├──────────────────►│                   │
       │                   │                   │
       │ 4. Auth code      │                   │
       │◄──────────────────┤                   │
       │                   │                   │
       │ 5. Exchange code  │                   │
       ├──────────────────►│                   │
       │                   │                   │
       │ 6. Access token   │                   │
       │◄──────────────────┤                   │
       │                   │                   │
       │ 7. API call with token                │
       ├───────────────────────────────────────►│
       │                   │                   │
       │                   │ 8. Validate token │
       │                   │◄──────────────────┤
       │                   │                   │
       │                   │ 9. User info      │
       │                   ├──────────────────►│
       │                   │                   │
       │ 10. API response  │                   │
       │◄───────────────────────────────────────┤
```

## Key Components

### 1. PKCE Implementation (service-a)

**File**: `service-a/main.go`

Key functions:

- `generatePKCE()` - Generates code verifier and challenge
- `loginFlowHandler()` - Initiates OAuth2 flow
- `callbackHandler()` - Handles authorization code callback
- `exchangeCodeForTokens()` - Exchanges code for tokens

**Security Features**:

- SHA256-based code challenge
- State parameter for CSRF protection
- Nonce for replay protection
- Secure random string generation

### 2. JWT Token Validation (service-b)

**File**: `oidc/validator.go`

Key functions:

- `ValidateAccessToken()` - Main token validation with JWKS
- `NewTokenValidator()` - Creates validator with SPIFFE mTLS
- `ExtractBearerToken()` - Extracts tokens from headers

**Validation Features**:

- JWKS-based signature verification
- Automatic JWKS caching (1-hour TTL)
- Standard claim validation (exp, aud, iss)
- SPIFFE identity-based client authentication
- Comprehensive error handling

## API Endpoints

### Service-A (Client)

#### 1. Start OIDC Login Flow

```bash
GET /login
Accept: application/json
```

**Response**:

```json
{
  "auth_url": "http://localhost:9000/application/o/authorize/?response_type=code&client_id=spiffe%3A%2F%2Fexample.org%2Fspiffe-services&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fcallback&scope=openid+profile+email+groups&state=abc123&nonce=xyz789&code_challenge=def456&code_challenge_method=S256",
  "state": "abc123",
  "message": "Visit the auth_url to complete login, then return to /callback with the authorization code"
}
```

#### 2. OAuth2 Callback

```bash
GET /callback?code=AUTH_CODE&state=STATE
```

**Response**:

```json
{
  "message": "Login successful!",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 300,
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."
}
```

#### 3. Test Token

```bash
GET /test-token?token=ACCESS_TOKEN
# OR
GET /test-token
Authorization: Bearer ACCESS_TOKEN
```

### Service-B (Resource Server)

#### 1. Hello Endpoint (with optional auth)

```bash
GET /hello
Authorization: Bearer ACCESS_TOKEN
```

#### 2. Document Operations (requires auth)

```bash
GET /documents/doc1      # View document
PUT /documents/doc1      # Edit document  
DELETE /documents/doc1   # Delete document
Authorization: Bearer ACCESS_TOKEN
```

## Testing the Implementation

### 1. Setup

First, ensure your environment is running:

```bash
# Start the infrastructure
./setup-kind-infra.sh

# Setup Authentik OIDC
python3 setup-authentik-spiffe-oidc-proper.py
```

### 2. Test Authorization Code Flow with PKCE

```bash
# Step 1: Start login flow
curl -H "Accept: application/json" http://localhost:8081/login

# This returns an auth_url - visit it in browser or use the URL
# After login, you'll be redirected to /callback with the authorization code

# Step 2: The callback automatically exchanges the code for tokens
# You'll receive an access_token in the response
```

### 3. Test Access Token Validation

```bash
# Use the access token from step 2
ACCESS_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."

# Test with service-b hello endpoint
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     --cert client.crt --key client.key --cacert ca.crt \
     https://service-b:8080/hello

# Test document operations
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     --cert client.crt --key client.key --cacert ca.crt \
     https://service-b:8080/documents/doc1
```

### 4. Test via service-a proxy

```bash
# Test token through service-a
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8081/test-token
```

## Error Handling

The implementation includes comprehensive error handling:

### Common Errors and Solutions

1. **"Token has expired"**
   - Solution: Request a new token via the login flow

2. **"Invalid signature"**  
   - Solution: Check JWKS endpoint availability
   - The system automatically retries JWKS fetching

3. **"Invalid audience"**
   - Solution: Verify client_id configuration matches

4. **"User authentication required"**
   - Solution: Include valid Bearer token in Authorization header

5. **"Session expired"**
   - Solution: Restart the login flow (PKCE sessions expire after 10 minutes)

## Security Features

### PKCE (Proof Key for Code Exchange)

- **Code Verifier**: 32-byte random string, base64url-encoded
- **Code Challenge**: SHA256 hash of verifier, base64url-encoded  
- **Method**: S256 (SHA256)

### Token Validation

- **Signature Verification**: Uses JWKS from Authentik
- **Claim Validation**: Validates exp, aud, iss claims
- **JWKS Caching**: 1-hour cache with automatic refresh
- **SPIFFE mTLS**: Client authentication for JWKS fetching

### State Management

- **CSRF Protection**: State parameter prevents CSRF attacks
- **Nonce**: Prevents replay attacks
- **Session Expiry**: PKCE sessions expire after 10 minutes

## Configuration

### OIDC Configuration

```go
type OIDCConfig struct {
    AuthURL:     "http://localhost:9000/application/o/authorize/"
    TokenURL:    "http://localhost:9000/application/o/token/"
    ClientID:    "spiffe://example.org/spiffe-services"
    RedirectURI: "http://localhost:8081/callback"
    Scope:       "openid profile email groups"
}
```

### Authentik Setup

- **Client Type**: Public (no client secret)
- **Grant Types**: Authorization Code + PKCE
- **SPIFFE Integration**: Uses SPIFFE ID as client identifier
- **mTLS**: SPIRE certificates for service authentication

## Key Benefits

1. **No Client Secrets**: Uses PKCE and SPIFFE identity
2. **Secure by Default**: Proper OIDC security practices
3. **Scalable**: JWKS caching reduces load on Authentik
4. **Standards Compliant**: Follows OAuth2/OIDC specifications
5. **SPIFFE Integration**: Leverages existing SPIRE infrastructure
6. **Comprehensive Validation**: Validates all standard JWT claims
7. **Error Resilience**: Robust error handling and recovery

## Next Steps

To extend this implementation:

1. **Refresh Tokens**: Add automatic token refresh
2. **User Management**: Integrate with user provisioning
3. **Group-based Authorization**: Enhance SpiceDB integration
4. **Audit Logging**: Add comprehensive audit trails
5. **Rate Limiting**: Add rate limiting for token endpoints
6. **Token Introspection**: Add OAuth2 introspection endpoint
7. **JWKS Rotation**: Handle key rotation gracefully

This implementation provides a solid foundation for secure OIDC authentication in a microservices environment with SPIFFE/SPIRE.
