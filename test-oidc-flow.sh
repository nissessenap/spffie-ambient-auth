#!/bin/bash

# OIDC Test Script
# This script demonstrates the complete OIDC Authorization Code Flow with PKCE

set -e

echo "🚀 OIDC Authorization Code Flow with PKCE Test"
echo "============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SERVICE_A_URL="http://localhost:8081"
SERVICE_B_URL="https://service-b:8080"

echo -e "${BLUE}Step 1: Starting OIDC login flow...${NC}"
echo "Requesting authorization URL from service-a..."

# Step 1: Start login flow
LOGIN_RESPONSE=$(curl -s -H "Accept: application/json" ${SERVICE_A_URL}/login)
echo "Response: $LOGIN_RESPONSE"

# Extract auth_url and state
AUTH_URL=$(echo $LOGIN_RESPONSE | jq -r '.auth_url')
STATE=$(echo $LOGIN_RESPONSE | jq -r '.state')

echo -e "${YELLOW}Step 2: User authentication required${NC}"
echo "Please visit the following URL in your browser to complete login:"
echo ""
echo -e "${GREEN}$AUTH_URL${NC}"
echo ""
echo "After logging in, you will be redirected to the callback URL."
echo "The authorization code will be automatically exchanged for tokens."

echo ""
echo -e "${BLUE}Step 3: Manual token testing${NC}"
echo "If you have an access token, you can test it manually:"
echo ""
echo "Test with service-a proxy:"
echo "curl -H \"Authorization: Bearer YOUR_TOKEN\" ${SERVICE_A_URL}/test-token"
echo ""
echo "Test directly with service-b (requires mTLS):"
echo "curl -H \"Authorization: Bearer YOUR_TOKEN\" \\"
echo "     --cert client.crt --key client.key --cacert ca.crt \\"
echo "     ${SERVICE_B_URL}/hello"

echo ""
echo -e "${BLUE}Step 4: Document operations test${NC}"
echo "Test document operations with your token:"
echo ""
echo "View document:"
echo "curl -H \"Authorization: Bearer YOUR_TOKEN\" \\"
echo "     --cert client.crt --key client.key --cacert ca.crt \\"
echo "     ${SERVICE_B_URL}/documents/doc1"
echo ""
echo "Edit document:"
echo "curl -X PUT -H \"Authorization: Bearer YOUR_TOKEN\" \\"
echo "     --cert client.crt --key client.key --cacert ca.crt \\"
echo "     ${SERVICE_B_URL}/documents/doc1"
echo ""
echo "Delete document:"
echo "curl -X DELETE -H \"Authorization: Bearer YOUR_TOKEN\" \\"
echo "     --cert client.crt --key client.key --cacert ca.crt \\"
echo "     ${SERVICE_B_URL}/documents/doc1"

echo ""
echo -e "${GREEN}✅ OIDC Implementation Features:${NC}"
echo "🔐 Authorization Code Flow with PKCE (no client secret needed)"
echo "🎫 JWT access token validation with JWKS"
echo "📝 Comprehensive claim verification (exp, aud, iss)"
echo "💾 Automatic JWKS caching for performance"
echo "🛡️  SPIFFE mTLS for service-to-service authentication"
echo "🚫 Proper error handling for invalid/expired tokens"
echo "🔄 State and nonce protection against CSRF and replay attacks"

echo ""
echo -e "${YELLOW}💡 Architecture Highlights:${NC}"
echo "• service-a acts as OIDC client (Authorization Code Flow)"
echo "• service-b acts as resource server (JWT validation)"
echo "• Authentik provides OIDC/OAuth2 services"
echo "• SPIFFE/SPIRE provides service identity and mTLS"
echo "• No client secrets - uses PKCE + SPIFFE identity"

echo ""
echo -e "${BLUE}📚 For more details, see: OIDC_IMPLEMENTATION.md${NC}"
