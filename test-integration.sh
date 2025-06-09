#!/usr/bin/env bash
set -euo pipefail

echo "=== JWT + SpiceDB Integration Test ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
SERVICE_A_URL="http://localhost:8081"
KEYCLOAK_URL="http://localhost:8080"

echo "Testing the complete authentication and authorization flow:"
echo "1. Keycloak user authentication"
echo "2. JWT token generation"
echo "3. Service-A → Service-B communication with JWT"
echo "4. JWT verification against Keycloak"
echo "5. SpiceDB authorization with user:{sub} format"
echo ""

echo -e "${YELLOW}[1] Testing Service-A login endpoint...${NC}"
echo "GET $SERVICE_A_URL/login"
if curl -s "$SERVICE_A_URL/login" > /dev/null; then
    echo -e "${GREEN}✓ Service-A login endpoint accessible${NC}"
else
    echo -e "${RED}✗ Service-A not accessible. Is port-forward running?${NC}"
    echo "Run: kubectl port-forward -n app svc/service-a 8081:8081"
    exit 1
fi

echo ""
echo -e "${YELLOW}[2] Getting OIDC auth URL...${NC}"
AUTH_RESPONSE=$(curl -s -H "Accept: application/json" "$SERVICE_A_URL/login")
AUTH_URL=$(echo "$AUTH_RESPONSE" | grep -o '"auth_url":"[^"]*"' | cut -d'"' -f4)

if [ -n "$AUTH_URL" ]; then
    echo -e "${GREEN}✓ Auth URL generated: ${NC}$AUTH_URL"
else
    echo -e "${RED}✗ Failed to get auth URL${NC}"
    echo "Response: $AUTH_RESPONSE"
    exit 1
fi

echo ""
echo -e "${YELLOW}[3] Manual steps needed:${NC}"
echo "To complete the test, you need to:"
echo "1. Open this URL in your browser: $AUTH_URL"
echo "2. Login with Keycloak credentials (edvin/admin or alice/admin)"
echo "3. Copy the JWT token from the callback response"
echo "4. Test document access with the JWT token"
echo ""

echo "Example commands to test with JWT token:"
echo ""
echo -e "${GREEN}# Test viewing doc1 (should work for both edvin and alice)${NC}"
echo 'curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8081/documents/doc1 --insecure'
echo ""
echo -e "${GREEN}# Test editing doc1 (should work for edvin, fail for alice)${NC}"
echo 'curl -X PUT -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8081/documents/doc1 --insecure'
echo ""
echo -e "${GREEN}# Test deleting doc1 (should work for edvin, fail for alice)${NC}"
echo 'curl -X DELETE -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8081/documents/doc1 --insecure'
echo ""

echo -e "${YELLOW}[4] Expected behavior:${NC}"
echo "- Edvin (admin group): Can view, edit, delete doc1 and doc2"
echo "- Alice (intern group): Can only view doc1 and doc3"
echo "- JWT tokens should be validated against Keycloak JWKS endpoint"
echo "- SpiceDB should authorize based on keycloak:user:{sub} format"
echo ""

echo -e "${YELLOW}[5] Checking SpiceDB relationships...${NC}"
echo "Current relationships should include:"
echo "- keycloak:user:edvin → editor permissions"
echo "- keycloak:user:alice → viewer permissions"
echo ""

echo -e "${GREEN}Integration test setup complete!${NC}"
echo "Follow the manual steps above to verify JWT + SpiceDB integration."
