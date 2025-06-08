#!/usr/bin/env bash
set -euo pipefail

SPICEDB_NS="spicedb"

# Wait for SpiceDB to be ready
echo "[*] Waiting for SpiceDB to be ready..."
kubectl wait --for=condition=Ready pods --all -n "$SPICEDB_NS" --timeout=180s

# Port forward SpiceDB gRPC service
echo "[*] Port-forwarding SpiceDB..."
kubectl port-forward -n "$SPICEDB_NS" svc/dev 50051:50051 &
PF_PID=$!

# Give it a moment to establish the port-forward
echo "[*] Waiting for port-forward to establish..."
sleep 3

# Apply the schema
echo "[*] Applying schema to SpiceDB..."
zed schema write schema.yaml --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Create relationships for our services
echo "[*] Setting up service relationships..."

# Loop over these relationships and add them all
# The zed CLI might require a specific format for subjects with SPIFFE URIs
# Let's try creating them one by one with special handling for SPIFFE URIs

# Create relationships with simple user format
echo "[*] Creating user relationships..."
zed relationship create "group:admin" "editor" "user:edvin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "group:editors" "editor" "user:alice" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "group:viewers" "viewer" "user:bob" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Set up document group relationships
zed relationship create "document:doc1" "editor_group" "group:admin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc1" "editor_group" "group:editors" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc1" "viewer_group" "group:viewers" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc2" "editor_group" "group:admin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc2" "viewer_group" "group:editors" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc3" "viewer_group" "group:viewers" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Add direct user permissions for testing JWT claims
echo "[*] Setting up direct user permissions based on Keycloak JWT claims..."

# Edvin (admin group member) should have edit/delete permissions on doc1, doc2
zed relationship create "document:doc1" "editor_user" "user:edvin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc1" "deleter_user" "user:edvin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc2" "editor_user" "user:edvin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc2" "deleter_user" "user:edvin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Alice (editors group member) should have edit permissions on doc1, view permissions on doc2
zed relationship create "document:doc1" "editor_user" "user:alice" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc2" "viewer_user" "user:alice" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Bob (viewers group member) should only have view permissions
zed relationship create "document:doc1" "viewer_user" "user:bob" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc3" "viewer_user" "user:bob" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Create test documents with different permission levels for service-a
echo "[*] Setting up test documents for service-b..."
# TODO, I don't think we need this one, but let's keep it for now
# Add service-b as a document that service-a can access
zed relationship create "document:service-b" "viewer_service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create viewer_service relationship for service-b"

# Document 1: service-a can view, edit and delete
zed relationship create "document:doc1" "viewer_service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create viewer_service relationship"
zed relationship create "document:doc1" "editor_service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create editor_service relationship"
zed relationship create "document:doc1" "deleter_service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create deleter_service relationship"

# Document 2: service-a can view and edit only
zed relationship create "document:doc2" "viewer_service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create viewer_service relationship"
zed relationship create "document:doc2" "editor_service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create editor_service relationship"

# Document 3: service-a can view only
zed relationship create "document:doc3" "viewer_service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create viewer_service relationship"

zed relationship create "user:edvin" "delegate" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create delegate relationship for edvin"

zed relationship create "user:alice" "delegate" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create delegate relationship for alice"

zed relationship create "user:bob" "delegate" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create delegate relationship for bob"

# Create proxy access relationships with Keycloak users
echo "[*] Creating proxy access relationships..."
zed relationship create "proxy_access:doc1_as_edvin" "user" "user:edvin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_edvin" "service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create service relationship for doc1_as_edvin"
zed relationship create "proxy_access:doc1_as_edvin" "document" "document:doc1" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_edvin" "user_is_editor_group" "group:admin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

zed relationship create "proxy_access:doc1_as_alice" "user" "user:alice" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_alice" "service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create service relationship for doc1_as_alice"
zed relationship create "proxy_access:doc1_as_alice" "document" "document:doc1" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_alice" "user_is_viewer_group" "group:editors" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Add Bob (viewer) relationships
zed relationship create "proxy_access:doc3_as_bob" "user" "user:bob" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc3_as_bob" "service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create service relationship for doc3_as_bob"
zed relationship create "proxy_access:doc3_as_bob" "document" "document:doc3" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc3_as_bob" "user_is_viewer_group" "group:viewers" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_alice" "document" "document:doc1" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_alice" "user_is_viewer_group" "group:interns" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Clean up the port-forward
kill $PF_PID
echo "[*] Schema and relationships set up successfully in SpiceDB"
