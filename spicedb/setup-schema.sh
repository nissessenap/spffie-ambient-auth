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

# Create relationships with regular subjects
echo "[*] Creating regular relationships..."
zed relationship create "group:devs" "editor" "user:edvin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "group:interns" "viewer" "user:alice" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc1" "editor_group" "group:devs" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "document:doc1" "viewer_group" "group:interns" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Create relationships with SPIFFE URIs - special handling
echo "[*] Creating SPIFFE URI relationships..."
zed relationship create "document:doc1" "deleter_service" "service:spiffe-example-org-ns-app-sa-cron" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create deleter_service relationship"
zed relationship create "document:doc1" "deleter_service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create deleter_service relationship"

zed relationship create "user:edvin" "delegate" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create delegate relationship for edvin"

zed relationship create "user:alice" "delegate" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create delegate relationship for alice"

# Create proxy access relationships
echo "[*] Creating proxy access relationships..."
zed relationship create "proxy_access:doc1_as_edvin" "user" "user:edvin" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_edvin" "service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create service relationship for doc1_as_edvin"
zed relationship create "proxy_access:doc1_as_edvin" "document" "document:doc1" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_edvin" "user_is_editor_group" "group:devs" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

zed relationship create "proxy_access:doc1_as_alice" "user" "user:alice" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_alice" "service" "service:spiffe-example-org-ns-app-sa-service-a" \
  --endpoint localhost:50051 --insecure --token "averysecretpresharedkey" || echo "Warning: Failed to create service relationship for doc1_as_alice"
zed relationship create "proxy_access:doc1_as_alice" "document" "document:doc1" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create "proxy_access:doc1_as_alice" "user_is_viewer_group" "group:interns" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Clean up the port-forward
kill $PF_PID
echo "[*] Schema and relationships set up successfully in SpiceDB"
