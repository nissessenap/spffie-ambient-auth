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
zed relationship create organization:eng service service:service-a --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create organization:eng service service:service-b --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
zed relationship create service:service-a can_access service:service-b --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"

# Clean up the port-forward
kill $PF_PID
echo "[*] Schema and relationships set up successfully in SpiceDB"
