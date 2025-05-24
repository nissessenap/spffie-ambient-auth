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
# Format: zed relationship create <resource:id> <relation> <subject:id#optional_subject_relation>
while read -r resource relation subject; do
  echo "[*] Creating relationship: $resource $relation $subject"
  zed relationship create "$resource" "$relation" "$subject" --endpoint localhost:50051 --insecure --token "averysecretpresharedkey"
done << EOF
group:devs editor user:edvin
group:interns viewer user:alice
document:doc1 editor_group group:devs
document:doc1 viewer_group group:interns
document:doc1 deleter_service service:spiffe://org/service-cron
user:edvin delegate service:spiffe://org/service-a
user:alice delegate service:spiffe://org/service-a
proxy_access:doc1_as_edvin user user:edvin
proxy_access:doc1_as_edvin service service:spiffe://org/service-a
proxy_access:doc1_as_edvin document document:doc1
proxy_access:doc1_as_edvin user_is_editor_group group:devs
proxy_access:doc1_as_alice user user:alice
proxy_access:doc1_as_alice service service:spiffe://org/service-a
proxy_access:doc1_as_alice document document:doc1
proxy_access:doc1_as_alice user_is_viewer_group group:interns
EOF

# Clean up the port-forward
kill $PF_PID
echo "[*] Schema and relationships set up successfully in SpiceDB"
