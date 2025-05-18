#!/usr/bin/env bash
set -euo pipefail

# This script sets up a local Kind cluster with SPIRE, Authentik, and SpiceDB for PoC development.
# Prerequisites: kind, kubectl, helm, docker

CLUSTER_NAME="spffie-demo"
SPIRE_NS="spire"
AUTHENTIK_NS="authentik"
SPICEDB_NS="spicedb"

# 1. Create Kind cluster (if not exists)
if ! kind get clusters | grep -q "$CLUSTER_NAME"; then
  echo "[+] Creating Kind cluster: $CLUSTER_NAME"
  kind create cluster --name "$CLUSTER_NAME" --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 8080
    hostPort: 8080
  - containerPort: 8443
    hostPort: 8443
  - containerPort: 9000
    hostPort: 9000
EOF
else
  echo "[!] Kind cluster $CLUSTER_NAME already exists. Skipping creation."
fi

kubectl cluster-info --context kind-$CLUSTER_NAME

# 2. Create namespaces
kubectl create namespace "$SPIRE_NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace "$AUTHENTIK_NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace "$SPICEDB_NS" --dry-run=client -o yaml | kubectl apply -f -

# 3. Install SPIRE (SPIFFE) using hardened charts
if ! helm repo list | grep -q "spiffe-hardened"; then
  helm repo add spiffe-hardened https://spiffe.github.io/helm-charts-hardened/
  helm repo update
fi
helm upgrade --install spire spiffe-hardened/spire -n "$SPIRE_NS" --create-namespace \

# 4. Install Authentik (OIDC provider)
if ! helm repo list | grep -q "authentik"; then
  helm repo add authentik https://charts.goauthentik.io/
  helm repo update
fi
helm upgrade --install authentik authentik/authentik -n "$AUTHENTIK_NS" --create-namespace \
  --set postgresql.enabled=true \
  --set redis.enabled=true \
  --set ingress.enabled=false

# 5. Install SpiceDB (authorization)
if ! helm repo list | grep -q "authzed"; then
  helm repo add authzed https://authzed.github.io/charts
  helm repo update
fi
helm upgrade --install spicedb authzed/spicedb -n "$SPICEDB_NS" --create-namespace \
  --set replicaCount=1 \
  --set datastore.engine=memory

# 6. Wait for pods to be ready
kubectl wait --for=condition=Ready pods --all -n "$SPIRE_NS" --timeout=180s
kubectl wait --for=condition=Ready pods --all -n "$AUTHENTIK_NS" --timeout=180s
kubectl wait --for=condition=Ready pods --all -n "$SPICEDB_NS" --timeout=180s

echo "[+] All infrastructure components are deployed!"
echo "- SPIRE (SPIFFE) in namespace: $SPIRE_NS"
echo "- Authentik (OIDC) in namespace: $AUTHENTIK_NS"
echo "- SpiceDB in namespace: $SPICEDB_NS"
echo "[!] You may want to port-forward or expose services for local access."
