#!/usr/bin/env bash
set -euo pipefail

# This script sets up a local Kind cluster with SPIRE, Authentik, and SpiceDB for PoC development.
# Prerequisites: kind, kubectl, helm, docker

CLUSTER_NAME="spffie-demo"
SPIRE_NS="spire-server"
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
  image: kindest/node:v1.32.2
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
kubectl create namespace "$AUTHENTIK_NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace "$SPICEDB_NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns app

# 3. Install SPIRE (SPIFFE) using hardened charts
if ! helm repo list | grep -q "spiffe-hardened"; then
  helm repo add spiffe-hardened https://spiffe.github.io/helm-charts-hardened/
  helm repo update
fi
# Install CRDs first (required by spiffe-hardened chart)
helm upgrade --install -n spire-server spire-crds spire-crds --repo https://spiffe.github.io/helm-charts-hardened/ --create-namespace
helm upgrade --install -n spire-server spire spire --repo https://spiffe.github.io/helm-charts-hardened/

#  4. Install Authentik (OIDC provider)
if ! helm repo list | grep -q "authentik"; then
  helm repo add authentik https://charts.goauthentik.io/
  helm repo update
fi
helm upgrade --install authentik authentik/authentik -n "$AUTHENTIK_NS" --create-namespace  -f authentik-values.yaml

# 5. Install SpiceDB (authorization)
# if ! helm repo list | grep -q "authzed"; then
#   helm repo add authzed https://authzed.github.io/charts
#   helm repo update
# fi
# helm upgrade --install spicedb authzed/spicedb -n "$SPICEDB_NS" --create-namespace \
#   --set replicaCount=1 \
#   --set datastore.engine=memory

# https://authzed.com/docs/spicedb/getting-started/install/kubernetes
kubectl apply --server-side -f https://github.com/authzed/spicedb-operator/releases/latest/download/bundle.yaml
kubectl apply -f spicedb/cluster.yaml


# 6. Wait for pods to be ready
kubectl wait --for=condition=Ready pods --all -n "$SPIRE_NS" --timeout=180s
kubectl wait --for=condition=Ready pods --all -n "$AUTHENTIK_NS" --timeout=180s
kubectl wait --for=condition=Ready pods --all -n "$SPICEDB_NS" --timeout=180s

# 7. Port-forward services for local access
echo "[+] Port-forwarding Authentik..."
kubectl port-forward -n "$AUTHENTIK_NS" svc/authentik-server 8080:80 &
echo "[+] Port-forwarding SpiceDB..."
kubectl port-forward -n "$SPICEDB_NS" svc/spicedb 50051:50051 &
echo "[+] Port-forwarding SpiceDB Console..."
kubectl port-forward -n "$SPICEDB_NS" svc/spicedb-console 8080:8080 &
echo "[+] Port-forwarding SpiceDB UI..."
kubectl port-forward -n "$SPICEDB_NS" svc/spicedb-ui 8081:8081 &
