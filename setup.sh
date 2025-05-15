#!/bin/bash

# Proof of Concept: Secure Microservice Architecture for Kubernetes
# This script automates the setup of a secure microservice architecture.

set -e

# Prerequisites check
command -v kind >/dev/null 2>&1 || { echo >&2 "Kind is not installed. Aborting."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo >&2 "Kubectl is not installed. Aborting."; exit 1; }
command -v helm >/dev/null 2>&1 || { echo >&2 "Helm is not installed. Aborting."; exit 1; }

# 1. Set Up a Minimal Kubernetes Cluster with Kind
echo "Creating Kind cluster..."
cat <<EOF > kind-cluster-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
EOF

kind create cluster --config kind-cluster-config.yaml
kubectl cluster-info

# 2. Deploy SPIRE
echo "Deploying SPIRE using hardened Helm chart..."
helm repo add spiffe https://spiffe.github.io/helm-charts/
helm repo update
helm install spire-server spiffe/spire-server --namespace spire --create-namespace
helm install spire-agent spiffe/spire-agent --namespace spire
kubectl get pods -n spire

# 3. Deploy Istio Ambient Mode
echo "Deploying Istio Ambient Mode..."
curl -L https://istio.io/downloadIstio | sh -
cd istio-*
export PATH=$PWD/bin:$PATH
istioctl install --set profile=ambient -y
kubectl get pods -n istio-system
cd ..

# 4. Deploy an OIDC Provider (Keycloak)
echo "Deploying Keycloak..."
helm repo add codecentric https://codecentric.github.io/helm-charts
helm install keycloak codecentric/keycloak --namespace keycloak --create-namespace

# 5. Deploy SpiceDB
echo "Deploying SpiceDB..."
helm repo add authzed https://charts.authzed.com
helm install spicedb authzed/spicedb --namespace spicedb --create-namespace

# Cleanup instructions
echo "To clean up, run the following commands:"
echo "kind delete cluster"
echo "helm uninstall spire-server -n spire"
echo "helm uninstall spire-agent -n spire"
echo "helm uninstall keycloak -n keycloak"
echo "helm uninstall spicedb -n spicedb"