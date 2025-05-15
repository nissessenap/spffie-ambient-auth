# Proof of Concept: Secure Microservice Architecture for Kubernetes

This document outlines the steps to set up a secure microservice architecture using SPIRE, Istio Ambient Mode, SpiceDB, and an OIDC provider. The setup includes a demo application stack showcasing user and service authentication and authorization.

## Prerequisites

- Linux OS
- Docker installed
- Kubernetes CLI (`kubectl`) installed
- Kind (Kubernetes in Docker) installed
- Helm installed

## Steps

### 1. Set Up a Minimal Kubernetes Cluster with Kind

1. Create a Kind configuration file:

    ```yaml
    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    nodes:
    - role: control-plane
    - role: worker
    ```

2. Create the cluster:

    ```bash
    kind create cluster --config kind-cluster-config.yaml
    ```

3. Verify the cluster:

    ```bash
    kubectl cluster-info
    ```

### 2. Deploy SPIRE

1. Clone the SPIRE repository:

    ```bash
    git clone https://github.com/spiffe/spire.git
    cd spire
    ```

2. Deploy SPIRE server and agent using Helm:

    ```bash
    helm install spire-server charts/spire-server --namespace spire --create-namespace
    helm install spire-agent charts/spire-agent --namespace spire
    ```

3. Verify SPIRE deployment:

    ```bash
    kubectl get pods -n spire
    ```

### 3. Deploy Istio Ambient Mode

1. Install Istio CLI:

    ```bash
    curl -L https://istio.io/downloadIstio | sh -
    cd istio-*
    export PATH=$PWD/bin:$PATH
    ```

2. Install Istio Ambient Mode:

    ```bash
    istioctl install --set profile=ambient -y
    ```

3. Verify Istio installation:

    ```bash
    kubectl get pods -n istio-system
    ```

### 4. Deploy an OIDC Provider (Keycloak)

1. Deploy Keycloak using Helm:

    ```bash
    helm repo add codecentric https://codecentric.github.io/helm-charts
    helm install keycloak codecentric/keycloak --namespace keycloak --create-namespace
    ```

2. Access Keycloak and configure a realm, client, and users.

### 5. Deploy SpiceDB

1. Deploy SpiceDB using Helm:

    ```bash
    helm repo add authzed https://charts.authzed.com
    helm install spicedb authzed/spicedb --namespace spicedb --create-namespace
    ```

2. Apply a schema defining users, services, resources, and permissions.

### 6. Deploy the Demo Application Stack

1. Create a frontend application for user login via OIDC.
2. Create a backend service for service-to-service calls authenticated with SPIFFE ID.
3. Configure the API Gateway to verify tokens and SPIFFE IDs.
4. Query SpiceDB for fine-grained access control.

### 7. Test the Setup

1. Log in as a user via the frontend.
2. Make a service-to-service call.
3. Verify that the call is allowed only if both user and service have the required relationship in SpiceDB.

### 8. Clean Up

1. Delete the Kind cluster:

    ```bash
    kind delete cluster
    ```

2. Remove Helm releases:

    ```bash
    helm uninstall spire-server -n spire
    helm uninstall spire-agent -n spire
    helm uninstall keycloak -n keycloak
    helm uninstall spicedb -n spicedb
    ```
