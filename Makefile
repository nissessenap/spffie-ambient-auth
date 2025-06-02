# Build Docker images for service-a and service-b
SERVICE_A_IMAGE ?= service-a:latest
SERVICE_B_IMAGE ?= service-b:latest
OIDC_SETUP_IMAGE ?= oidc-setup:latest


.PHONY: build-service-a build-service-b build-oidc-setup build-all load-service-a load-service-b load-oidc-setup load-all

build-service-a:
	docker build -t $(SERVICE_A_IMAGE) ./service-a

load-service-a: build-service-a
	kind load docker-image $(SERVICE_A_IMAGE) --name spffie-demo

build-service-b:
	docker build -t $(SERVICE_B_IMAGE) -f ./service-b/Dockerfile --no-cache .

load-service-b: build-service-b
	kind load docker-image $(SERVICE_B_IMAGE) --name spffie-demo

build-oidc-setup:
	docker build -t $(OIDC_SETUP_IMAGE) -f ./Dockerfile.oidc-setup .

load-oidc-setup: build-oidc-setup
	kind load docker-image $(OIDC_SETUP_IMAGE) --name spffie-demo

build-all: build-service-a build-service-b
	echo "Built both service-a and service-b images."

load-all: load-service-a load-service-b
	echo "Loaded both images into kind cluster."
