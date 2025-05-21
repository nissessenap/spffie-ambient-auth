
# Build Docker images for service-a and service-b
SERVICE_A_IMAGE ?= service-a:latest
SERVICE_B_IMAGE ?= service-b:latest

.PHONY: build-service-a build-service-b build-all

build-service-a:
	docker build -t $(SERVICE_A_IMAGE) ./service-a

build-service-b:
	docker build -t $(SERVICE_B_IMAGE) ./service-b

build-all: build-service-a build-service-b
	echo "Built both service-a and service-b images."
