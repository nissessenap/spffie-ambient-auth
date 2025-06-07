FROM golang:1.24-alpine AS builder
WORKDIR /app
# Use GOWORK=off to disable go.work and build independently
ENV GOWORK=off
COPY service-a/go.mod service-a/go.sum ./service-a/
COPY pkg/oidc/go.mod pkg/oidc/go.sum ./pkg/oidc/
RUN cd service-a && go mod download
WORKDIR /app
COPY service-a/ ./service-a/
COPY pkg ./pkg
RUN cd service-a && go build -o service-a .

FROM alpine:3.19
WORKDIR /app
RUN addgroup -S spire && adduser -S spire -G spire
COPY --from=builder /app/service-a/service-a .
USER spire
EXPOSE 8080 8081
ENTRYPOINT ["/app/service-a"]
