FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY service-a/go.mod service-a/go.sum ./service-a/
COPY service-a/main.go ./service-a/
COPY pkg ./pkg
# Use GOWORK=off to disable go.work and build independently
ENV GOWORK=off
RUN cd service-a && go mod download && go build -o service-a main.go

FROM alpine:3.19
WORKDIR /app
RUN addgroup -S spire && adduser -S spire -G spire
COPY --from=builder /app/service-a/service-a .
USER spire
EXPOSE 8080 8081
ENTRYPOINT ["/app/service-a"]
