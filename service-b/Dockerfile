FROM golang:1.24-alpine AS builder
# Set up a workspace structure
WORKDIR /workspace
# Copy the whole repo (this works because we run docker build from repo root with . context)
COPY . .
# Build service-b
WORKDIR /workspace/service-b
RUN go build -o service-b main.go

FROM alpine:3.19
WORKDIR /app
RUN addgroup -S spire && adduser -S spire -G spire
COPY --from=builder /workspace/service-b/service-b .
USER spire
EXPOSE 8080
ENTRYPOINT ["/app/service-b"]
