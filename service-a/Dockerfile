FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o service-a main.go

FROM alpine:3.19
WORKDIR /app
RUN addgroup -S spire && adduser -S spire -G spire
COPY --from=builder /app/service-a .
USER spire
EXPOSE 8080
ENTRYPOINT ["/app/service-a"]
