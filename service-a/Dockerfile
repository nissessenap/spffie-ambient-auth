FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o service-a main.go

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/service-a .
EXPOSE 8080
ENTRYPOINT ["/app/service-a"]
