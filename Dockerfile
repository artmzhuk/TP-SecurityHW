FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY proxy.go go.mod ./
COPY cert ./cert


RUN go build -o proxy

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/proxy .
COPY certs/ca.crt certs/ca-PRIVATE.key ./certs/
RUN mkdir -p "certs/hosts"
EXPOSE 8080
CMD ["./proxy"]