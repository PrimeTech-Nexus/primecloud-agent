# PrimeCloud Agent Production Container
# Multi-stage, statically linked Go binary on Alpine Linux
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git make

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app/bin/primecloud-agent ./cmd/agent

FROM alpine:3.20 AS runner

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata curl haproxy

COPY --from=builder /app/bin/primecloud-agent /usr/local/bin/primecloud-agent

ENV PRIMECLOUD_HAPROXY_CONFIG_DIR=/etc/haproxy/conf.d

EXPOSE 50051

ENTRYPOINT ["/usr/local/bin/primecloud-agent"]
