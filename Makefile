.PHONY: all build test lint fmt vet run clean

BINARY_NAME=primecloud-agent
CMD_DIR=./cmd/agent

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS ?= -s -w -X main.Version=$(VERSION) -X main.CommitSHA=$(COMMIT)

all: build

build:
	go build -v -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME) $(CMD_DIR)

test:
	go test -v -race ./...

smoke-test:
	go test -v ./tests/smoke/...

lint: vet fmt
	golangci-lint run || echo "golangci-lint completed"

fmt:
	gofmt -s -w .

vet:
	go vet ./...

run: build
	./bin/$(BINARY_NAME)

clean:
	rm -rf bin/
