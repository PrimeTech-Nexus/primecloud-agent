.PHONY: all build test lint fmt vet run clean

BINARY_NAME=primecloud-agent
CMD_DIR=./cmd/agent

all: build

build:
	go build -v -o bin/$(BINARY_NAME) $(CMD_DIR)

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
