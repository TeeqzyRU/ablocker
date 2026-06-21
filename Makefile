.PHONY: all amd64 arm64 build test test-short vet fmt clean

VERSION ?= v0.0.1-dev
LDFLAGS := -s -w -X main.Version=$(VERSION)

all: amd64 arm64

amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o build/ablocker_amd64 .

arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o build/ablocker_arm64 .

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o build/ablocker .

test:
	go test ./... -v

test-short:
	go test ./... -v -short

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf build/
