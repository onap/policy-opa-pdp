PWD := $(shell pwd)
PLATFORM := linux
BINARY := opa-pdp


all: test build
deploy: test build

build: clean test cover
	CGO_ENABED=0 GOOS=$(PLATFORM) GOARCH=amd64 go build -ldflags "-w -s" -o $(PWD)/$(BINARY) cmd/opa-pdp/opa-pdp.go

deploy: build

.PHONY: test
test: clean
	@go test -v ./...

format:
	@go fmt ./...

clean:
	@rm -f $(BINARY)

.PHONY: cover
cover:
	@go test -p 2 ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
