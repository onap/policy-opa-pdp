PWD := $(shell pwd)
PLATFORM := linux
BINARY := opa-pdp
GO_TEST_CLEAN ?= go clean -cache -testcache -modcache -i -r
RETRY_COUNT ?= 3
SLEEP_BETWEEN_RETRIES ?= 5


all: test build

build: install clean go_build test cover

deploy: build_image

.PHONY: test
test:
	@echo "Test Execution"
	@for in in $$(seq 1 $(RETRY_COUNT)); do \
		echo "Attempt $$i of $(RETRY_COUNT)..."; \
		if $(MAKE) do_test; then \
		   echo "Test Execution Completed Successfully"; \
		   exit 0; \
		fi; \
		echo "Retrying in $(SLEEP_BETWEEN_RETRIES) seconds..."; \
		$(GO_TEST_CLEAN) \
		sleep $(SLEEP_BETWEEN_RETRIES); \
	done; \
        echo "Test Execution Failed after $(RETRY_COUNT) attempts."; \
        exit 1

do_test:
	@go test -v ./...

format:
	@go fmt ./...

clean:
	@echo "Cleaning up..."
	rm -f go.tar.gz
	@rm -f $(BINARY)
	@echo "Done."

.PHONY: cover
cover:
	@go test -p 2 ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html

.PHONY: install clean

install:
	./build_image.sh install

build_image:
	./build_image.sh build

go_build:
	CGO_ENABED=0 GOOS=$(PLATFORM) GOARCH=amd64 go build -ldflags "-w -s" -o $(PWD)/$(BINARY) cmd/opa-pdp/opa-pdp.go
