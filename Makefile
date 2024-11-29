PWD := $(shell pwd)
PLATFORM := linux
BINARY := opa-pdp
GO_VERSION ?= 1.23.3
INSTALL_DIR ?= /usr/local
GO_URL ?= https://go.dev/dl/go$(GO_VERSION).linux-amd64.tar.gz
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
		$(GO_TEST_CLEAN)
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
	@echo "Downloading Go $(GO_VERSION)..."
	curl -fsSL $(GO_URL) -o go.tar.gz
	@echo "Extracting Go $(GO_VERSION)..."
	sudo rm -rf $(INSTALL_DIR)/go
	sudo tar -C $(INSTALL_DIR) -xzf go.tar.gz
	@echo "Adding Go to PATH..."
	echo "export PATH=$(INSTALL_DIR)/go/bin:\$$PATH" >> ~/.profile
	@echo "Reloading PATH for verification..."
	export PATH=$(INSTALL_DIR)/go/bin:$$PATH; $(INSTALL_DIR)/go/bin/go version
	@echo "Go $(GO_VERSION) installed successfully. Run 'source ~/.profile' to update PATH."

build_image:
	docker build -f  Dockerfile  -t policy-opa-pdp:1.0.0 .
	docker tag policy-opa-pdp:1.0.0 nexus3.onap.org:10003/onap/policy-opa-pdp:latest
	docker tag nexus3.onap.org:10003/onap/policy-opa-pdp:latest nexus3.onap.org:10003/onap/policy-opa-pdp:1.0.0

go_build:
	CGO_ENABED=0 GOOS=$(PLATFORM) GOARCH=amd64 go build -ldflags "-w -s" -o $(PWD)/$(BINARY) cmd/opa-pdp/opa-pdp.go
