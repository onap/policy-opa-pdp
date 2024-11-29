PWD := $(shell pwd)
PLATFORM := linux
BINARY := opa-pdp
GO_VERSION ?= 1.23.3
INSTALL_DIR ?= /usr/local
GO_URL ?= https://go.dev/dl/go$(GO_VERSION).linux-amd64.tar.gz


all: test build

build: install test build_image

deploy: test build

.PHONY: test
test: clean
	@go test -v ./...

format:
	@go fmt ./...

clean:
	@echo "Cleaning up..."
	rm -f go.tar.gz
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
