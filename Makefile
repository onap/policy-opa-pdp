PWD := $(shell pwd)
PLATFORM := linux
BINARY := opa-pdp
GO_TEST_CLEAN ?= go clean -cache -testcache -modcache -i -r
RETRY_COUNT ?= 3
SLEEP_BETWEEN_RETRIES ?= 5
GO_INSTALL_DIR := /usr/local/go

# The install target unpacks the pinned Go (build_image.sh GO_VERSION) into
# GO_INSTALL_DIR, but it runs in a subshell so its PATH never reaches this make
# process and go falls back to whatever the build node ships -- Go 1.23 on the
# ONAP CI nodes. go.mod toolchain switching covers build and test but not
# coverage: 'go test -coverprofile' shells out to 'go tool covdata' resolved from
# PATH, and a pre-1.26 go cannot find covdata inside a 1.26 GOROOT because 1.26
# builds it on demand instead of shipping it prebuilt. GOROOT is dropped because
# the Jenkins Go plugin points it at that same older tree.
ifneq ($(wildcard $(GO_INSTALL_DIR)/bin/go),)
export PATH := $(GO_INSTALL_DIR)/bin:$(PATH)
unexport GOROOT
endif


all: test build

build: install clean go_build test cover

deploy: build_image

.PHONY: test
test:
	@go test -v -p 1 ./...

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
	@go tool cover -func=coverage.out -o coverage.html

.PHONY: install clean

install:
	./build_image.sh install

build_image:
	./build_image.sh build

go_build:
	CGO_ENABLED=1 GOOS=$(PLATFORM) GOARCH=amd64 go build -ldflags "-w -s" -o $(PWD)/$(BINARY) cmd/opa-pdp/opa-pdp.go
