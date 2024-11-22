PWD := $(shell pwd)
PLATFORM := linux
BINARY := opa-pdp


all: test build
deploy: test build

build: build_image

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

build_image:
	$(MAKE) -C build build
