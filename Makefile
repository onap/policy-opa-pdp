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
	docker build -f  Dockerfile  -t policy-opa-pdp:1.0.0 .
	docker tag policy-opa-pdp:1.0.0 nexus3.onap.org:10003/onap/policy-opa-pdp:latest
	docker push nexus3.onap.org:10003/onap/policy-opa-pdp:latest
	docker tag nexus3.onap.org:10003/onap/policy-opa-pdp:latest nexus3.onap.org:10003/onap/policy-opa-pdp:1.0.0
	docker push nexus3.onap.org:10003/onap/policy-opa-pdp:1.0.0
