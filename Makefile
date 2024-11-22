PWD := $(shell pwd)
PLATFORM := linux
BINARY := opa-pdp


all: test build
deploy: test build

build: clean
	@echo $(shell pwd)
	@mkdir  ../src
	@echo $(shell pwd)
	@cp -r $(PWD)/* ../src/
	@echo $(PWD)
	CGO_ENABED=0 GOOS=$(PLATFORM) GOPATH=$(PWD)/.. GOARCH=amd64 go build -ldflags "-w -s" -o $(PWD)/$(BINARY) cmd/opa-pdp/opa-pdp.go

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
