#!/bin/bash
echo "--> prescan-go-coverage-ubuntu.sh"

set -ex

# Test and coverage
go test -p 1 ./... -coverprofile=coverage.out

echo "--> prescan-go-coverage-ubuntu.sh ends"
