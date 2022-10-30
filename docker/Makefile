# Setup common vars and funcs
.ONESHELL:
.SHELL := /bin/bash
.PHONY: ALL
.DEFAULT_GOAL := help

VERSION      := $(shell git describe --abbrev=0 --tags --always)
REV          := $(shell git rev-parse --short HEAD)
BUILD_NUMBER := "${BUILD_NUMBER}"
PWD          := $(shell pwd)

define assert-set
  @[ -n "$($1)" ] || (echo "'$(1)' variable not defined in $(@)"; exit 1)
endef

define assert-unset
  @[ -z "$($1)" ] || (echo "'$(1)' variable should not be defined in $(@)"; exit 1)
endef

GOTESTSUM_VERSION := $(shell gotestsum --version 2>/dev/null)


clean:
	@echo "Cleaning"
	@rm -f ./bin/*

build: ## Builds things
	@echo "Building Intake"
	@echo "\tLinux64"
	@GOOS=linux GOARCH=amd64 time go build \
		-o ./bin/intake-linux64 \
		./cmd/intake
	@echo "\tDarwin64"
	@GOOS=darwin GOARCH=amd64 time go build \
		-o ./bin/intake-darwin64 \
		./cmd/intake
	@echo "Building Deliver"
	@echo "\tLinux64"
	@GOOS=linux GOARCH=amd64 time go build \
		-o ./bin/deliver-linux64 \
		./cmd/deliver
	@echo "\tDarwin64"
	@GOOS=darwin GOARCH=amd64 time go build \
		-o ./bin/deliver-darwin64 \
		./cmd/deliver
	@echo "Building Validate"
	@echo "\tLinux64"
	@GOOS=linux GOARCH=amd64 time go build \
		-o ./bin/validate-linux64 \
		./cmd/validate
	@echo "\tDarwin64"
	@GOOS=darwin GOARCH=amd64 time go build \
		-o ./bin/validate-darwin64 \
		./cmd/validate
	@echo "Building Validate-targets"
	@echo "\tLinux64"
	@GOOS=linux GOARCH=amd64 time go build \
		-o ./bin/validate-targets-linux64 \
		./cmd/validate-targets
	@echo "\tDarwin64"
	@GOOS=darwin GOARCH=amd64 time go build \
		-o ./bin/validate-targets-darwin64 \
		./cmd/validate-targets
test: ## Tests things
	@echo "Testing"
ifdef GOTESTSUM_VERSION
	@time gotestsum
else
	@time go test

endif

help: ## Shows this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'