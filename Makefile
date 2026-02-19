.PHONY: build test clean

GO       := $(HOME)/go-sdk/go/bin/go
BINARY   := burrow
BUILD_DIR := build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) .
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

test:
	$(GO) test ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	$(GO) mod tidy
