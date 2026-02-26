.PHONY: build build-local test clean tidy

GO        ?= go
MODULE    := github.com/loudmumble/burrow/cmd/burrow/cmd
BINARY    := burrow
BUILD_DIR := build
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "3.0.0")
LDFLAGS   := -s -w -X $(MODULE).version=$(VERSION)

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64

# Build all platform binaries
build:
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*}; \
		GOARCH=$${platform#*/}; \
		ext=""; \
		if [ "$$GOOS" = "windows" ]; then ext=".exe"; fi; \
		echo "Building $$GOOS/$$GOARCH..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH CGO_ENABLED=0 $(GO) build \
			-ldflags="$(LDFLAGS)" \
			-o $(BUILD_DIR)/$(BINARY)-$$GOOS-$$GOARCH$$ext . || exit 1; \
		echo "  -> $(BUILD_DIR)/$(BINARY)-$$GOOS-$$GOARCH$$ext"; \
	done
	@echo "All platforms built successfully."

# Build for current platform only
build-local:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) .
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

# Build single platform: make build-linux-arm64
build-%:
	@mkdir -p $(BUILD_DIR)
	$(eval GOOS := $(word 1,$(subst -, ,$*)))
	$(eval GOARCH := $(word 2,$(subst -, ,$*)))
	$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,))
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 $(GO) build \
		-ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-$(GOOS)-$(GOARCH)$(EXT) .
	@echo "Built: $(BUILD_DIR)/$(BINARY)-$(GOOS)-$(GOARCH)$(EXT)"

test:
	$(GO) test ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	$(GO) mod tidy
