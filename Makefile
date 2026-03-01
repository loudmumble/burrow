.PHONY: build build-local build-stager build-all test clean tidy upx sizes

GO        ?= go
MODULE    := github.com/loudmumble/burrow/cmd/burrow/cmd
BINARY    := burrow
STAGER    := stager
BUILD_DIR := build
VERSION   ?= $(shell git describe --tags --always 2>/dev/null || echo "3.0.0")
LDFLAGS   := -s -w -X $(MODULE).version=$(VERSION)
UPX       ?= /home/mumble/.local/bin/upx

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64

# Build all platform binaries (full burrow)
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

# Build stager for linux/amd64 + windows/amd64
build-stager:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
		-ldflags="-s -w" -o $(BUILD_DIR)/$(STAGER)-linux-amd64 ./cmd/stager/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build \
		-ldflags="-s -w" -o $(BUILD_DIR)/$(STAGER)-windows-amd64.exe ./cmd/stager/
	@echo "Stager built (linux-amd64 + windows-amd64)."

# Build everything: full burrow + stager (linux + windows amd64), then UPX
build-all:
	@mkdir -p $(BUILD_DIR)
	@echo "=== Full burrow ==="
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
		-ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build \
		-ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe .
	@echo "=== Stager ==="
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
		-ldflags="-s -w" -o $(BUILD_DIR)/$(STAGER)-linux-amd64 ./cmd/stager/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build \
		-ldflags="-s -w" -o $(BUILD_DIR)/$(STAGER)-windows-amd64.exe ./cmd/stager/
	@echo "=== UPX compress ==="
	cp $(BUILD_DIR)/$(BINARY)-linux-amd64 $(BUILD_DIR)/$(BINARY)-linux-amd64-upx && \
		$(UPX) --best $(BUILD_DIR)/$(BINARY)-linux-amd64-upx || true
	cp $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(BUILD_DIR)/$(BINARY)-windows-amd64-upx.exe && \
		$(UPX) --best $(BUILD_DIR)/$(BINARY)-windows-amd64-upx.exe || true
	cp $(BUILD_DIR)/$(STAGER)-linux-amd64 $(BUILD_DIR)/$(STAGER)-linux-amd64-upx && \
		$(UPX) --best $(BUILD_DIR)/$(STAGER)-linux-amd64-upx || true
	cp $(BUILD_DIR)/$(STAGER)-windows-amd64.exe $(BUILD_DIR)/$(STAGER)-windows-amd64-upx.exe && \
		$(UPX) --best $(BUILD_DIR)/$(STAGER)-windows-amd64-upx.exe || true
	@echo "=== Done ==="
	@$(MAKE) --no-print-directory sizes

# UPX compress existing binaries
upx:
	@for f in $(BUILD_DIR)/$(BINARY)-linux-amd64 $(BUILD_DIR)/$(BINARY)-windows-amd64.exe \
	          $(BUILD_DIR)/$(STAGER)-linux-amd64 $(BUILD_DIR)/$(STAGER)-windows-amd64.exe; do \
		if [ -f "$$f" ]; then \
			cp "$$f" "$$f-upx$${f##*.exe}" 2>/dev/null || cp "$$f" "$${f%.*}-upx$${f##*[^.]}" 2>/dev/null; \
			$(UPX) --best "$$f" || true; \
		fi; \
	done

# Print binary sizes
sizes:
	@echo ""
	@echo "Binary sizes:"
	@ls -lh $(BUILD_DIR)/ 2>/dev/null | grep -E '\.(exe|amd64)' | awk '{printf "  %-45s %s\n", $$NF, $$5}' || true

test:
	$(GO) test ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	$(GO) mod tidy
