.PHONY: build build-local build-stager check-anvil build-anvil build-stager-evasion build-stager-packed build-all test clean tidy sizes verify

GO        ?= go
MODULE    := github.com/loudmumble/burrow/cmd/burrow/cmd
BINARY    := burrow
STAGER    := stager
BUILD_DIR := build
VERSION   ?= $(shell git describe --tags --always 2>/dev/null || echo "3.0.0")
LDFLAGS   := -s -w -X $(MODULE).version=$(VERSION)
ANVIL_DIR := ../anvil
ANVIL     := $(ANVIL_DIR)/build/anvil

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

# Verify anvil toolkit is available
check-anvil:
	@if [ ! -d $(ANVIL_DIR) ]; then \
		echo "ERROR: anvil directory not found at $(ANVIL_DIR)"; \
		echo "  Clone anvil next to burrow:"; \
		echo "    Clone the anvil toolkit into ../anvil"; \
		exit 1; \
	fi

# Build anvil toolkit (external dependency)
build-anvil: check-anvil
	@if [ ! -f $(ANVIL) ]; then \
		echo "Building anvil toolkit..."; \
		$(MAKE) -C $(ANVIL_DIR) build || { echo "ERROR: anvil build failed"; exit 1; }; \
	else \
		echo "anvil: $(ANVIL) (cached)"; \
	fi
	@if [ ! -x $(ANVIL) ]; then \
		echo "ERROR: anvil binary not executable at $(ANVIL)"; \
		exit 1; \
	fi
# Evasion stager: obfuscated strings + hardened build
build-stager-evasion: build-anvil
	@echo "=== Evasion stager ==="
	@rm -rf cmd/stager/_build
	$(ANVIL) obfuscate go -input cmd/stager/main.go -outdir cmd/stager/_build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$(STAGER)-evasion-linux-amd64 ./cmd/stager/_build/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$(STAGER)-evasion-windows-amd64.exe ./cmd/stager/_build/
	@rm -rf cmd/stager/_build

# Packed stager: evasion + custom compression
build-stager-packed: build-stager-evasion
	@echo "=== Packed stager ==="
	$(ANVIL) pack -input $(BUILD_DIR)/$(STAGER)-evasion-linux-amd64 -output $(BUILD_DIR)/$(STAGER)-packed-linux-amd64 -goos linux -goarch amd64
	$(ANVIL) pack -input $(BUILD_DIR)/$(STAGER)-evasion-windows-amd64.exe -output $(BUILD_DIR)/$(STAGER)-packed-windows-amd64.exe -goos windows -goarch amd64

# Build everything: full burrow (all platforms) + stager + evasion + packed
build-all:
	@mkdir -p $(BUILD_DIR)
	@echo "=== Full burrow (all platforms) ==="
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*}; \
		GOARCH=$${platform#*/}; \
		ext=""; \
		if [ "$$GOOS" = "windows" ]; then ext=".exe"; fi; \
		echo "  $$GOOS/$$GOARCH..."; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH $(GO) build \
			-ldflags="$(LDFLAGS)" \
			-o $(BUILD_DIR)/$(BINARY)-$$GOOS-$$GOARCH$$ext . || exit 1; \
	done
	@echo "=== Stager ==="
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
		-ldflags="-s -w" -o $(BUILD_DIR)/$(STAGER)-linux-amd64 ./cmd/stager/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build \
		-ldflags="-s -w" -o $(BUILD_DIR)/$(STAGER)-windows-amd64.exe ./cmd/stager/
	$(MAKE) --no-print-directory build-stager-packed
	@echo "=== Done ==="
	$(MAKE) --no-print-directory sizes
	$(MAKE) --no-print-directory verify

# Print binary sizes
sizes:
	@echo ""
	@echo "Binary sizes:"
	@ls -lh $(BUILD_DIR)/ 2>/dev/null | grep -v '^total' | grep -v '^d' | awk '{printf "  %-45s %s\n", $$NF, $$5}' || true

# Verify all expected binaries exist
verify:
	@echo ""
	@echo "Verifying binaries..."
	@fail=0; \
	for bin in \
		$(BINARY)-linux-amd64 \
		$(BINARY)-linux-arm64 \
		$(BINARY)-windows-amd64.exe \
		$(BINARY)-darwin-amd64 \
		$(BINARY)-darwin-arm64 \
		$(STAGER)-linux-amd64 \
		$(STAGER)-windows-amd64.exe \
		$(STAGER)-evasion-linux-amd64 \
		$(STAGER)-evasion-windows-amd64.exe \
		$(STAGER)-packed-linux-amd64 \
		$(STAGER)-packed-windows-amd64.exe; \
	do \
		if [ -f $(BUILD_DIR)/$$bin ]; then \
			echo "  OK  $$bin"; \
		else \
			echo "  FAIL  $$bin  (MISSING)"; \
			fail=1; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then \
		echo ""; \
		echo "ERROR: some binaries are missing. Check build output above."; \
		exit 1; \
	fi; \
	echo ""
	@echo "All 11 binaries verified."

test:
	$(GO) test ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	$(GO) mod tidy
