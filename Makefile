.PHONY: build build-py test clean tidy

GO        := $(HOME)/go-sdk/go/bin/go
BINARY    := burrow
BUILD_DIR := build
ENTRY_MOD  := burrow.cli
ENTRY_FUNC := main

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) .
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

build-py:
	@mkdir -p $(BUILD_DIR)/.work
	@echo 'from $(ENTRY_MOD) import $(ENTRY_FUNC); $(ENTRY_FUNC)()' > $(BUILD_DIR)/.work/entry.py
	pyinstaller --onefile \
		--name $(BINARY)-py \
		--distpath $(BUILD_DIR) \
		--workpath $(BUILD_DIR)/.work \
		--specpath $(BUILD_DIR)/.work \
		--clean --noconfirm \
		--paths src \
		$(BUILD_DIR)/.work/entry.py
	@echo "Built: $(BUILD_DIR)/$(BINARY)-py"

test:
	$(GO) test ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	$(GO) mod tidy
