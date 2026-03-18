.PHONY: build install test clean

BINARY := containerd-shim-ironbox-v1
INSTALL_DIR := /usr/local/bin

build:
	cargo build --release

install: build
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Run 'sudo make install' to install the shim binary"; \
		exit 1; \
	fi
	cp target/release/$(BINARY) $(INSTALL_DIR)/$(BINARY).new
	mv $(INSTALL_DIR)/$(BINARY).new $(INSTALL_DIR)/$(BINARY)

test: install
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Run 'sudo make test' to run integration tests"; \
		exit 1; \
	fi
	./tests/integration.sh

clean:
	cargo clean
