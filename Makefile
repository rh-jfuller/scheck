.PHONY: all build release check test clippy fmt clean install publish
.PHONY: wasm serve

CARGO = cargo
BIN = scheck

# --- Cargo targets ---

all: check

build:
	$(CARGO) build

release:
	$(CARGO) build --release

check: fmt clippy test

test:
	$(CARGO) test

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt --check

fmt-fix:
	$(CARGO) fmt

clean:
	$(CARGO) clean

install:
	$(CARGO) install --path .

publish: check
	$(CARGO) publish

wasm:
	wasm-pack build --target web --features wasm --no-default-features

serve: wasm
	ln -sfn ../pkg etc/pkg
	@echo "Open http://localhost:8080"
	python3 -m http.server 8080 -d etc
