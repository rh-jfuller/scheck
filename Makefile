.PHONY: all build release check test clippy fmt clean install publish
.PHONY: wasm serve rulesets rulesets-security rulesets-api rulesets-config rulesets-data-quality

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

SCHECK = $(CARGO) run --

rulesets: build rulesets-security rulesets-api rulesets-config rulesets-data-quality

rulesets-security: build
	@echo "──── Security ────"
	@echo "=== CSAF 2.0 (valid) ==="
	$(SCHECK) validate etc/testdata/security/csaf-valid.json --rules rulesets/security/csaf-2.0-mandatory.json --phase full
	@echo "=== CSAF 2.0 (invalid) ==="
	-$(SCHECK) validate etc/testdata/security/csaf-invalid.json --rules rulesets/security/csaf-2.0-mandatory.json --phase structural
	@echo "=== CycloneDX (valid) ==="
	$(SCHECK) validate etc/testdata/security/cyclonedx-valid.json --rules rulesets/security/cyclonedx-min.json
	@echo "=== CycloneDX (invalid) ==="
	-$(SCHECK) validate etc/testdata/security/cyclonedx-invalid.json --rules rulesets/security/cyclonedx-min.json
	@echo "=== SPDX (valid) ==="
	$(SCHECK) validate etc/testdata/security/spdx-valid.json --rules rulesets/security/spdx-min.json
	@echo "=== SPDX (invalid) ==="
	-$(SCHECK) validate etc/testdata/security/spdx-invalid.json --rules rulesets/security/spdx-min.json
	@echo "=== VEX (valid) ==="
	$(SCHECK) validate etc/testdata/security/vex-valid.json --rules rulesets/security/vex-coherence.json --phase full
	@echo "=== VEX (invalid) ==="
	-$(SCHECK) validate etc/testdata/security/vex-invalid.json --rules rulesets/security/vex-coherence.json --phase full
	@echo "=== OSV (valid) ==="
	$(SCHECK) validate etc/testdata/security/osv-valid.json --rules rulesets/security/osv.json
	@echo "=== OSV (invalid) ==="
	-$(SCHECK) validate etc/testdata/security/osv-invalid.json --rules rulesets/security/osv.json

rulesets-api: build
	@echo "──── API ────"
	@echo "=== OpenAPI response (valid) ==="
	$(SCHECK) validate etc/testdata/api/openapi-response-valid.json --rules rulesets/api/openapi-response.json
	@echo "=== OpenAPI response (invalid) ==="
	-$(SCHECK) validate etc/testdata/api/openapi-response-invalid.json --rules rulesets/api/openapi-response.json
	@echo "=== JSON:API (valid) ==="
	$(SCHECK) validate etc/testdata/api/jsonapi-valid.json --rules rulesets/api/jsonapi.json
	@echo "=== JSON:API (invalid) ==="
	-$(SCHECK) validate etc/testdata/api/jsonapi-invalid.json --rules rulesets/api/jsonapi.json

rulesets-config: build
	@echo "──── Config ────"
	@echo "=== Kubernetes Pod (valid) ==="
	$(SCHECK) validate etc/testdata/config/kubernetes-pod-valid.json --rules rulesets/config/kubernetes-pod.json
	@echo "=== Kubernetes Pod (invalid) ==="
	-$(SCHECK) validate etc/testdata/config/kubernetes-pod-invalid.json --rules rulesets/config/kubernetes-pod.json
	@echo "=== GitHub Actions (valid) ==="
	$(SCHECK) validate etc/testdata/config/github-actions-valid.json --rules rulesets/config/github-actions.json
	@echo "=== GitHub Actions (invalid) ==="
	-$(SCHECK) validate etc/testdata/config/github-actions-invalid.json --rules rulesets/config/github-actions.json

rulesets-data-quality: build
	@echo "──── Data Quality ────"
	@echo "=== Contact records (valid) ==="
	$(SCHECK) validate etc/testdata/data-quality/contacts-valid.json --rules rulesets/data-quality/contact-records.json
	@echo "=== Contact records (invalid) ==="
	-$(SCHECK) validate etc/testdata/data-quality/contacts-invalid.json --rules rulesets/data-quality/contact-records.json
	@echo "=== Dataset metadata (valid) ==="
	$(SCHECK) validate etc/testdata/data-quality/dataset-valid.json --rules rulesets/data-quality/dataset-metadata.json
	@echo "=== Dataset metadata (invalid) ==="
	-$(SCHECK) validate etc/testdata/data-quality/dataset-invalid.json --rules rulesets/data-quality/dataset-metadata.json

wasm:
	wasm-pack build --target web --features wasm --no-default-features

serve: wasm
	ln -sfn ../pkg etc/pkg
	@echo "Open http://localhost:8080"
	python3 -m http.server 8080 -d etc
