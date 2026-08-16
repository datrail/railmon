.PHONY: build test test-rust test-python fmt clippy docker clean fetch-agentsight build-ebpf

AGENTSIGHT_URL ?= https://github.com/eunomia-bpf/agentsight/releases/latest/download/agentsight
AGENTSIGHT_BIN := bin/agentsight

build:
	cargo build --release

# Both halves. The Python moved here from railscan under DR-84 and keeps its
# own tests; a Rust-only `make test` would let the scanner rot silently.
test: test-rust test-python

# fmt and clippy run here rather than only in CI, so the feedback arrives while
# the change is still in your head. Warnings are denied: a warning nobody has to
# fix is one nobody reads.
test-rust:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test

test-python:
	python3 -m py_compile \
		tools/agent-environment-scanner/scan_agent_environment.py \
		tools/skills-scanner/skill_scanner.py \
		rail-collector/rail_collector.py
	RAILMON_ROOT="$(CURDIR)" ./entrypoint.sh scan --help >/dev/null
	RAILMON_ROOT="$(CURDIR)" ./entrypoint.sh skills --help >/dev/null
	RAILMON_ROOT="$(CURDIR)" ./entrypoint.sh forward --help >/dev/null
	python3 -m unittest discover -s tests-python

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

# Only needed to run the collector outside the container; the image downloads
# AgentSight itself. Unpinned on purpose — we track upstream.
fetch-agentsight:
	mkdir -p bin
	curl -fsSL -o $(AGENTSIGHT_BIN) $(AGENTSIGHT_URL)
	chmod +x $(AGENTSIGHT_BIN)
	$(AGENTSIGHT_BIN) --version

# Back-compat alias.
build-ebpf: fetch-agentsight

docker:
	docker build -t railmon .

clean:
	cargo clean
	rm -f $(AGENTSIGHT_BIN)
