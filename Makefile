.PHONY: fetch-agentsight build-ebpf test docker clean

AGENTSIGHT_URL ?= https://github.com/eunomia-bpf/agentsight/releases/latest/download/agentsight
AGENTSIGHT_BIN := bin/agentsight

# Direct download of the agentsight release binary (no build, no submodule).
fetch-agentsight:
	mkdir -p bin
	curl -fsSL -o $(AGENTSIGHT_BIN) $(AGENTSIGHT_URL)
	chmod +x $(AGENTSIGHT_BIN)
	$(AGENTSIGHT_BIN) --version

# Back-compat alias.
build-ebpf: fetch-agentsight

test:
	@test -x $(AGENTSIGHT_BIN) || $(MAKE) fetch-agentsight
	python3 -m py_compile collector/collector.py collector/runtime_interaction.py
	python3 -m unittest discover -s tests -v

docker:
	docker build -t railmon .

clean:
	rm -f $(AGENTSIGHT_BIN)
	find collector tests -type d -name __pycache__ -prune -exec rm -rf {} +
