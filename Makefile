.PHONY: fetch-agentsight build-ebpf test docker clean

AGENTSIGHT_VERSION ?= v0.2.65
AGENTSIGHT_BIN := bin/agentsight

fetch-agentsight:
	AGENTSIGHT_VERSION=$(AGENTSIGHT_VERSION) ./scripts/fetch-agentsight.sh

# Back-compat alias: eBPF capture now comes from AgentSight releases.
build-ebpf: fetch-agentsight

test: fetch-agentsight
	python3 -m py_compile collector/collector.py collector/runtime_interaction.py
	python3 -m unittest discover -s tests -v

docker: fetch-agentsight
	docker build -t railmon .

clean:
	rm -f $(AGENTSIGHT_BIN)
	find collector tests -type d -name __pycache__ -prune -exec rm -rf {} +
