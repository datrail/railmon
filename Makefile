.PHONY: build-ebpf test docker clean

build-ebpf:
	git submodule update --init --recursive
	$(MAKE) -C ebpf-tls-tap/bpf sslsniff

test:
	python3 -m py_compile collector/collector.py collector/runtime_interaction.py
	python3 -m unittest discover -s tests -v

docker:
	docker build -t railmon .

clean:
	$(MAKE) -C ebpf-tls-tap/bpf clean
	find collector tests -type d -name __pycache__ -prune -exec rm -rf {} +
