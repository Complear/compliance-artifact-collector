PY ?= .venv/bin/python
BENCHMARK ?= ../aiod-compliance-benchmark

setup:
	python3 -m venv .venv && .venv/bin/pip install -q jsonschema==4.26.0 $(BENCHMARK)

test:
	$(PY) -m unittest discover -s tests -t .

example:
	$(PY) -m cac collect examples/nodesight/product.json --out examples/nodesight/record.json

image:
	docker build --build-context benchmark=$(BENCHMARK) -t compliance-artifact-collector:0.3.0 .

.PHONY: setup test example image
