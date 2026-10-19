.PHONY: install test lint demo eval docker clean

install:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check src tests

demo:
	orarem --config config/default.yaml demo --topology single

eval:
	orarem --config config/default.yaml demo --topology exadata --eval --out runs/eval
	orarem eval report runs/eval/run-*

docker:
	docker build -f docker/Dockerfile -t oracle-remediate:latest .

clean:
	rm -rf runs .pytest_cache build dist *.egg-info src/*.egg-info
