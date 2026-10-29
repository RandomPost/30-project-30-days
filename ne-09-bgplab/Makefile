PY ?= python3
DESIGN ?= a

.PHONY: up down test unit matrix
up:             ## deploy the lab (DESIGN=a|b), then wait ~90 s for FRR to start
	DESIGN=$(DESIGN) scripts/lab.sh up
down:
	scripts/lab.sh down
unit:           ## no lab needed
	$(PY) -m pytest -q tests/test_model.py tests/test_rtr.py
test:           ## unit tests plus the lab path-choice tests
	$(PY) -m pytest -q
matrix:         ## best path per router for the key prefixes
	$(PY) -m bgplab.cli matrix
