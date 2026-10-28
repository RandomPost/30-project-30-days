PY ?= python3
CHANGE ?= changes/bad-guest-acl-reordered.patch

.PHONY: up down test try demo
up:
	docker compose up -d --wait
down:
	docker compose down
test:           ## policy suite against the current network
	$(PY) -m pytest -q
try:            ## make try CHANGE=changes/<file>.patch
	scripts/try-change.sh $(CHANGE)
demo:
	scripts/demo.sh
