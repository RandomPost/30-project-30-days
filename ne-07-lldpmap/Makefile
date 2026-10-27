# Lab: scripts/lab.sh up needs LAB_SSH_PASSWORD; the tool needs LLDPMAP_USER/PASSWORD.
PY ?= python3

.PHONY: lab-up lab-down demo test
lab-up:
	scripts/lab.sh up
lab-down:
	scripts/lab.sh down
demo:
	scripts/demo.sh
test:
	$(PY) -m pytest -q
