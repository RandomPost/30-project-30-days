# Lab: scripts/lab.sh up needs LAB_SSH_PASSWORD; the tool needs CONFDRIFT_USER/PASSWORD.
PY ?= python3

.PHONY: lab-up lab-down backup drift demo test
lab-up:
	scripts/lab.sh up
lab-down:
	scripts/lab.sh down
backup:
	$(PY) -m confdrift backup
drift:
	$(PY) -m confdrift drift
demo:
	scripts/demo.sh
test:
	$(PY) -m pytest -q
