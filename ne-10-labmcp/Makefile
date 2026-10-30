PY ?= python3

.PHONY: test register unregister
test:           ## unit tests always; lab tests run when the NE-09 lab is up
	$(PY) -m pytest -q
register:       ## add the server to Claude Code (local scope)
	claude mcp add netlab -e DOCKER_HOST=$${DOCKER_HOST:-unix:///var/run/docker.sock} -- $(PY) -m labmcp.server
unregister:
	claude mcp remove netlab
