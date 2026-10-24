# OSPF lab: make up | verify | break | restore | failover | show | down | test
TOPO     := ospf-lab.clab.yml
CLAB     ?= containerlab
LINK     ?= r1-r3
PYTHON   ?= python3

# Images. Override when Docker Hub is rate-limited, e.g.
#   make up FRR_IMAGE=mirror.gcr.io/frrouting/frr:v8.4.1 HOST_IMAGE=mirror.gcr.io/library/alpine:3.20
export FRR_IMAGE  ?= docker.io/frrouting/frr:v8.4.1
export HOST_IMAGE ?= docker.io/library/alpine:3.20

.PHONY: up verify break restore failover show down test

up:        ## deploy the lab (needs root or docker + containerlab permissions)
	$(CLAB) deploy -t $(TOPO) --reconfigure

verify:    ## wait for OSPF to converge, then check neighbours, routes and pings
	$(PYTHON) -m ospflab verify --wait 90

break:     ## shut one end of a link (LINK=r1-r3 | r1-r2 | r2-r3)
	$(PYTHON) -m ospflab break $(LINK)

restore:   ## bring the link back
	$(PYTHON) -m ospflab restore $(LINK)

failover:  ## ping h1 -> h2, break the link mid-stream, report reconvergence, restore
	$(PYTHON) -m ospflab failover $(LINK)

show:      ## OSPF neighbours and routes on every router
	$(PYTHON) -m ospflab show

down:      ## destroy the lab
	$(CLAB) destroy -t $(TOPO) --cleanup

test:      ## unit tests for the verification logic (no Docker needed)
	$(PYTHON) -m pytest -q
