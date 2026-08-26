SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

REGISTRY        ?= ghcr.io/rokh-oghab
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GATEWAY_IMAGE   ?= $(REGISTRY)/gateway:$(VERSION)
CONTROLLER_IMAGE?= $(REGISTRY)/controller:$(VERSION)
AGENT_IMAGE     ?= $(REGISTRY)/agent:$(VERSION)
OPENRESTY_IMAGE ?= openresty/openresty:1.27.1.2-0-alpine-fat
COMPOSE         ?= docker compose
E2E             := tests/e2e
PYTHON          ?= python3
FUZZ_ROUNDS     ?= 150
FUZZ_SEED       ?= 20260824

DEV_GATEWAY_IMAGE    := rokh-oghab/gateway:dev
DEV_CONTROLLER_IMAGE := rokh-oghab/controller:dev
DEV_AGENT_IMAGE      := rokh-oghab/agent:dev

export RO_TEST_IMAGE     := $(OPENRESTY_IMAGE)
export RO_GATEWAY_IMAGE  := $(DEV_GATEWAY_IMAGE)

NO_PROXY_ENV := env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY \
                    -u http_proxy -u https_proxy -u no_proxy

CHAOS_ROUNDS ?= 20
CHAOS_WORKERS ?= 8
CHAOS_SEED ?= 20260825

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nRokh Oghab (رخ عقاب) - sandbox egress gateway\n\nUsage:\n  make \033[36m<target>\033[0m\n"} \
	/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2 } \
	/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@echo

.PHONY: version
version:
	@echo "version:    $(VERSION)"
	@echo "gateway:    $(GATEWAY_IMAGE)"
	@echo "controller: $(CONTROLLER_IMAGE)"
	@echo "agent:      $(AGENT_IMAGE)"

.PHONY: build
build: build-gateway build-controller build-agent

.PHONY: build-gateway
build-gateway:
	docker build --target gateway -t $(DEV_GATEWAY_IMAGE) -t $(GATEWAY_IMAGE) .

.PHONY: build-controller
build-controller:
	docker build --target controller -t $(DEV_CONTROLLER_IMAGE) -t $(CONTROLLER_IMAGE) .

.PHONY: build-agent
build-agent:
	docker build --target agent -t $(DEV_AGENT_IMAGE) -t $(AGENT_IMAGE) .

.PHONY: push
push:
	docker push $(GATEWAY_IMAGE)
	docker push $(CONTROLLER_IMAGE)
	docker push $(AGENT_IMAGE)

.PHONY: lint
lint: lint-lua lint-nginx lint-shell lint-yaml lint-python

.PHONY: lint-lua
lint-lua:
	@bash tests/lint.sh

.PHONY: lint-nginx
lint-nginx: build-gateway
	@docker run --rm $(DEV_GATEWAY_IMAGE) check

.PHONY: lint-shell
lint-shell:
	@fail=0; for f in $$(git ls-files '*.sh' bin/ro-agent start.sh gen-ca.sh 2>/dev/null | sort -u); do \
	  head -1 "$$f" | grep -q bash && checker=bash || checker=sh; \
	  $$checker -n "$$f" || { echo "SYNTAX ERROR: $$f"; fail=1; }; \
	done; \
	if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -S warning $$(git ls-files '*.sh' bin/ro-agent start.sh gen-ca.sh 2>/dev/null | sort -u) || fail=1; \
	fi; \
	exit $$fail

.PHONY: lint-yaml
lint-yaml:
	@$(PYTHON) scripts/lint-yaml.py

.PHONY: lint-python
lint-python:
	@$(PYTHON) -m compileall -q bin/roctl tests scripts >/dev/null && echo "python sources compile"

.PHONY: test
test: test-unit test-agent test-e2e

.PHONY: test-all
test-all: lint ratchet check-reasons audit-defaults test-unit test-agent test-examples test-manifests test-e2e test-security test-control test-cli ## Run everything that does not need root

.PHONY: test-privileged
test-privileged: test-enforcement test-bypass test-sandbox-demo

.PHONY: test-unit
test-unit:
	@bash tests/run-unit.sh

.PHONY: test-agent
test-agent:
	@bash tests/run-agent.sh

.PHONY: test-examples
test-examples:
	@bash tests/run-examples.sh

.PHONY: ratchet
ratchet:
	@bash tests/run-ratchet.sh

.PHONY: ratchet-update
ratchet-update:
	@bash tests/run-ratchet.sh --update

.PHONY: e2e-up
e2e-up: build-gateway build-controller
	@bash $(E2E)/make-certs.sh
	@$(PYTHON) $(E2E)/make-bundle.py
	@cd $(E2E) && $(COMPOSE) up -d --wait --wait-timeout 120 || $(COMPOSE) up -d
	@sleep 3

.PHONY: e2e-down
e2e-down:
	@cd $(E2E) && $(COMPOSE) down -v --remove-orphans

.PHONY: e2e-logs
e2e-logs:
	@cd $(E2E) && $(COMPOSE) logs -f

.PHONY: test-e2e
test-e2e: e2e-up
	@cd $(E2E) && $(NO_PROXY_ENV) $(PYTHON) driver.py

.PHONY: test-security
test-security: e2e-up
	@cd $(E2E) && $(NO_PROXY_ENV) $(PYTHON) security_driver.py

.PHONY: test-control
test-control: e2e-up
	@cd $(E2E) && $(NO_PROXY_ENV) $(PYTHON) controller_driver.py

.PHONY: check-reasons
check-reasons:
	@$(PYTHON) tests/check-reasons.py

.PHONY: test-cli
test-cli: e2e-up
	@cd $(E2E) && $(NO_PROXY_ENV) $(PYTHON) cli_driver.py

.PHONY: chaos
chaos: e2e-up
	@$(PYTHON) tests/chaos/run.py --rounds $(CHAOS_ROUNDS) --workers $(CHAOS_WORKERS) --seed $(CHAOS_SEED)

.PHONY: test-enforcement
test-enforcement: build-gateway
	@bash tests/enforcement/run.sh

.PHONY: test-bypass
test-bypass: build-gateway
	@bash tests/enforcement/bypass.sh

.PHONY: test-sandbox-demo
test-sandbox-demo: build-gateway
	@bash tests/run-sandbox-demo.sh

.PHONY: test-manifests
test-manifests:
	@bash tests/run-manifests.sh

.PHONY: audit-defaults
audit-defaults:
	@bash tests/run-defaults-audit.sh

.PHONY: test-k8s
test-k8s:
	@bash tests/k8s/run.sh

.PHONY: fuzz
fuzz: e2e-up
	@cd $(E2E) && $(NO_PROXY_ENV) $(PYTHON) ../fuzz/fuzz.py --rounds $(FUZZ_ROUNDS) --seed $(FUZZ_SEED)

.PHONY: bench
bench: e2e-up
	@cd $(E2E) && $(NO_PROXY_ENV) $(PYTHON) ../perf/bench.py

.PHONY: helm-lint
helm-lint:
	helm lint deploy/helm/rokh-oghab

.PHONY: helm-template
helm-template:
	helm template rokh-oghab deploy/helm/rokh-oghab

.PHONY: kustomize-build
kustomize-build:
	kubectl kustomize deploy/kubernetes/base

.PHONY: tf-validate
tf-validate:
	@bash scripts/tf-validate.sh

.PHONY: ansible-check
ansible-check:
	@command -v ansible-playbook >/dev/null 2>&1 \
	  && ansible-playbook --syntax-check -i deploy/ansible/inventory.example.ini deploy/ansible/site.yml \
	  || echo "ansible-playbook is not installed; skipping"

.PHONY: pki
pki:
	@./gen-ca.sh

.PHONY: up
up:
	@bash scripts/dev-up.sh

.PHONY: down
down:
	@bash scripts/dev-down.sh

.PHONY: smoke
smoke:
	@bash scripts/smoke.sh

.PHONY: token
token:
	@bash scripts/issue-token.sh

.PHONY: clean
clean: e2e-down
	@rm -rf pki $(E2E)/certs __pycache__ .pytest_cache
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@docker rmi -f $(DEV_GATEWAY_IMAGE) $(DEV_CONTROLLER_IMAGE) $(DEV_AGENT_IMAGE) 2>/dev/null || true
	@echo "cleaned"

.PHONY: ci
ci: lint test-all
