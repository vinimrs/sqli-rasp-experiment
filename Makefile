SHELL := /bin/bash

ROOT := /Users/viniciusromualdo/swe/openrasp_lab
LAB_ROOT := $(ROOT)/sqli_rasp_experiment
NS := sqli
WEBGOAT_IMAGE := webgoat-rasp:latest
PROFILE ?= rasp-on
ZAP_MODE ?= sqli_focused
PROFILE_DIR := $(LAB_ROOT)/k8s/profiles/$(PROFILE)

.PHONY: help build build-webgoat load-images deploy deploy-profile profile-rasp-on profile-rasp-off restart status run-zap run-zap-current run-sqli-current

help:
	@echo "Targets:"
	@echo "  build             Build all images"
	@echo "  load-images       Load images into minikube"
	@echo "  deploy            Apply default manifests (rasp-on)"
	@echo "  deploy-profile    Apply selected profile (PROFILE=rasp-on|rasp-off)"
	@echo "  profile-rasp-on   Apply profile rasp-on and restart deployments"
	@echo "  profile-rasp-off  Apply profile rasp-off and restart deployments"
	@echo "  restart           Rollout restart core deployments"
	@echo "  status            Show pods/services/deployments"
	@echo "  run-zap          Run OWASP ZAP on rasp-on/rasp-off (default: ZAP_MODE=sqli_focused; use ZAP_MODE=full for broad scan)"
	@echo "  run-zap-current  Run ZAP against current cluster state without apply/restart"
	@echo "  run-sqli-current Run SQLi-focused current-cluster experiment (no apply/restart)"

build: build-webgoat

build-webgoat:
	docker build --platform linux/amd64 -t $(WEBGOAT_IMAGE) -f $(LAB_ROOT)/images/webgoat-rasp/Dockerfile $(LAB_ROOT)

load-images:
	minikube image load $(WEBGOAT_IMAGE)

deploy:
	kubectl apply -k $(LAB_ROOT)/k8s

deploy-profile:
	kubectl apply -k $(PROFILE_DIR)

profile-rasp-on:
	$(MAKE) deploy-profile PROFILE=rasp-on
	$(MAKE) restart

profile-rasp-off:
	$(MAKE) deploy-profile PROFILE=rasp-off
	$(MAKE) restart

restart:
	kubectl -n $(NS) rollout restart deploy/webgoat deploy/api-gateway
	kubectl -n $(NS) rollout status deploy/webgoat --timeout=420s
	kubectl -n $(NS) rollout status deploy/api-gateway --timeout=240s

status:
	kubectl -n $(NS) get pods -o wide
	kubectl -n $(NS) get svc
	kubectl -n $(NS) get deploy

run-zap:
	@if [ "$(ZAP_MODE)" = "full" ]; then \
		$(LAB_ROOT)/scripts/rasp_toggle_experiment_zap.py --scan-paths ''; \
	elif [ "$(ZAP_MODE)" = "sqli_focused" ] || [ "$(ZAP_MODE)" = "sqli-focused" ]; then \
		$(LAB_ROOT)/scripts/rasp_toggle_experiment_zap.py; \
	else \
		echo "Unsupported ZAP_MODE=$(ZAP_MODE). Use sqli_focused or full."; \
		exit 2; \
	fi

run-zap-current:
	$(LAB_ROOT)/scripts/sqli_zap_current.py --profile-label $(PROFILE)

run-sqli-current:
	$(LAB_ROOT)/scripts/sqli_zap_current.py --profile-label current
