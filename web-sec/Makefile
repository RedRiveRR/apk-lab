# Web Sec Lab — make targets mirror `./labctl websec <target>`.
PYTHON ?= python3
RUN = $(PYTHON) run.py

.PHONY: help status doctor setup scan quick test catalogue plugins preflight

help:
	@$(RUN) --help

status:
	@$(RUN) status

doctor:
	@$(RUN) doctor

setup:
	@$(RUN) setup

preflight:
	@./scripts/preflight.sh

catalogue:
	@$(RUN) modules

plugins:
	@$(RUN) plugins

scan:
	@$(RUN) scan $(TARGET) --preset $(or $(PRESET),standard) $(if $(ACTIVE),--active,)

quick:
	@$(RUN) scan $(TARGET) --preset quick

test:
	@cd engine && $(PYTHON) -m pytest -q
