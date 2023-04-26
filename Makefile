.PHONY: help
help: ## show this help
	@echo "make"; echo
	@fgrep -h " ## " $(MAKEFILE_LIST) | sed -e 's/\(\:.*\#\#\)/\:|/' | \
	  fgrep -v fgrep | sed -e 's/\\$$//' | column -t -s '|'

.PHONY: get-versions
get-versions: ## Get sofware versions installed
	$(info --- Software versions installed ----------------------------------------)
	@printf -- '--- %s version ---\n' "git"
	@type git && git --version 2>/dev/null || true
	@printf -- '--- %s version ---\n' "Python"
	@type python && python --version 2>/dev/null || true
	@type python3 && python3 --version 2>/dev/null || true
	@printf -- '--- %s version ---\n' "pip packages"
	@type pip && pip --version && pip list || true
	@printf -- '--- %s version ---\n' "pip3 packages"
	@type pip3 && pip3 --version &&  pip3 list || true
	@printf -- '--- %s version ---\n' "Pre-commit"
	@type pre-commit && pre-commit --version 2>/dev/null || true
	@pre-commit --version 2>/dev/null || echo "No Pre-commit found in: $(PIPENV)"
	@cd "$(TERRAFORM_ROOT)" && make get-versions || true


###############################################################################
#
# Setup
#
###############################################################################
.PHONY: init
init: ## Init pre-commit hooks
	@echo "* Preparing project"
	pre-commit install --install-hooks -c .ci/pre-commit-config.yaml

###############################################################################
#
# Validation
#
###############################################################################
.PHONY: validate
validate:  ## Run Pre-commit against all files
	@echo "* Autoformat"
	@echo "* Pre-commit run"
	pre-commit run --all-files -c .ci/pre-commit-config.yaml

.PHONY: clean
clean: ## Remove pre-commit hooks
	pre-commit uninstall

.PHONY: build
build:
	docker build -t sunflower:latest .
