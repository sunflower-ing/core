KUBE_NAMESPACE ?= sunflower-staging

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

###############################################################################
#
# Release
#
###############################################################################
.PHONY: release
release: ## Bump release version
	pre-commit uninstall
	docker run -it -v ${HOME}/.ssh:/root/.ssh \
	-v ${PWD}:/app \
	-e GITHUB_TOKEN=${GITHUB_TOKEN} \
	-w /app \
	registry.gitlab.com/xom4ek/toolset/semantic-release:2.0.0 semantic-release --ci=false --dry-run=false --no-verify
	pre-commit install --install-hooks -c .ci/pre-commit-config.yaml

.PHONY: release-dry-run
release-dry-run: ## Dry run release
	docker run -it -v ${HOME}/.ssh:/root/.ssh \
	-v ${PWD}:/app \
	-e GITHUB_TOKEN=${GITHUB_TOKEN} \
	-w /app \
	registry.gitlab.com/xom4ek/toolset/semantic-release:2.0.0 semantic-release --ci=false --dry-run --no-verify

.PHONY: encrypt
encrypt: ## Encrypt .helm/secret.yaml
	werf helm secret values encrypt .helm/secret-values.yaml -o .helm/secret-values.yaml

.PHONY: decrypt
decrypt: ## Decrypt .helm/secret.yaml
	werf helm secret values decrypt .helm/secret-values.yaml -o .helm/secret-values.yaml

.PHONY: kube-login
kube-login: ## Login to kuberntes and set namespace to $KUBE_NAMESPACE
	tsh login --proxy teleport.sunflower3455.com
	tsh kube ls
	tsh kube login do-sunflower3455-com
	kubectl config set-context --current --namespace ${KUBE_NAMESPACE}
	echo 'Example usage:'
	echo 'kubectl get pods'
	echo 'kubectl logs POD_NAME'
